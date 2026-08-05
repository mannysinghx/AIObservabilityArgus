import { scryptSync, randomBytes, timingSafeEqual } from "node:crypto";
import { pool, sha256 } from "./db.js";
import { safeProjectId } from "./ids.js";
import * as Email from "./email.js";
import * as Mfa from "./mfa.js";

function baseUrl(): string {
  if (process.env.PUBLIC_URL) return process.env.PUBLIC_URL.replace(/\/$/, "");
  if (process.env.RAILWAY_PUBLIC_DOMAIN) return "https://" + process.env.RAILWAY_PUBLIC_DOMAIN;
  return "http://localhost:3002";
}
function verificationLink(token: string): string {
  return `${baseUrl()}/api/auth/verify?token=${encodeURIComponent(token)}`;
}
function resetLink(token: string): string {
  return `${baseUrl()}/reset.html?token=${encodeURIComponent(token)}`;
}

// ---------------- password hashing (scrypt, stdlib — no native dep) ----------------

function hashPassword(pw: string): string {
  const salt = randomBytes(16);
  const dk = scryptSync(pw, salt, 64);
  return salt.toString("hex") + ":" + dk.toString("hex");
}

function verifyPassword(pw: string, stored: string): boolean {
  const [saltHex, hashHex] = (stored || "").split(":");
  if (!saltHex || !hashHex) return false;
  try {
    const dk = scryptSync(pw, Buffer.from(saltHex, "hex"), 64);
    const expected = Buffer.from(hashHex, "hex");
    return expected.length === dk.length && timingSafeEqual(expected, dk);
  } catch {
    return false;
  }
}

const SESSION_TTL_DAYS = 30;
export const SESSION_COOKIE = "argus_session";

export interface SessionUser {
  id: string;
  email: string;
  name: string;
  emailVerified: boolean;
  isPlatformAdmin: boolean;
}

export interface AuthError {
  error: string;
}

function validEmail(e: string): boolean {
  return /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(e);
}

// ---------------- signup policy ----------------
// Who is allowed to create an account, and who gets the keys to the platform.
//
//   ARGUS_SIGNUP_MODE = open (default) | invite_only | closed
//   ARGUS_BOOTSTRAP_TOKEN = <secret>
//
// The first account to exist becomes the platform operator (super-admin over
// every tenant). On a deployment reachable from the internet that is a race:
// whoever finds the URL between `deploy` and `you signing up` owns the install.
// Setting ARGUS_BOOTSTRAP_TOKEN closes the race — the first signup must present
// it, and until someone does, there is no account at all.
//
// `invite_only` is the steady state for a hosted deployment: after bootstrap,
// accounts are created only for addresses someone already invited.
export type SignupMode = "open" | "invite_only" | "closed";

export function signupMode(): SignupMode {
  const m = (process.env.ARGUS_SIGNUP_MODE || "open").trim().toLowerCase();
  return m === "invite_only" || m === "closed" ? m : "open";
}

/** Public description of the signup policy, for the login/signup UI. */
export function signupPolicy(): { mode: SignupMode; bootstrapRequired: boolean } {
  return { mode: signupMode(), bootstrapRequired: !!process.env.ARGUS_BOOTSTRAP_TOKEN };
}

function bootstrapTokenOk(presented: string): boolean {
  const expected = process.env.ARGUS_BOOTSTRAP_TOKEN || "";
  if (!expected) return true; // not configured — nothing to check
  const a = Buffer.from(String(presented || ""), "utf8");
  const b = Buffer.from(expected, "utf8");
  return a.length === b.length && timingSafeEqual(a, b);
}

/**
 * Create an account. The first user to sign up becomes the platform operator
 * (super-admin), subject to ARGUS_BOOTSTRAP_TOKEN above. Every account —
 * including the first — gets an org of its own from the company name, and
 * membership of nothing else.
 *
 * The first account used to also be granted `owner` membership of every
 * organization that already existed. That silently made one customer a member
 * of other customers' companies, which is indistinguishable from a breach when
 * read out of the memberships table. Platform-operator reach now comes only
 * from the explicit is_platform_admin flag, which is visible and revocable.
 */
export async function signup(
  emailRaw: string,
  password: string,
  name: string,
  companyName: string,
  bootstrapToken = "",
): Promise<{ token: string; user: SessionUser } | AuthError> {
  const email = String(emailRaw || "").trim().toLowerCase();
  if (!validEmail(email)) return { error: "Enter a valid email address." };
  if (!password || password.length < 8) return { error: "Password must be at least 8 characters." };

  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    const dup = await client.query("SELECT 1 FROM users WHERE email = $1", [email]);
    if (dup.rowCount) {
      await client.query("ROLLBACK");
      return { error: "An account with that email already exists." };
    }

    const isFirst = (await client.query("SELECT 1 FROM users LIMIT 1")).rowCount === 0;

    // Policy gate. The first account is exempt from signup *mode* (otherwise a
    // closed deployment could never be bootstrapped) but is the only account
    // subject to the bootstrap token.
    if (isFirst) {
      if (!bootstrapTokenOk(bootstrapToken)) {
        await client.query("ROLLBACK");
        return { error: "A setup token is required to create the first account." };
      }
    } else {
      const mode = signupMode();
      if (mode === "closed") {
        await client.query("ROLLBACK");
        return { error: "Sign-ups are closed on this deployment. Ask an administrator for an invitation." };
      }
      if (mode === "invite_only") {
        const invited = await client.query(
          "SELECT 1 FROM invitations WHERE lower(email) = lower($1) AND accepted_at IS NULL LIMIT 1",
          [email],
        );
        if (!invited.rowCount) {
          await client.query("ROLLBACK");
          return { error: "This deployment is invite-only. Ask an administrator to invite your email address." };
        }
      }
    }

    const nm = String(name || "").trim().slice(0, 120);

    // The platform operator (first account) is trusted; if no mailer is
    // configured there's no way to verify, so don't strand anyone — verify
    // immediately. Otherwise the account starts unverified and gets an email.
    const verified = isFirst || !Email.configured();

    // The first account is the platform operator — a super-admin over everything.
    const ins = await client.query<{ id: string }>(
      "INSERT INTO users (email, name, password_hash, email_verified, is_platform_admin) VALUES ($1, $2, $3, $4, $5) RETURNING id",
      [email, nm, hashPassword(password), verified, isFirst],
    );
    const userId = ins.rows[0].id;

    const company = String(companyName || "").trim().slice(0, 200);
    if (company) {
      const org = await client.query<{ id: string }>(
        "INSERT INTO organizations (name) VALUES ($1) RETURNING id",
        [company],
      );
      await client.query(
        "INSERT INTO memberships (user_id, org_id, role) VALUES ($1, $2, 'owner') ON CONFLICT DO NOTHING",
        [userId, org.rows[0].id],
      );
    }
    // Everyone ends up in at least one org: a personal workspace if nothing else.
    const hasOrg = await client.query("SELECT 1 FROM memberships WHERE user_id = $1 LIMIT 1", [userId]);
    if (!hasOrg.rowCount) {
      const org = await client.query<{ id: string }>(
        "INSERT INTO organizations (name) VALUES ($1) RETURNING id",
        [(name || email.split("@")[0]) + "'s workspace"],
      );
      await client.query("INSERT INTO memberships (user_id, org_id, role) VALUES ($1, $2, 'owner')", [
        userId,
        org.rows[0].id,
      ]);
    }

    // Join any orgs they were invited to — but ONLY once we know the address is
    // really theirs. An invitation is a grant of access to another tenant's
    // data, keyed on an email address, so activating it for an unproven address
    // means anyone who signs up as victim@company.com inherits every invite
    // sent to that person. When no mailer is configured `verified` is already
    // true (there is no way to prove anything, and a self-hoster shouldn't be
    // locked out of their own invites), so this doesn't change single-tenant
    // deployments — it closes the hole on the ones that can actually verify.
    if (verified) await activateInvites(client, userId, email);

    let verifyLink: string | null = null;
    if (!verified) {
      const vtoken = randomBytes(24).toString("base64url");
      await client.query(
        "INSERT INTO email_verifications (token_hash, user_id, email, expires_at) VALUES ($1, $2, $3, now() + interval '24 hours')",
        [sha256(vtoken), userId, email],
      );
      verifyLink = verificationLink(vtoken);
    }

    const token = await createSession(client, userId);
    await client.query("COMMIT");
    if (verifyLink) void Email.sendVerification(email, nm, verifyLink); // fire-and-forget
    return { token, user: { id: userId, email, name: nm, emailVerified: verified, isPlatformAdmin: isFirst } };
  } catch (err) {
    await client.query("ROLLBACK");
    throw err;
  } finally {
    client.release();
  }
}

/**
 * Three outcomes, not two: the password can be wrong, the password can be
 * enough, or the password can be correct but only half the story. The middle
 * state deliberately carries no session — see mfa_challenges in 017_mfa.sql.
 */
export type LoginResult =
  | { token: string; user: SessionUser }
  | { mfaRequired: true; challenge: string }
  | AuthError;

export async function login(emailRaw: string, password: string): Promise<LoginResult> {
  const email = String(emailRaw || "").trim().toLowerCase();
  const r = await pool.query<{ id: string; email: string; name: string; password_hash: string; email_verified: boolean; is_platform_admin: boolean }>(
    "SELECT id, email, name, password_hash, email_verified, is_platform_admin FROM users WHERE email = $1",
    [email],
  );
  const u = r.rows[0];
  if (!u || !verifyPassword(password, u.password_hash)) {
    return { error: "Incorrect email or password." };
  }
  // Second factor, if this account has one. Nothing that follows — no session,
  // no invite activation — happens until the factor is presented.
  if (await Mfa.isEnabled(u.id)) {
    return { mfaRequired: true, challenge: await Mfa.createChallenge(u.id) };
  }
  return {
    token: await finishLogin(u.id, u.email, u.email_verified),
    user: { id: u.id, email: u.email, name: u.name, emailVerified: u.email_verified, isPlatformAdmin: u.is_platform_admin },
  };
}

/** The tail of a successful login, shared by the one-factor and two-factor paths. */
async function finishLogin(id: string, email: string, emailVerified: boolean): Promise<string> {
  // Pick up invites created since last login — verified addresses only (see signup).
  if (emailVerified) await activateInvites(pool, id, email);
  return createSession(pool, id);
}

/**
 * Second leg of a two-factor login: exchange a challenge token plus a TOTP or
 * recovery code for a real session. The challenge survives a wrong code (so a
 * typo doesn't send the user back to the password form) but is burned the
 * moment one is accepted.
 */
export async function completeMfaLogin(
  challenge: string,
  code: string,
): Promise<{ token: string; user: SessionUser; usedRecoveryCode: boolean } | AuthError> {
  const userId = await Mfa.challengeUser(challenge);
  if (!userId) return { error: "That sign-in attempt expired. Please enter your password again." };

  const v = await Mfa.verifyForLogin(userId, code);
  if (!v.ok) return { error: "That code isn't right. Try again, or use a recovery code." };

  await Mfa.consumeChallenge(challenge);
  const r = await pool.query<{ id: string; email: string; name: string; email_verified: boolean; is_platform_admin: boolean }>(
    "SELECT id, email, name, email_verified, is_platform_admin FROM users WHERE id = $1",
    [userId],
  );
  const u = r.rows[0];
  if (!u) return { error: "Account not found." };
  return {
    token: await finishLogin(u.id, u.email, u.email_verified),
    user: { id: u.id, email: u.email, name: u.name, emailVerified: u.email_verified, isPlatformAdmin: u.is_platform_admin },
    usedRecoveryCode: !!v.usedRecoveryCode,
  };
}

/**
 * Re-check a signed-in user's password. Turning MFA off is precisely what
 * someone holding a stolen session would do, so that route asks for the
 * password again rather than trusting the cookie.
 */
export async function checkPassword(userId: string, password: string): Promise<boolean> {
  const r = await pool.query<{ password_hash: string }>("SELECT password_hash FROM users WHERE id = $1", [userId]);
  const row = r.rows[0];
  return !!row && verifyPassword(password, row.password_hash);
}

async function createSession(
  client: { query: (q: string, p: unknown[]) => Promise<unknown> },
  userId: string,
): Promise<string> {
  const token = randomBytes(32).toString("base64url");
  await client.query(
    `INSERT INTO user_sessions (token_hash, user_id, expires_at)
     VALUES ($1, $2, now() + interval '${SESSION_TTL_DAYS} days')`,
    [sha256(token), userId],
  );
  return token;
}

/** Resolve the signed-in user from a session token, or null. */
export async function sessionUser(token: string | undefined): Promise<SessionUser | null> {
  if (!token) return null;
  const r = await pool.query<{ id: string; email: string; name: string; email_verified: boolean; is_platform_admin: boolean }>(
    `SELECT u.id, u.email, u.name, u.email_verified, u.is_platform_admin
     FROM user_sessions s JOIN users u ON u.id = s.user_id
     WHERE s.token_hash = $1 AND s.expires_at > now()`,
    [sha256(token)],
  );
  const u = r.rows[0];
  return u ? { id: u.id, email: u.email, name: u.name, emailVerified: u.email_verified, isPlatformAdmin: u.is_platform_admin } : null;
}

export async function logout(token: string | undefined): Promise<void> {
  if (token) await pool.query("DELETE FROM user_sessions WHERE token_hash = $1", [sha256(token)]);
}

// ---------------- email verification ----------------

export function emailConfigured(): boolean {
  return Email.configured();
}

/** Mark the user behind a valid verification token as verified. */
export async function verifyEmailToken(token: string): Promise<{ ok: true } | AuthError> {
  if (!token) return { error: "Invalid link." };
  const r = await pool.query<{ user_id: string }>(
    "SELECT user_id FROM email_verifications WHERE token_hash = $1 AND expires_at > now()",
    [sha256(token)],
  );
  const row = r.rows[0];
  if (!row) return { error: "This verification link is invalid or has expired." };
  await pool.query("UPDATE users SET email_verified = true WHERE id = $1", [row.user_id]);
  await pool.query("DELETE FROM email_verifications WHERE user_id = $1", [row.user_id]);
  // Verification is the moment an invite becomes safe to honour, so this is
  // where pending invites are redeemed. Without it, gating signup/login on
  // `email_verified` would leave an invited user permanently outside the org.
  const who = await pool.query<{ email: string }>("SELECT email FROM users WHERE id = $1", [row.user_id]);
  if (who.rows[0]) await activateInvites(pool, row.user_id, who.rows[0].email);
  return { ok: true };
}

/** Re-issue a verification email for the signed-in user. */
export async function resendVerification(userId: string, email: string, name: string): Promise<{ sent: boolean; configured: boolean; alreadyVerified?: boolean }> {
  const u = await pool.query<{ email_verified: boolean }>("SELECT email_verified FROM users WHERE id = $1", [userId]);
  if (u.rows[0]?.email_verified) return { sent: false, configured: Email.configured(), alreadyVerified: true };
  await pool.query("DELETE FROM email_verifications WHERE user_id = $1", [userId]);
  const vtoken = randomBytes(24).toString("base64url");
  await pool.query(
    "INSERT INTO email_verifications (token_hash, user_id, email, expires_at) VALUES ($1, $2, $3, now() + interval '24 hours')",
    [sha256(vtoken), userId, email],
  );
  await Email.sendVerification(email, name, verificationLink(vtoken));
  return { sent: true, configured: Email.configured() };
}

// ---------------- password reset ----------------

/**
 * Start a password reset. If the email has an account, email a single-use reset
 * link. Always returns the same {ok:true} regardless — never reveal whether an
 * address is registered (anti-enumeration).
 */
export async function requestPasswordReset(emailRaw: string): Promise<{ ok: true }> {
  const email = String(emailRaw || "").trim().toLowerCase();
  const r = await pool.query<{ id: string; name: string }>("SELECT id, name FROM users WHERE email = $1", [email]);
  const u = r.rows[0];
  if (u) {
    await pool.query("DELETE FROM password_resets WHERE user_id = $1", [u.id]);
    const token = randomBytes(24).toString("base64url");
    await pool.query(
      "INSERT INTO password_resets (token_hash, user_id, expires_at) VALUES ($1, $2, now() + interval '1 hour')",
      [sha256(token), u.id],
    );
    await Email.sendPasswordReset(email, u.name, resetLink(token));
  }
  return { ok: true };
}

/** Complete a reset: set the new password, consume the token, and sign the user
 *  out everywhere (invalidate all their sessions). */
export async function resetPassword(token: string, newPassword: string): Promise<{ ok: true } | AuthError> {
  if (!newPassword || newPassword.length < 8) return { error: "Password must be at least 8 characters." };
  const r = await pool.query<{ user_id: string }>(
    "SELECT user_id FROM password_resets WHERE token_hash = $1 AND expires_at > now()",
    [sha256(token)],
  );
  const row = r.rows[0];
  if (!row) return { error: "This reset link is invalid or has expired." };
  await pool.query("UPDATE users SET password_hash = $2 WHERE id = $1", [row.user_id, hashPassword(newPassword)]);
  await pool.query("DELETE FROM password_resets WHERE user_id = $1", [row.user_id]);
  await pool.query("DELETE FROM user_sessions WHERE user_id = $1", [row.user_id]); // force re-login everywhere
  return { ok: true };
}

// ---------------- authorization ----------------

/** Org ids the user belongs to. */
export async function userOrgIds(userId: string): Promise<string[]> {
  const r = await pool.query<{ org_id: string }>("SELECT org_id FROM memberships WHERE user_id = $1", [userId]);
  return r.rows.map((x) => x.org_id);
}

/** Every org id — the platform-admin catalog scope. */
export async function allOrgIds(): Promise<string[]> {
  const r = await pool.query<{ id: string }>("SELECT id FROM organizations");
  return r.rows.map((x) => x.id);
}

/** Is `projectId` inside one of the user's organizations? */
export async function userCanAccessProject(userId: string, projectId: string): Promise<boolean> {
  const safe = safeProjectId(projectId); // must match the query-side sanitizer exactly
  if (!safe) return false;
  const r = await pool.query(
    `SELECT 1 FROM projects p JOIN memberships m ON m.org_id = p.org_id
     WHERE p.id = $1 AND m.user_id = $2 LIMIT 1`,
    [safe, userId],
  );
  return (r.rowCount ?? 0) > 0;
}

// ---------------- roles ----------------

export const ROLE_RANK: Record<string, number> = { viewer: 0, member: 1, admin: 2, owner: 3 };
export const ASSIGNABLE_ROLES = ["admin", "member", "viewer"]; // owner is implicit (creator)

/** The user's role in the org that owns `projectId`, or null if not a member. */
export async function userRoleForProject(userId: string, projectId: string): Promise<string | null> {
  const safe = safeProjectId(projectId); // must match the query-side sanitizer exactly
  if (!safe) return null;
  const r = await pool.query<{ role: string }>(
    `SELECT m.role FROM projects p JOIN memberships m ON m.org_id = p.org_id
     WHERE p.id = $1 AND m.user_id = $2 LIMIT 1`,
    [safe, userId],
  );
  return r.rows[0]?.role ?? null;
}

export async function orgIdForProject(projectId: string): Promise<string | null> {
  const safe = safeProjectId(projectId); // must match the query-side sanitizer exactly
  if (!safe) return null;
  const r = await pool.query<{ org_id: string }>("SELECT org_id FROM projects WHERE id = $1", [safe]);
  return r.rows[0]?.org_id ?? null;
}

export async function userRoleForOrg(userId: string, orgId: string): Promise<string | null> {
  const r = await pool.query<{ role: string }>(
    "SELECT role FROM memberships WHERE user_id = $1 AND org_id = $2",
    [userId, orgId],
  );
  return r.rows[0]?.role ?? null;
}

function atLeast(role: string | null, min: string): boolean {
  return role != null && (ROLE_RANK[role] ?? -1) >= (ROLE_RANK[min] ?? 99);
}

// ---------------- team / invitations ----------------

export interface Member {
  userId: string | null;
  email: string;
  name: string;
  role: string;
  pending: boolean;
  inviteToken?: string;
}

/** Members of an org plus any pending invitations. */
export async function listMembers(orgId: string): Promise<Member[]> {
  const active = await pool.query<{ user_id: string; email: string; name: string; role: string }>(
    `SELECT u.id AS user_id, u.email, u.name, m.role
     FROM memberships m JOIN users u ON u.id = m.user_id
     WHERE m.org_id = $1 ORDER BY (m.role='owner') DESC, u.email`,
    [orgId],
  );
  const pending = await pool.query<{ email: string; role: string; token: string }>(
    "SELECT email, role, token FROM invitations WHERE org_id = $1 AND accepted_at IS NULL ORDER BY email",
    [orgId],
  );
  return [
    ...active.rows.map((r) => ({ userId: r.user_id, email: r.email, name: r.name, role: r.role, pending: false })),
    ...pending.rows.map((r) => ({ userId: null, email: r.email, name: "", role: r.role, pending: true, inviteToken: r.token })),
  ];
}

/**
 * Invite an email to an org with a role. If the email already has an account,
 * they're added immediately; otherwise a pending invitation is recorded and
 * activated when they sign up / sign in. Returns { added } or { invited, token }.
 */
export async function inviteMember(
  orgId: string,
  emailRaw: string,
  role: string,
  invitedBy: string,
): Promise<{ added?: boolean; invited?: boolean; token?: string } | AuthError> {
  const email = String(emailRaw || "").trim().toLowerCase();
  if (!validEmail(email)) return { error: "Enter a valid email address." };
  if (!ASSIGNABLE_ROLES.includes(role)) return { error: "Invalid role." };

  const existing = await pool.query<{ id: string }>("SELECT id FROM users WHERE email = $1", [email]);
  if (existing.rowCount) {
    const uid = existing.rows[0].id;
    const already = await pool.query("SELECT 1 FROM memberships WHERE user_id = $1 AND org_id = $2", [uid, orgId]);
    if (already.rowCount) return { error: "That person is already a member." };
    await pool.query("INSERT INTO memberships (user_id, org_id, role) VALUES ($1, $2, $3)", [uid, orgId, role]);
    return { added: true };
  }
  const token = randomBytes(18).toString("base64url");
  await pool.query(
    `INSERT INTO invitations (org_id, email, role, token, invited_by) VALUES ($1, $2, $3, $4, $5)
     ON CONFLICT (org_id, email) DO UPDATE SET role = EXCLUDED.role, token = EXCLUDED.token, accepted_at = NULL`,
    [orgId, email, role, token, invitedBy],
  );
  return { invited: true, token };
}

/** Change a member's role. Refuses to demote the last owner. */
export async function updateMemberRole(orgId: string, targetUserId: string, role: string): Promise<AuthError | { ok: true }> {
  if (!ASSIGNABLE_ROLES.includes(role) && role !== "owner") return { error: "Invalid role." };
  const cur = await pool.query<{ role: string }>("SELECT role FROM memberships WHERE org_id = $1 AND user_id = $2", [orgId, targetUserId]);
  if (!cur.rowCount) return { error: "Not a member." };
  if (cur.rows[0].role === "owner" && role !== "owner") {
    const owners = await pool.query("SELECT count(*)::int AS n FROM memberships WHERE org_id = $1 AND role = 'owner'", [orgId]);
    if ((owners.rows[0] as { n: number }).n <= 1) return { error: "Can't change the last owner's role." };
  }
  await pool.query("UPDATE memberships SET role = $3 WHERE org_id = $1 AND user_id = $2", [orgId, targetUserId, role]);
  return { ok: true };
}

/** Remove a member (or revoke a pending invite by email). Refuses the last owner. */
export async function removeMember(orgId: string, targetUserId: string): Promise<AuthError | { ok: true }> {
  const cur = await pool.query<{ role: string }>("SELECT role FROM memberships WHERE org_id = $1 AND user_id = $2", [orgId, targetUserId]);
  if (cur.rowCount && cur.rows[0].role === "owner") {
    const owners = await pool.query("SELECT count(*)::int AS n FROM memberships WHERE org_id = $1 AND role = 'owner'", [orgId]);
    if ((owners.rows[0] as { n: number }).n <= 1) return { error: "Can't remove the last owner." };
  }
  await pool.query("DELETE FROM memberships WHERE org_id = $1 AND user_id = $2", [orgId, targetUserId]);
  return { ok: true };
}

export async function revokeInvite(orgId: string, email: string): Promise<void> {
  await pool.query("DELETE FROM invitations WHERE org_id = $1 AND lower(email) = lower($2) AND accepted_at IS NULL", [orgId, email]);
}

/** Turn any pending invitations for this email into memberships. */
async function activateInvites(
  exec: { query: (q: string, p: unknown[]) => Promise<unknown> },
  userId: string,
  email: string,
): Promise<void> {
  await exec.query(
    `INSERT INTO memberships (user_id, org_id, role)
     SELECT $1, org_id, role FROM invitations WHERE lower(email) = lower($2) AND accepted_at IS NULL
     ON CONFLICT (user_id, org_id) DO NOTHING`,
    [userId, email],
  );
  await exec.query("UPDATE invitations SET accepted_at = now() WHERE lower(email) = lower($1) AND accepted_at IS NULL", [email]);
}

export { atLeast };

/** Parse the session token out of a Cookie header. */
export function parseSessionCookie(cookieHeader: string | undefined): string | undefined {
  if (!cookieHeader) return undefined;
  for (const part of cookieHeader.split(";")) {
    const [k, ...v] = part.trim().split("=");
    if (k === SESSION_COOKIE) return decodeURIComponent(v.join("="));
  }
  return undefined;
}

/**
 * `Secure` is emitted only for connections that are actually TLS. It used to be
 * unconditional, which reads as "more secure" but means the browser silently
 * discards the cookie over plain HTTP — so local development and any
 * self-hosted HTTP deployment could never stay signed in, with no error to
 * explain why. Over HTTPS the flag is still always set, which is the case that
 * matters; `ARGUS_FORCE_SECURE_COOKIE=1` pins it on for a proxy we can't detect.
 */
function cookieAttrs(secure: boolean): string {
  const forced = process.env.ARGUS_FORCE_SECURE_COOKIE === "1";
  return `HttpOnly; ${secure || forced ? "Secure; " : ""}SameSite=Lax; Path=/`;
}

export function sessionCookie(token: string, secure = true): string {
  const maxAge = SESSION_TTL_DAYS * 24 * 3600;
  return `${SESSION_COOKIE}=${token}; ${cookieAttrs(secure)}; Max-Age=${maxAge}`;
}

export function clearCookie(secure = true): string {
  return `${SESSION_COOKIE}=; ${cookieAttrs(secure)}; Max-Age=0`;
}
