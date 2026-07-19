import { scryptSync, randomBytes, timingSafeEqual } from "node:crypto";
import { pool, sha256 } from "./db.js";
import * as Email from "./email.js";

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

/**
 * Create an account. The FIRST user to sign up bootstraps the platform: they
 * become owner of every organization that already exists (the projects created
 * before accounts existed). Everyone after gets a fresh org from their company
 * name. Returns the new session token, or an error.
 */
export async function signup(
  emailRaw: string,
  password: string,
  name: string,
  companyName: string,
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

    if (isFirst) {
      // Bootstrap: claim every pre-existing organization as owner.
      await client.query(
        "INSERT INTO memberships (user_id, org_id, role) SELECT $1, id, 'owner' FROM organizations ON CONFLICT DO NOTHING",
        [userId],
      );
    }
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

    await activateInvites(client, userId, email); // join any orgs they were invited to

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

export async function login(
  emailRaw: string,
  password: string,
): Promise<{ token: string; user: SessionUser } | AuthError> {
  const email = String(emailRaw || "").trim().toLowerCase();
  const r = await pool.query<{ id: string; email: string; name: string; password_hash: string; email_verified: boolean; is_platform_admin: boolean }>(
    "SELECT id, email, name, password_hash, email_verified, is_platform_admin FROM users WHERE email = $1",
    [email],
  );
  const u = r.rows[0];
  if (!u || !verifyPassword(password, u.password_hash)) {
    return { error: "Incorrect email or password." };
  }
  await activateInvites(pool, u.id, u.email); // pick up invites created since last login
  const token = await createSession(pool, u.id);
  return { token, user: { id: u.id, email: u.email, name: u.name, emailVerified: u.email_verified, isPlatformAdmin: u.is_platform_admin } };
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
  const safe = String(projectId || "").replace(/[^a-zA-Z0-9-]/g, "");
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
  const safe = String(projectId || "").replace(/[^a-zA-Z0-9-]/g, "");
  if (!safe) return null;
  const r = await pool.query<{ role: string }>(
    `SELECT m.role FROM projects p JOIN memberships m ON m.org_id = p.org_id
     WHERE p.id = $1 AND m.user_id = $2 LIMIT 1`,
    [safe, userId],
  );
  return r.rows[0]?.role ?? null;
}

export async function orgIdForProject(projectId: string): Promise<string | null> {
  const safe = String(projectId || "").replace(/[^a-zA-Z0-9-]/g, "");
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

export function sessionCookie(token: string): string {
  const maxAge = SESSION_TTL_DAYS * 24 * 3600;
  return `${SESSION_COOKIE}=${token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${maxAge}`;
}

export function clearCookie(): string {
  return `${SESSION_COOKIE}=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0`;
}
