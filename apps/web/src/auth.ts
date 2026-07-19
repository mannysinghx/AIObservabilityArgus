import { scryptSync, randomBytes, timingSafeEqual } from "node:crypto";
import { pool, sha256 } from "./db.js";

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

    const ins = await client.query<{ id: string }>(
      "INSERT INTO users (email, name, password_hash) VALUES ($1, $2, $3) RETURNING id",
      [email, String(name || "").trim().slice(0, 120), hashPassword(password)],
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

    const token = await createSession(client, userId);
    await client.query("COMMIT");
    return { token, user: { id: userId, email, name: String(name || "").trim() } };
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
  const r = await pool.query<{ id: string; email: string; name: string; password_hash: string }>(
    "SELECT id, email, name, password_hash FROM users WHERE email = $1",
    [email],
  );
  const u = r.rows[0];
  if (!u || !verifyPassword(password, u.password_hash)) {
    return { error: "Incorrect email or password." };
  }
  const token = await createSession(pool, u.id);
  return { token, user: { id: u.id, email: u.email, name: u.name } };
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
  const r = await pool.query<{ id: string; email: string; name: string }>(
    `SELECT u.id, u.email, u.name
     FROM user_sessions s JOIN users u ON u.id = s.user_id
     WHERE s.token_hash = $1 AND s.expires_at > now()`,
    [sha256(token)],
  );
  return r.rows[0] || null;
}

export async function logout(token: string | undefined): Promise<void> {
  if (token) await pool.query("DELETE FROM user_sessions WHERE token_hash = $1", [sha256(token)]);
}

// ---------------- authorization ----------------

/** Org ids the user belongs to. */
export async function userOrgIds(userId: string): Promise<string[]> {
  const r = await pool.query<{ org_id: string }>("SELECT org_id FROM memberships WHERE user_id = $1", [userId]);
  return r.rows.map((x) => x.org_id);
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
