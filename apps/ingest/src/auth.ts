import { createHash } from "node:crypto";
import pg from "pg";
import { config } from "@argus/shared";

const pool = new pg.Pool({ connectionString: config.databaseUrl, max: 4 });

export interface AuthedProject {
  projectId: string;
  publicKey: string;
}

// Small in-process cache so we don't hit Postgres on every ingest request.
const cache = new Map<string, { project: AuthedProject; expires: number }>();
const TTL_MS = 60_000;

function sha256(s: string): string {
  return createHash("sha256").update(s).digest("hex");
}

/**
 * Basic-auth style: publicKey as username, secret as password.
 * Matches the dev seed in deploy/postgres/migrations/001_init.sql
 * (secret_hash = sha256(secret)). Swap for argon2 before production.
 */
export async function authenticate(
  publicKey: string,
  secret: string,
): Promise<AuthedProject | null> {
  const cacheKey = `${publicKey}:${sha256(secret)}`;
  const hit = cache.get(cacheKey);
  if (hit && hit.expires > Date.now()) return hit.project;

  const res = await pool.query(
    `SELECT project_id, secret_hash FROM api_keys WHERE public_key = $1 LIMIT 1`,
    [publicKey],
  );
  if (res.rowCount === 0) return null;
  const row = res.rows[0];
  if (row.secret_hash !== sha256(secret)) return null;

  const project: AuthedProject = { projectId: row.project_id, publicKey };
  cache.set(cacheKey, { project, expires: Date.now() + TTL_MS });
  // best-effort last-used stamp
  pool
    .query(`UPDATE api_keys SET last_used_at = now() WHERE public_key = $1`, [publicKey])
    .catch(() => {});
  return project;
}

export function parseBasicAuth(header?: string): { user: string; pass: string } | null {
  if (!header?.startsWith("Basic ")) return null;
  try {
    const decoded = Buffer.from(header.slice(6), "base64").toString("utf8");
    const idx = decoded.indexOf(":");
    if (idx < 0) return null;
    return { user: decoded.slice(0, idx), pass: decoded.slice(idx + 1) };
  } catch {
    return null;
  }
}
