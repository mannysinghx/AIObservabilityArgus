/**
 * API key authentication, shared by the ingest service and the public read API.
 *
 * One definition of "is this key valid, and what may it do", because the
 * alternative — each service deciding for itself — is how a key ends up
 * accepted by one surface and rejected by another, or worse, accepted by both
 * with different scope rules.
 */
import pg from "pg";
import { createHash } from "node:crypto";
import { config } from "./config.js";
import { expireEpochCache, keyEpoch, subscribeKeyRevoked } from "./keyevents.js";

export type Scope = "ingest" | "read";

export interface AuthedKey {
  projectId: string;
  publicKey: string;
  keyId: string;
  scopes: Scope[];
}

let _pool: pg.Pool | null = null;
function pool(): pg.Pool {
  return (_pool ??= new pg.Pool({ connectionString: config.databaseUrl, max: 4 }));
}

function sha256(s: string): string {
  return createHash("sha256").update(s).digest("hex");
}

// Short-lived cache so a busy read client doesn't hit Postgres per request.
// Entries carry the revocation epoch they were created under; a bump to that
// epoch invalidates them regardless of whether the pub/sub message arrived.
const cache = new Map<string, { key: AuthedKey; expires: number; epoch: number }>();
const TTL_MS = 60_000;

// Revocation must not wait for the TTL — see keyevents.ts.
let subscribed = false;
function ensureSubscribed(): void {
  if (subscribed) return;
  subscribed = true;
  subscribeKeyRevoked((projectId) => {
    expireEpochCache(); // don't wait out the poll interval when we did hear it
    if (!projectId) return void cache.clear();
    for (const [k, v] of cache) if (v.key.projectId === projectId) cache.delete(k);
  });
}

function parseScopes(raw: unknown): Scope[] {
  const list = Array.isArray(raw) ? raw.map(String) : [];
  return list.filter((s): s is Scope => s === "ingest" || s === "read");
}

/**
 * Resolve `Authorization: Bearer ak_live_…` to a project and its scopes.
 * Returns null for unknown or revoked keys.
 */
export async function authenticateKey(token: string): Promise<AuthedKey | null> {
  ensureSubscribed();
  const hash = sha256(token);
  const cacheKey = `tok:${hash}`;
  const epoch = await keyEpoch();
  const hit = cache.get(cacheKey);
  // Both conditions matter: the TTL bounds staleness in the normal case, the
  // epoch makes a revocation take effect even if the notification was missed.
  if (hit && hit.expires > Date.now() && hit.epoch === epoch) return hit.key;

  const res = await pool().query<{
    id: string; project_id: string; public_key: string; scopes: string[] | null;
  }>(
    `SELECT id, project_id, public_key, scopes FROM api_keys
     WHERE token_hash = $1 AND revoked_at IS NULL LIMIT 1`,
    [hash],
  );
  if (res.rowCount === 0) return null;
  const row = res.rows[0];

  const key: AuthedKey = {
    projectId: row.project_id,
    publicKey: row.public_key,
    keyId: row.id,
    scopes: parseScopes(row.scopes),
  };
  cache.set(cacheKey, { key, expires: Date.now() + TTL_MS, epoch });
  pool().query(`UPDATE api_keys SET last_used_at = now() WHERE id = $1`, [row.id]).catch(() => {});
  return key;
}

export function hasScope(key: AuthedKey, scope: Scope): boolean {
  return key.scopes.includes(scope);
}

export function parseBearer(header?: string): string | null {
  if (!header?.startsWith("Bearer ")) return null;
  const t = header.slice(7).trim();
  return t || null;
}
