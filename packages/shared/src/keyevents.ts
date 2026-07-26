/**
 * Credential-invalidation fan-out.
 *
 * The ingest service caches key lookups for ~60s so it doesn't hit Postgres on
 * every span. That cache is also a 60-second window in which a key you *just*
 * revoked still works — which is the wrong behaviour for the one action a
 * customer takes when they believe a key has leaked. Revocation is exactly the
 * case where "eventually consistent" is the wrong default.
 *
 * So the dashboard announces revocations on a Redis channel and every ingest
 * replica drops its cache on receipt. Sub-second in practice, and the failure
 * mode if Redis is down is the old behaviour (expire on TTL), not a broken
 * revoke.
 */
import Redis from "ioredis";
import { config } from "./config.js";
import { redis } from "./redis.js";

export const KEY_REVOKED_CHANNEL = "argus:key-revoked";

/** Announce that one or more API keys are no longer valid. Never throws. */
export async function publishKeyRevoked(projectId: string): Promise<void> {
  try {
    await redis().publish(KEY_REVOKED_CHANNEL, JSON.stringify({ projectId, at: Date.now() }));
  } catch {
    /* best effort — the TTL is the backstop */
  }
}

/**
 * Listen for revocations. Uses its own connection because a Redis client in
 * subscriber mode cannot serve normal commands, and the shared one is busy
 * doing XADD on the ingest hot path.
 */
export function subscribeKeyRevoked(onRevoked: (projectId: string) => void): Redis {
  const sub = new Redis(config.redisUrl, { maxRetriesPerRequest: null, lazyConnect: false });
  sub.on("error", () => { /* reconnects on its own; don't crash ingest over this */ });
  void sub.subscribe(KEY_REVOKED_CHANNEL);
  sub.on("message", (channel, message) => {
    if (channel !== KEY_REVOKED_CHANNEL) return;
    try {
      const { projectId } = JSON.parse(message) as { projectId?: string };
      onRevoked(String(projectId ?? ""));
    } catch {
      onRevoked(""); // unparseable => invalidate everything, the safe direction
    }
  });
  return sub;
}
