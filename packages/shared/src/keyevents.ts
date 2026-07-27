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

/**
 * A monotonically increasing counter bumped on every revocation.
 *
 * Pub/sub alone is not sufficient. Redis pub/sub delivers only to subscribers
 * connected at the moment of publish, so a process that is starting up,
 * reconnecting, or (as in a single-process test) publishing before its own
 * subscriber has finished attaching simply never hears about the revocation and
 * keeps honouring the key until its cache entry expires. "Probably propagates"
 * is not a good enough guarantee for the one action a customer takes when they
 * believe a credential has leaked.
 *
 * So the epoch is the correctness mechanism and pub/sub is the latency
 * optimisation: cache entries record the epoch they were created under, and a
 * changed epoch invalidates them no matter what happened on the channel.
 */
const EPOCH_KEY = "argus:key-epoch";

/** Announce that one or more API keys are no longer valid. Never throws. */
export async function publishKeyRevoked(projectId: string): Promise<void> {
  // Expire our OWN epoch cache first and unconditionally.
  //
  // Without this, a single-process deployment (and any deployment where the
  // dashboard and the API share a process) would keep honouring the revoked key
  // for up to the poll interval: the process bumps the epoch in Redis but goes
  // on comparing against the copy it read a moment earlier. The one process
  // that definitely knows a revocation happened is the one performing it.
  expireEpochCache();
  try {
    // Bump before publishing: a subscriber that receives the message will
    // already see the new epoch, and one that misses it picks the change up on
    // its next poll, which is what makes this correct rather than hopeful.
    await redis().incr(EPOCH_KEY);
    await redis().publish(KEY_REVOKED_CHANNEL, JSON.stringify({ projectId, at: Date.now() }));
  } catch {
    /* best effort — the cache TTL is the final backstop */
  }
}

// The epoch is read at most once per EPOCH_POLL_MS per process, so this costs a
// single Redis GET per second under any load.
const EPOCH_POLL_MS = 1000;
let epochValue = 0;
let epochReadAt = 0;

/**
 * The current revocation epoch. Returns the last known value when Redis is
 * unreachable — an epoch that fails to advance degrades to TTL-based expiry,
 * which is the old behaviour rather than a new failure.
 */
export async function keyEpoch(): Promise<number> {
  const now = Date.now();
  if (now - epochReadAt < EPOCH_POLL_MS) return epochValue;
  epochReadAt = now;
  try {
    epochValue = Number(await redis().get(EPOCH_KEY)) || 0;
  } catch {
    /* keep the previous value */
  }
  return epochValue;
}

/** Force the next keyEpoch() to re-read. Used when a revocation is observed on
 *  the channel, so the fast path doesn't wait out the poll interval. */
export function expireEpochCache(): void {
  epochReadAt = 0;
}

/**
 * Listen for revocations. Uses its own connection because a Redis client in
 * subscriber mode cannot serve normal commands, and the shared one is busy
 * doing XADD on the ingest hot path.
 */
// Tracked so it can be closed. A subscriber connection is long-lived by nature,
// which makes it exactly the kind of handle that silently outlives the process
// that created it.
const subscribers = new Set<Redis>();

/** Close every subscriber connection. */
export async function closeKeyEventSubscribers(): Promise<void> {
  const all = [...subscribers];
  subscribers.clear();
  await Promise.all(all.map((s) => s.quit().catch(() => s.disconnect())));
}

export function subscribeKeyRevoked(onRevoked: (projectId: string) => void): Redis {
  const sub = new Redis(config.redisUrl, { maxRetriesPerRequest: null, lazyConnect: false });
  subscribers.add(sub);
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
