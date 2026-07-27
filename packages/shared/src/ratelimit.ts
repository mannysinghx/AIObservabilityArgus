/**
 * Fixed-window rate limiting, shared by every service.
 *
 * Redis-backed so the limit is the *platform's* limit rather than one replica's
 * — an IP that gets 5 login attempts should not get 5 per instance behind a load
 * balancer. When Redis is unreachable it degrades to an in-process counter
 * rather than failing open completely: a degraded limit still stops a brute
 * force, whereas no limit at all is how the outage becomes the breach.
 *
 * Fixed windows (not sliding) on purpose: one INCR + one PEXPIRE per request,
 * no sorted sets to trim, and the worst case (2x the limit across a window
 * boundary) is irrelevant at the thresholds we care about.
 */
import Redis from "ioredis";
import { config } from "./config.js";

export interface RateLimitResult {
  allowed: boolean;
  /** Requests left in the current window (0 when blocked). */
  remaining: number;
  /** Milliseconds until the window resets — feeds the Retry-After header. */
  resetMs: number;
  /** True when the in-process fallback was used (Redis was unreachable). */
  degraded: boolean;
}

// Fallback counters, only touched when Redis errors. Keyed by "<key>:<window>"
// so old windows fall out naturally; swept when the map grows.
const local = new Map<string, number>();
function localHit(key: string, limit: number, windowMs: number): RateLimitResult {
  const window = Math.floor(Date.now() / windowMs);
  const k = `${key}:${window}`;
  const n = (local.get(k) ?? 0) + 1;
  local.set(k, n);
  if (local.size > 10_000) {
    for (const old of local.keys()) {
      if (!old.endsWith(`:${window}`)) local.delete(old);
    }
  }
  const resetMs = (window + 1) * windowMs - Date.now();
  return { allowed: n <= limit, remaining: Math.max(0, limit - n), resetMs, degraded: true };
}

/**
 * Dedicated connection, NOT the shared `redis()` client.
 *
 * The shared client is configured with `maxRetriesPerRequest: null` because the
 * ingest hot path must never drop a span — a command issued while Redis is down
 * queues until Redis returns. That is exactly right for XADD and exactly wrong
 * here: a rate-limit check that waits indefinitely doesn't degrade, it hangs the
 * request it was supposed to be protecting, and a Redis blip becomes a total
 * outage of login. So this connection is told to fail fast and give up, which is
 * what makes the in-process fallback below reachable at all.
 */
let limiterConn: Redis | null = null;
function limiter(): Redis {
  return (limiterConn ??= new Redis(config.redisUrl, {
    maxRetriesPerRequest: 1,
    enableOfflineQueue: false, // reject immediately when not connected
    connectTimeout: 1000,
    lazyConnect: false,
    retryStrategy: (times) => Math.min(times * 200, 5000),
  }).on("error", () => {
    /* expected while Redis is down; the fallback covers it */
  }));
}

/** Belt and braces: even a "fail fast" client can stall on a half-open socket. */
const REDIS_TIMEOUT_MS = 250;
function withTimeout<T>(p: Promise<T>): Promise<T> {
  return Promise.race([
    p,
    new Promise<T>((_, rej) => setTimeout(() => rej(new Error("rate-limit redis timeout")), REDIS_TIMEOUT_MS)),
  ]);
}

/**
 * Count one hit against `key`. Returns whether it is allowed.
 *
 * @param key      Identity being limited — include the scope, e.g. `login:1.2.3.4`.
 * @param limit    Max hits per window.
 * @param windowMs Window length in milliseconds.
 */
export async function rateLimit(
  key: string,
  limit: number,
  windowMs: number,
): Promise<RateLimitResult> {
  const window = Math.floor(Date.now() / windowMs);
  const redisKey = `argus:rl:${key}:${window}`;
  try {
    const r = limiter();
    const n = await withTimeout(r.incr(redisKey));
    // Only the first hit of a window needs the TTL; PEXPIRE on every hit would
    // keep pushing the expiry out and turn a fixed window into a rolling one.
    if (n === 1) await withTimeout(r.pexpire(redisKey, windowMs));
    const resetMs = (window + 1) * windowMs - Date.now();
    return { allowed: n <= limit, remaining: Math.max(0, limit - n), resetMs, degraded: false };
  } catch {
    return localHit(key, limit, windowMs);
  }
}

/** Release the limiter connection (tests and graceful shutdown). */
export async function closeRateLimiter(): Promise<void> {
  const c = limiterConn;
  limiterConn = null;
  if (c) await c.quit().catch(() => c.disconnect());
}

/** Named limit policies, so thresholds live in one reviewable place. */
export const LIMITS = {
  /** Password guessing. Deliberately tight; a human never hits it. */
  login: { limit: 10, windowMs: 15 * 60_000 },
  /** Account creation from one address. */
  signup: { limit: 5, windowMs: 60 * 60_000 },
  /** Outbound-email triggers — these spend money and reputation. */
  emailTrigger: { limit: 5, windowMs: 60 * 60_000 },
  /** Reset-token submission (guessing a token). */
  resetSubmit: { limit: 20, windowMs: 15 * 60_000 },
  /** General authenticated dashboard API traffic, per user. */
  api: { limit: 600, windowMs: 60_000 },
  /** Telemetry ingest, per project. Generous — this is the product's hot path. */
  ingest: { limit: Number(process.env.INGEST_RATE_LIMIT ?? 6000), windowMs: 60_000 },
} as const;
