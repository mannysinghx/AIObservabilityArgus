/**
 * Release every long-lived connection this package owns.
 *
 * Three of them accumulated without anyone able to close them: the shared Redis
 * client, the rate limiter's dedicated fail-fast client, and the key-revocation
 * subscriber. Each is created lazily on first use and lives for the process, so
 * nothing ever noticed — until CI, where a test file that had touched any of
 * them simply never exited and was reported as cancelled with every assertion
 * inside it passing.
 *
 * It is also what a service needs to shut down cleanly rather than being killed
 * with sockets open.
 */
import { closeRedis } from "./redis.js";
import { closeRateLimiter } from "./ratelimit.js";
import { closeKeyEventSubscribers } from "./keyevents.js";

export async function closeSharedConnections(): Promise<void> {
  // Settled, not all: one connection refusing to close must not leave the
  // others open, since the point of calling this is to let the process exit.
  await Promise.allSettled([
    closeKeyEventSubscribers(),
    closeRateLimiter(),
    closeRedis(),
  ]);
}
