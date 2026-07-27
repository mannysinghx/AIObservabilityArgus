import Redis from "ioredis";
import { config } from "./config.js";

let conn: Redis | null = null;

export function redis(): Redis {
  if (!conn) {
    conn = new Redis(config.redisUrl, { maxRetriesPerRequest: null });
  }
  return conn;
}

/**
 * Release the shared connection.
 *
 * Needed for graceful shutdown, and needed for tests: an open ioredis socket
 * keeps the event loop alive, so a test file that touched Redis never exits and
 * the runner reports it as cancelled even though every assertion in it passed.
 * That is precisely how this suite failed on CI while passing locally — Node 20
 * and Node 23 differ in how the test runner handles lingering handles, so the
 * bug was invisible on the newer local runtime.
 */
export async function closeRedis(): Promise<void> {
  const c = conn;
  conn = null;
  if (c) await c.quit().catch(() => c.disconnect());
}

/** Create a consumer group if it doesn't already exist (idempotent). */
export async function ensureGroup(stream: string, group: string) {
  try {
    await redis().xgroup("CREATE", stream, group, "$", "MKSTREAM");
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    if (!msg.includes("BUSYGROUP")) throw err;
  }
}
