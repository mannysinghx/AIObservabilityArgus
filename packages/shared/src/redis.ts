import Redis from "ioredis";
import { config } from "./config.js";

let conn: Redis | null = null;

export function redis(): Redis {
  if (!conn) {
    conn = new Redis(config.redisUrl, { maxRetriesPerRequest: null });
  }
  return conn;
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
