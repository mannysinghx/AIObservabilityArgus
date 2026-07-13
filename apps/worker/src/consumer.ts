import { redis, ensureGroup, STREAM_KEY, type StreamEvent } from "@argus/shared";

type Handler = (events: StreamEvent[]) => Promise<void>;

/**
 * Generic Redis Streams consumer-group loop. Each worker (trace, security) runs
 * its own group so they progress independently — security processing can lag
 * under load without holding up trace availability (docs/02).
 */
export async function runConsumer(
  group: string,
  consumerName: string,
  handler: Handler,
  opts: { batch?: number; blockMs?: number } = {},
) {
  const r = redis();
  await ensureGroup(STREAM_KEY, group);
  const batch = opts.batch ?? 64;
  const blockMs = opts.blockMs ?? 5000;
  console.log(`[${group}] consumer ${consumerName} started`);

  // First drain any pending (previously delivered, unacked) entries, then tail.
  let cursor = "0";
  for (;;) {
    try {
      const res = (await r.xreadgroup(
        "GROUP",
        group,
        consumerName,
        "COUNT",
        batch,
        "BLOCK",
        blockMs,
        "STREAMS",
        STREAM_KEY,
        cursor,
      )) as [string, [string, string[]][]][] | null;

      if (!res) {
        // No pending backlog left; switch to consuming new messages.
        cursor = ">";
        continue;
      }

      const ids: string[] = [];
      const events: StreamEvent[] = [];
      for (const [, entries] of res) {
        for (const [id, fields] of entries) {
          ids.push(id);
          const idx = fields.indexOf("event");
          if (idx >= 0 && fields[idx + 1]) {
            try {
              events.push(JSON.parse(fields[idx + 1]) as StreamEvent);
            } catch (err) {
              console.error(`[${group}] bad event ${id}:`, err);
            }
          }
        }
      }

      if (cursor === "0" && ids.length === 0) {
        cursor = ">";
        continue;
      }

      if (events.length > 0) {
        try {
          await handler(events);
        } catch (err) {
          console.error(`[${group}] handler error:`, err);
          // Leave unacked so a later run retries via the pending list.
          continue;
        }
      }
      if (ids.length > 0) {
        await r.xack(STREAM_KEY, group, ...ids);
      }
    } catch (err) {
      console.error(`[${group}] consumer loop error:`, err);
      await new Promise((res2) => setTimeout(res2, 1000));
    }
  }
}
