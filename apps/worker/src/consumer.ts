import { redis, ensureGroup, STREAM_KEY, metrics, type StreamEvent } from "@argus/shared";

type Handler = (events: StreamEvent[]) => Promise<void>;

/**
 * Generic Redis Streams consumer-group loop. Each worker (trace, security) runs
 * its own group so they progress independently — security processing can lag
 * under load without holding up trace availability (docs/02).
 *
 * The important behaviour here is what happens when a batch fails.
 *
 * Previously: the batch was left unacked and the loop continued, forever. There
 * was no attempt counter and no dead-letter, so a single event that could never
 * succeed — a malformed payload, a row ClickHouse rejects — would be redelivered
 * on every pass and block that consumer group permanently. Worse, it was
 * invisible: the process stayed up, the logs showed a handler error scrolling
 * past, and telemetry simply stopped arriving.
 *
 * Now: delivery counts are tracked, and a batch that has failed MAX_DELIVERIES
 * times is split so the poison event can be isolated, moved to a dead-letter
 * stream, and acked — the queue drains, one event is quarantined for inspection
 * instead of the whole pipeline stopping, and the DLQ depth is a metric someone
 * can alert on.
 */

export const DLQ_KEY = "argus:ingest:dlq";

/** Redeliveries before an entry is treated as poison. */
const MAX_DELIVERIES = Number(process.env.CONSUMER_MAX_DELIVERIES ?? 5);

/** Delivery counts for this consumer's pending entries, from XPENDING. */
async function pendingCounts(group: string): Promise<Map<string, number>> {
  const out = new Map<string, number>();
  try {
    const rows = (await redis().xpending(
      STREAM_KEY, group, "-", "+", 100,
    )) as unknown as Array<[string, string, number, number]>;
    for (const [id, , , deliveries] of rows) out.set(id, Number(deliveries));
  } catch {
    /* XPENDING unavailable — fall back to treating everything as first delivery */
  }
  return out;
}

/** Quarantine one entry and ack it so the group can move on. */
async function deadLetter(group: string, id: string, raw: string | undefined, reason: string): Promise<void> {
  try {
    await redis().xadd(
      DLQ_KEY, "*",
      "group", group,
      "id", id,
      "reason", reason.slice(0, 500),
      "event", raw ?? "",
      "at", new Date().toISOString(),
    );
    await redis().xack(STREAM_KEY, group, id);
    metrics.inc("worker_dlq_total", { group });
    console.error(`[${group}] dead-lettered ${id} after ${MAX_DELIVERIES} failed deliveries: ${reason}`);
  } catch (err) {
    console.error(`[${group}] could not dead-letter ${id}:`, err);
  }
}

export async function runConsumer(
  group: string,
  consumerName: string,
  handler: Handler,
  // `signal` exists so the loop can be stopped. In production nothing aborts it
  // — the worker runs until the process ends — but an infinite loop that cannot
  // be stopped is also an infinite loop that cannot be tested, and the retry
  // and dead-letter behaviour here is exactly the sort that has to be.
  opts: { batch?: number; blockMs?: number; signal?: AbortSignal } = {},
) {
  const r = redis();
  await ensureGroup(STREAM_KEY, group);
  const batch = opts.batch ?? 64;
  const blockMs = opts.blockMs ?? 5000;
  console.log(`[${group}] consumer ${consumerName} started`);

  // First drain any pending (previously delivered, unacked) entries, then tail.
  let cursor = "0";
  while (!opts.signal?.aborted) {
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
      const rawById = new Map<string, string>();
      for (const [, entries] of res) {
        for (const [id, fields] of entries) {
          ids.push(id);
          const idx = fields.indexOf("event");
          const raw = idx >= 0 ? fields[idx + 1] : undefined;
          if (raw) rawById.set(id, raw);
          if (raw) {
            try {
              events.push(JSON.parse(raw) as StreamEvent);
            } catch (err) {
              // Unparseable on arrival: it will never parse. Quarantine it now
              // rather than letting it ride along in every future batch.
              console.error(`[${group}] bad event ${id}:`, err);
              await deadLetter(group, id, raw, `unparseable: ${String(err)}`);
            }
          }
        }
      }

      if (cursor === "0" && ids.length === 0) {
        cursor = ">";
        continue;
      }

      if (events.length > 0) {
        const started = Date.now();
        try {
          await handler(events);
          metrics.inc("worker_events_processed_total", { group }, events.length);
          metrics.observe("worker_batch_duration_ms", Date.now() - started, { group });
        } catch (err) {
          metrics.inc("worker_batch_errors_total", { group });
          console.error(`[${group}] handler error:`, err);

          // Has any entry in this batch exhausted its redeliveries?
          const counts = await pendingCounts(group);
          const exhausted = ids.filter((id) => (counts.get(id) ?? 1) >= MAX_DELIVERIES);

          if (exhausted.length > 0) {
            // Retry the exhausted entries ONE AT A TIME to find the actual
            // culprit.
            //
            // The batch failed, but a batch failing does not mean every event
            // in it is bad — almost always exactly one is. Quarantining the
            // whole batch would throw away up to 63 perfectly good events
            // alongside the one poison pill, which is a far worse outcome than
            // the stall this code exists to prevent: a stall is visible and
            // recoverable, silently discarded telemetry is neither.
            for (const id of exhausted) {
              const raw = rawById.get(id);
              if (!raw) { await deadLetter(group, id, raw, "missing payload"); continue; }
              try {
                await handler([JSON.parse(raw) as StreamEvent]);
                await r.xack(STREAM_KEY, group, id); // innocent — it was a neighbour
              } catch (single) {
                await deadLetter(group, id, raw, String(single));
              }
            }
          }
          // Go back to reading this consumer's PENDING list.
          //
          // This is the line that makes retrying actually happen. With cursor
          // ">" Redis delivers only messages that have never been delivered to
          // the group, so a failed batch left unacked was never seen again: it
          // sat in the pending list forever, unprocessed and uncounted, and the
          // events in it were silently lost. The original loop read "0" once at
          // startup and then switched to ">" permanently, so "leave it unacked
          // and a later pass will retry" was never true — there was no later
          // pass. Only "0" re-reads pending entries.
          cursor = "0";
          continue;
        }
      }
      if (ids.length > 0) {
        await r.xack(STREAM_KEY, group, ...ids);
      }
      // Drained the pending list successfully — resume tailing new messages.
      if (cursor === "0") cursor = ">";
    } catch (err) {
      if (opts.signal?.aborted) break;
      metrics.inc("worker_loop_errors_total", { group });
      console.error(`[${group}] consumer loop error:`, err);
      await new Promise((res2) => setTimeout(res2, 1000));
    }
  }
  console.log(`[${group}] consumer ${consumerName} stopped`);
}
