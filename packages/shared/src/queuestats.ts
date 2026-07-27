/**
 * Queue depth and consumer lag.
 *
 * The most valuable number this platform can expose about itself. Every process
 * being up tells you nothing: the way Argus fails in practice is that a consumer
 * group stops advancing — a poison event, a ClickHouse outage, a detection
 * service that hangs — while the ingest API keeps happily accepting spans. From
 * outside, everything is green and data has silently stopped landing.
 *
 * Lag is the number that catches that, and it catches it within one scrape.
 */
import { redis } from "./redis.js";
import { STREAM_KEY, GROUP_TRACE, GROUP_SECURITY } from "./config.js";
import { metrics } from "./metrics.js";

export interface GroupStats {
  group: string;
  /** Entries delivered but not yet acked. A number that only grows is a stall. */
  pending: number;
  /** Entries added to the stream since this group's last-delivered id. */
  lag: number;
  consumers: number;
}

export interface QueueStats {
  streamLength: number;
  dlqLength: number;
  groups: GroupStats[];
}

const DLQ_KEY = "argus:ingest:dlq";

export async function collectQueueStats(): Promise<QueueStats> {
  const r = redis();
  const [streamLength, dlqLength] = await Promise.all([
    r.xlen(STREAM_KEY).catch(() => 0),
    r.xlen(DLQ_KEY).catch(() => 0),
  ]);

  const groups: GroupStats[] = [];
  try {
    // XINFO GROUPS returns a flat field/value array per group.
    const raw = (await r.xinfo("GROUPS", STREAM_KEY)) as unknown as unknown[][];
    for (const entry of raw) {
      const rec: Record<string, unknown> = {};
      for (let i = 0; i < entry.length; i += 2) rec[String(entry[i])] = entry[i + 1];
      const name = String(rec.name ?? "");
      if (name !== GROUP_TRACE && name !== GROUP_SECURITY) continue;
      groups.push({
        group: name,
        pending: Number(rec.pending ?? 0),
        // `lag` is null on older Redis or after certain trims; treat unknown as
        // 0 rather than guessing, so an alert never fires on a missing field.
        lag: rec.lag == null ? 0 : Number(rec.lag),
        consumers: Number(rec.consumers ?? 0),
      });
    }
  } catch {
    /* stream may not exist yet — no groups is a valid answer */
  }

  return { streamLength, dlqLength, groups };
}

/** Refresh the queue gauges. Called from each service's /metrics handler. */
export async function refreshQueueMetrics(): Promise<QueueStats> {
  const s = await collectQueueStats();
  metrics.set("argus_stream_length", s.streamLength, {}, "Entries in the ingest stream");
  metrics.set("argus_dlq_length", s.dlqLength, {}, "Entries quarantined in the dead-letter stream");
  for (const g of s.groups) {
    metrics.set("argus_consumer_pending", g.pending, { group: g.group }, "Delivered but unacked entries");
    metrics.set("argus_consumer_lag", g.lag, { group: g.group }, "Entries not yet delivered to this group");
    metrics.set("argus_consumer_count", g.consumers, { group: g.group }, "Active consumers in this group");
  }
  return s;
}
