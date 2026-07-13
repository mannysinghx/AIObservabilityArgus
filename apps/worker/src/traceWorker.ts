import { createHash, randomUUID } from "node:crypto";
import {
  insertRows,
  toChDateTime,
  type StreamEvent,
  type TraceInput,
  type ObservationInput,
} from "@argus/shared";
import { inferTaint } from "./taint.js";

const PREVIEW_LIMIT = 4000;

function preview(s: string): string {
  return s.length > PREVIEW_LIMIT ? s.slice(0, PREVIEW_LIMIT) : s;
}

function sha256(s: string): string {
  return createHash("sha256").update(s).digest("hex");
}

// The analyzable body per span type — matches the detection client so the
// stored content_sha256 corresponds to what detection actually scanned (used
// later for cross-trace poisoned-document correlation).
function contentOf(o: ObservationInput): string {
  if (o.type === "generation" || o.type === "retrieval") return o.output || o.input;
  return [o.input, o.output].filter(Boolean).join("\n");
}

/**
 * Trace worker: normalizes stream events into ClickHouse rows.
 * Writes `traces`, `observations` (FULL content, untruncated, plus a preview
 * for fast list views), and an append-only `raw_events` archive of every
 * ingested envelope so history can be re-scored by future detectors.
 */
export async function handleTraceBatch(events: StreamEvent[]) {
  const traceRows: Record<string, unknown>[] = [];
  const obsRows: Record<string, unknown>[] = [];
  const rawRows: Record<string, unknown>[] = [];
  const now = toChDateTime(new Date().toISOString());

  for (const ev of events) {
    if (ev.kind === "trace") {
      const t = ev.payload as TraceInput;
      traceRows.push({
        project_id: ev.projectId,
        trace_id: t.traceId,
        session_id: t.sessionId ?? "",
        user_id: t.userId ?? "",
        name: t.name ?? "",
        timestamp: toChDateTime(t.timestamp),
        environment: t.environment ?? "default",
        release: t.release ?? "",
        metadata: t.metadata ?? {},
        tags: t.tags ?? [],
        event_ts: now,
      });
      rawRows.push({
        project_id: ev.projectId,
        event_id: randomUUID(),
        kind: "trace",
        trace_id: t.traceId,
        received_at: now,
        payload: JSON.stringify(t),
      });
    } else {
      const o = ev.payload as ObservationInput;
      const taint = inferTaint(o);
      const input = o.input ?? "";
      const output = o.output ?? "";
      obsRows.push({
        project_id: ev.projectId,
        trace_id: o.traceId,
        observation_id: o.observationId,
        parent_id: o.parentId ?? "",
        type: o.type,
        name: o.name ?? "",
        start_time: toChDateTime(o.startTime),
        end_time: o.endTime ? toChDateTime(o.endTime) : null,
        model: o.model ?? "",
        provider: o.provider ?? "",
        input_tokens: o.inputTokens ?? 0,
        output_tokens: o.outputTokens ?? 0,
        cost_usd: o.costUsd ?? 0,
        finish_reason: o.finishReason ?? "",
        input_preview: preview(input),
        output_preview: preview(output),
        input_full: input,
        output_full: output,
        content_sha256: sha256(contentOf(o)),
        taint,
        taint_source: o.taintSource ?? "",
        taint_influenced: 0,
        attributes: o.attributes ?? {},
        event_ts: now,
      });
      rawRows.push({
        project_id: ev.projectId,
        event_id: randomUUID(),
        kind: "observation",
        trace_id: o.traceId,
        received_at: now,
        payload: JSON.stringify(o),
      });
    }
  }

  await Promise.all([
    insertRows("traces", traceRows),
    insertRows("observations", obsRows),
    insertRows("raw_events", rawRows),
  ]);
  if (traceRows.length || obsRows.length) {
    console.log(
      `[trace-workers] wrote ${traceRows.length} traces, ${obsRows.length} observations, ${rawRows.length} raw`,
    );
  }
}
