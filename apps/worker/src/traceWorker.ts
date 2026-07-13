import {
  insertRows,
  toChDateTime,
  type StreamEvent,
  type TraceInput,
  type ObservationInput,
} from "@argus/shared";
import { inferTaint } from "./taint.js";

const PREVIEW_LIMIT = 4000;

function truncate(s: string): string {
  return s.length > PREVIEW_LIMIT ? s.slice(0, PREVIEW_LIMIT) : s;
}

/**
 * Trace worker: normalizes stream events into ClickHouse rows.
 * Writes `traces` and `observations`. Content is stored as a truncated preview
 * inline; blob offload to S3/MinIO is a Phase 1.5 addition (pointer columns
 * already exist in the schema).
 */
export async function handleTraceBatch(events: StreamEvent[]) {
  const traceRows: Record<string, unknown>[] = [];
  const obsRows: Record<string, unknown>[] = [];

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
        event_ts: toChDateTime(new Date().toISOString()),
      });
    } else {
      const o = ev.payload as ObservationInput;
      const taint = inferTaint(o);
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
        input_preview: truncate(o.input ?? ""),
        output_preview: truncate(o.output ?? ""),
        content_sha256: "",
        taint,
        taint_source: o.taintSource ?? "",
        taint_influenced: 0,
        attributes: o.attributes ?? {},
        event_ts: toChDateTime(new Date().toISOString()),
      });
    }
  }

  await Promise.all([
    insertRows("traces", traceRows),
    insertRows("observations", obsRows),
  ]);
  if (traceRows.length || obsRows.length) {
    console.log(
      `[trace-workers] wrote ${traceRows.length} traces, ${obsRows.length} observations`,
    );
  }
}
