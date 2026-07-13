import { randomUUID } from "node:crypto";
import {
  insertRows,
  redis,
  toChDateTime,
  type Finding,
  type StreamEvent,
  type ObservationInput,
} from "@argus/shared";
import { scanObservation, scanTrace } from "./detectionClient.js";
import { maybeAlert } from "./alert.js";

const BUF_TTL_SECONDS = 3600;

function bufKey(projectId: string, traceId: string): string {
  return `argus:tracebuf:${projectId}:${traceId}`;
}

function findingToRow(projectId: string, f: Finding): Record<string, unknown> {
  return {
    project_id: projectId,
    event_id: randomUUID(),
    trace_id: f.trace_id,
    observation_id: f.observation_id ?? "",
    detected_at: toChDateTime(new Date().toISOString()),
    category: f.category,
    severity: f.severity,
    outcome: f.outcome,
    score: f.score,
    l1_rules: f.l1_rules ?? [],
    l2_scores: f.l2_scores ?? {},
    l3_verdict: f.l3_verdict ?? "",
    l4_signals: f.l4_signals ?? [],
    evidence_excerpt: f.evidence_excerpt ?? "",
    content_sha256: "",
    incident_id: "",
    analyst_verdict: "unreviewed",
    event_ts: toChDateTime(new Date().toISOString()),
  };
}

async function persistAndAlert(projectId: string, findings: Finding[]) {
  if (findings.length === 0) return;
  const rows = findings.map((f) => findingToRow(projectId, f));
  await insertRows("security_events", rows);
  for (const f of findings) await maybeAlert(projectId, f);
  console.log(
    `[security-workers] raised ${findings.length} event(s): ` +
      findings.map((f) => `${f.severity}/${f.category}`).join(", "),
  );
}

/**
 * Security worker: span-level scan on each observation, plus L4 trace analysis
 * when a trace's summary event arrives (our "trace complete" signal). Between
 * the two, observations are buffered per-trace in Redis so L4 sees the whole
 * graph without depending on arrival order within a batch.
 */
export async function handleSecurityBatch(events: StreamEvent[]) {
  const r = redis();

  for (const ev of events) {
    if (ev.kind === "observation") {
      const o = ev.payload as ObservationInput;
      // buffer for later L4
      await r.rpush(bufKey(ev.projectId, o.traceId), JSON.stringify(o));
      await r.expire(bufKey(ev.projectId, o.traceId), BUF_TTL_SECONDS);
      // span-level scan now
      try {
        const findings = await scanObservation(ev.projectId, o);
        await persistAndAlert(ev.projectId, findings);
      } catch (err) {
        console.error("[security-workers] span scan failed:", err);
        throw err; // let consumer retry the batch
      }
    } else {
      // trace summary => run L4 over the buffered observations
      const traceId = (ev.payload as { traceId: string }).traceId;
      const key = bufKey(ev.projectId, traceId);
      const raw = await r.lrange(key, 0, -1);
      if (raw.length === 0) continue;
      const observations = raw
        .map((s) => {
          try {
            return JSON.parse(s) as ObservationInput;
          } catch {
            return null;
          }
        })
        .filter((x): x is ObservationInput => x !== null);
      try {
        const findings = await scanTrace(ev.projectId, traceId, observations);
        await persistAndAlert(ev.projectId, findings);
      } catch (err) {
        console.error("[security-workers] trace scan failed:", err);
        throw err;
      }
    }
  }
}
