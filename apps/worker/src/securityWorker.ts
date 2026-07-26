import { randomUUID } from "node:crypto";
import {
  contentSha256,
  insertRows,
  redis,
  toChDateTime,
  loadProjectConfig,
  type Finding,
  type StreamEvent,
  type ObservationInput,
} from "@argus/shared";
import { scanObservation, scanTrace } from "./detectionClient.js";
import { maybeAlert } from "./alert.js";

const BUF_TTL_SECONDS = 3600;
/** Hard cap on spans buffered per trace for L4 — see the ltrim below. */
const MAX_BUFFERED_SPANS = Number(process.env.MAX_BUFFERED_SPANS ?? 500);

function bufKey(projectId: string, traceId: string): string {
  return `argus:tracebuf:${projectId}:${traceId}`;
}

/** observation_id -> content fingerprint, for the observations a scan covered. */
function hashIndex(observations: ObservationInput[]): Map<string, string> {
  return new Map(observations.map((o) => [o.observationId, contentSha256(o)]));
}

function findingToRow(
  projectId: string,
  f: Finding,
  hashes: Map<string, string>,
): Record<string, unknown> {
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
    // The fingerprint of the content this finding was raised on. This is what
    // makes "the same poisoned document has now hit N traces" possible — the
    // Incidents view groups events by it. It used to be hardcoded to "", and
    // the query filters `content_sha256 != ''`, so that panel could never
    // return a row no matter how many times a source was reused.
    content_sha256: hashes.get(f.observation_id ?? "") ?? "",
    incident_id: "",
    analyst_verdict: "unreviewed",
    event_ts: toChDateTime(new Date().toISOString()),
  };
}

async function persistAndAlert(
  projectId: string,
  findings: Finding[],
  minSeverity: string,
  hashes: Map<string, string>,
) {
  if (findings.length === 0) return;
  const rows = findings.map((f) => findingToRow(projectId, f, hashes));
  await insertRows("security_events", rows);
  for (const f of findings) await maybeAlert(projectId, f, minSeverity);
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
    // Per-application config: which layers run, and the alert threshold. Cached
    // (~30s) and fails open to defaults, so a config read never stalls scanning.
    const cfg = await loadProjectConfig(ev.projectId);
    const minSeverity = cfg.alerting.min_severity;

    if (ev.kind === "observation") {
      const o = ev.payload as ObservationInput;
      // Buffer for later L4. Capped: L4 compares every span against every other
      // span (O(n²)), and this buffer is attacker-influenced in size — one
      // client looping tool calls under a single traceId would otherwise grow
      // it without bound and turn the detection service into a CPU sink. We
      // keep the FIRST spans rather than the last, because the taint frontier
      // (the untrusted span everything downstream is judged against) is near
      // the start of a trace; dropping the head would blind L4 entirely.
      const key = bufKey(ev.projectId, o.traceId);
      const buffered = await r.rpush(key, JSON.stringify(o));
      await r.expire(key, BUF_TTL_SECONDS);
      if (buffered > MAX_BUFFERED_SPANS) await r.ltrim(key, 0, MAX_BUFFERED_SPANS - 1);
      // span-level scan now (L1 always; L2 only if the project enabled classifiers)
      try {
        const findings = await scanObservation(ev.projectId, o, cfg.layers.classifiers.enabled);
        await persistAndAlert(ev.projectId, findings, minSeverity, hashIndex([o]));
      } catch (err) {
        console.error("[security-workers] span scan failed:", err);
        throw err; // let consumer retry the batch
      }
    } else {
      // trace summary => run L4 over the buffered observations, unless the
      // project turned trace analysis off.
      const traceId = (ev.payload as { traceId: string }).traceId;
      const key = bufKey(ev.projectId, traceId);
      if (!cfg.layers.trace_analysis.enabled) {
        await r.del(key); // don't leak the buffer we won't consume
        continue;
      }
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
        await persistAndAlert(ev.projectId, findings, minSeverity, hashIndex(observations));
      } catch (err) {
        console.error("[security-workers] trace scan failed:", err);
        throw err;
      }
    }
  }
}
