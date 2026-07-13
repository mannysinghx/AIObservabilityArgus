import { config, SEVERITY_ORDER, type Finding } from "@argus/shared";

/**
 * Alert router (Phase 1: webhook only). Every alert carries the trace link and
 * detection provenance so an analyst goes from alert to evidence in one hop
 * (docs/02 §Alert router). Dedup/suppression/Slack/PagerDuty land in Phase 2.
 */
export async function maybeAlert(projectId: string, finding: Finding) {
  if (SEVERITY_ORDER[finding.severity] < SEVERITY_ORDER[config.alertMinSeverity]) {
    return;
  }
  const payload = {
    source: "argus",
    projectId,
    severity: finding.severity,
    category: finding.category,
    outcome: finding.outcome,
    score: finding.score,
    traceId: finding.trace_id,
    observationId: finding.observation_id,
    signals: [...finding.l1_rules, ...finding.l4_signals],
    evidence: finding.evidence_excerpt,
    traceUrl: `http://localhost:3000/projects/${projectId}/traces/${finding.trace_id}`,
  };

  if (!config.alertWebhookUrl) {
    console.log(
      `[alert] ${finding.severity.toUpperCase()} ${finding.category} ` +
        `trace=${finding.trace_id} score=${finding.score} (no webhook configured)`,
    );
    return;
  }
  try {
    await fetch(config.alertWebhookUrl, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(payload),
    });
  } catch (err) {
    console.error("[alert] webhook failed:", err);
  }
}
