import { config, routeAlert, SEVERITY_ORDER, type Finding } from "@argus/shared";

/**
 * Alert dispatch.
 *
 * The routing itself (channels, suppression, dedup, retries, delivery health)
 * lives in @argus/shared so the gateway can reuse it. This is the worker's
 * entry point into it, plus the legacy single-webhook path.
 */

/** The pre-channels behaviour: one global webhook from the environment. Kept so
 *  an existing deployment doesn't go silent on upgrade — it keeps firing until
 *  the customer configures channels of their own. */
async function legacyWebhook(projectId: string, finding: Finding): Promise<void> {
  if (!config.alertWebhookUrl) {
    console.log(
      `[alert] ${finding.severity.toUpperCase()} ${finding.category} ` +
        `trace=${finding.trace_id} score=${finding.score} (no channels configured)`,
    );
    return;
  }
  try {
    await fetch(config.alertWebhookUrl, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
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
      }),
      signal: AbortSignal.timeout(5000),
    });
  } catch (err) {
    console.error("[alert] legacy webhook failed:", err);
  }
}

export async function maybeAlert(
  projectId: string,
  finding: Finding,
  // Per-project threshold from the app's Settings; falls back to the global env
  // default when a caller doesn't supply one.
  minSeverity: string = config.alertMinSeverity,
  contentHash = "",
): Promise<void> {
  if (SEVERITY_ORDER[finding.severity] < (SEVERITY_ORDER[minSeverity] ?? SEVERITY_ORDER[config.alertMinSeverity])) {
    return;
  }

  try {
    const r = await routeAlert(projectId, finding, contentHash, minSeverity);

    if (r.suppressed) {
      console.log(`[alert] suppressed ${finding.severity}/${finding.category} by rule ${r.suppressed}`);
      return;
    }
    if (r.deduped) {
      console.log(`[alert] deduped ${finding.severity}/${finding.category} (already sent recently)`);
      return;
    }
    if (r.noChannels) {
      // No channel of their own — fall back so the deployment isn't silent.
      await legacyWebhook(projectId, finding);
      return;
    }

    const failed = r.sent.filter((s) => !s.ok);
    console.log(
      `[alert] ${finding.severity.toUpperCase()} ${finding.category} → ` +
        `${r.sent.length - failed.length}/${r.sent.length} channel(s)` +
        (failed.length ? `, failures: ${failed.map((f) => f.error).join("; ")}` : ""),
    );
  } catch (err) {
    // Routing must never take down the worker that raised the finding — the
    // security_event row is already persisted and is the record of truth.
    console.error("[alert] routing failed:", err);
  }
}
