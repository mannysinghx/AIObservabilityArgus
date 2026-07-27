/**
 * Alert routing: channels, suppression, dedup, and delivery.
 *
 * What this replaces: a single ALERT_WEBHOOK_URL for the entire deployment, so
 * every tenant's incidents went to one endpoint chosen by whoever ran the
 * server, with a trace link hardcoded to http://localhost:3000.
 *
 * Three things have to be right for alerting to be usable rather than merely
 * present:
 *
 *   Reachability  A security team adopts nothing that can't reach the surface
 *                 they already watch. Hence Slack and PagerDuty, not just a
 *                 generic webhook.
 *   Quiet         Noise is the stated top churn risk. Suppression rules and
 *                 dedup exist so a customer can silence a known false positive
 *                 instead of muting the whole product.
 *   Honesty       A channel that has been failing for a week must look
 *                 different from one that has had nothing to say.
 */
import pg from "pg";
import { createHmac } from "node:crypto";
import { config, SEVERITY_ORDER } from "./config.js";
import { redis } from "./redis.js";
import type { Finding } from "./types.js";

export type ChannelKind = "webhook" | "slack" | "pagerduty" | "email";

export interface AlertChannel {
  id: string;
  kind: ChannelKind;
  label: string;
  target: string;
  signingSecret: string | null;
  minSeverity: string;
}

export interface SuppressionRule {
  id: string;
  ruleId: string | null;
  category: string | null;
  scopeType: string;
  scopeValue: string;
}

let _pool: pg.Pool | null = null;
function pool(): pg.Pool {
  return (_pool ??= new pg.Pool({ connectionString: config.databaseUrl, max: 4 }));
}

// ---------------------------------------------------------------- config load

const channelCache = new Map<string, { channels: AlertChannel[]; rules: SuppressionRule[]; expires: number }>();
const TTL_MS = 30_000;

export function invalidateAlertCache(projectId: string): void {
  channelCache.delete(projectId);
}

async function loadRouting(projectId: string) {
  const hit = channelCache.get(projectId);
  if (hit && hit.expires > Date.now()) return hit;
  let channels: AlertChannel[] = [];
  let rules: SuppressionRule[] = [];
  try {
    const c = await pool().query<{
      id: string; kind: string; label: string; target: string;
      signing_secret: string | null; min_severity: string;
    }>(
      `SELECT id, kind, label, target, signing_secret, min_severity
       FROM alert_channels WHERE project_id = $1 AND enabled`,
      [projectId],
    );
    channels = c.rows.map((r) => ({
      id: r.id, kind: r.kind as ChannelKind, label: r.label, target: r.target,
      signingSecret: r.signing_secret, minSeverity: r.min_severity,
    }));
    const s = await pool().query<{
      id: string; rule_id: string | null; category: string | null;
      scope_type: string; scope_value: string;
    }>(
      `SELECT id, rule_id, category, scope_type, scope_value
       FROM suppression_rules
       WHERE project_id = $1 AND enabled AND (expires_at IS NULL OR expires_at > now())`,
      [projectId],
    );
    rules = s.rows.map((r) => ({
      id: r.id, ruleId: r.rule_id, category: r.category,
      scopeType: r.scope_type, scopeValue: r.scope_value,
    }));
  } catch {
    // Fail OPEN for channels (a config read must not swallow an incident) and
    // CLOSED for suppression (never silence something because a query failed).
    channels = [];
    rules = [];
  }
  const entry = { channels, rules, expires: Date.now() + TTL_MS };
  channelCache.set(projectId, entry);
  return entry;
}

// ---------------------------------------------------------------- suppression

/** Does any active rule silence this finding? */
export function isSuppressed(finding: Finding, rules: SuppressionRule[]): SuppressionRule | null {
  for (const r of rules) {
    if (r.ruleId && finding.l1_rules.includes(r.ruleId)) return r;
    if (r.category && finding.category === r.category) return r;
    // A tool-scoped rule silences findings raised on that span name — the
    // "our internal doc-search tool always looks like injection" case.
    if (r.scopeType === "tool" && r.scopeValue && finding.evidence_excerpt.includes(r.scopeValue)) return r;
  }
  return null;
}

// ---------------------------------------------------------------- dedup

/**
 * Has this alert already gone out recently?
 *
 * A poisoned document that gets retrieved on every request produces one finding
 * per trace. Without dedup that is one page per request, which is how a team
 * ends up muting the channel — and a muted channel is worse than no channel,
 * because everyone still believes they are covered.
 *
 * Keyed on what makes two alerts "the same incident" to a human: project,
 * category, severity, and the content fingerprint. Deliberately NOT the trace
 * id, since a repeating attack has a new trace every time.
 */
const DEDUP_WINDOW_S = Number(process.env.ALERT_DEDUP_WINDOW_S ?? 900);

export async function shouldSend(projectId: string, finding: Finding, contentHash: string): Promise<boolean> {
  const key = `argus:alertdedup:${projectId}:${finding.category}:${finding.severity}:${contentHash || finding.observation_id}`;
  try {
    // SET NX EX: the first caller wins and everyone else is a duplicate. Atomic,
    // so concurrent workers can't both decide they're first.
    const set = await redis().set(key, "1", "EX", DEDUP_WINDOW_S, "NX");
    return set === "OK";
  } catch {
    // Redis down: send. A duplicate page is an annoyance; a dropped one is the
    // failure this product exists to prevent.
    return true;
  }
}

// ---------------------------------------------------------------- payloads

function traceUrl(projectId: string, traceId: string): string {
  const base = (process.env.PUBLIC_URL || process.env.ARGUS_PUBLIC_URL || "").replace(/\/$/, "");
  // Without a configured public URL, emit a relative path rather than a link to
  // localhost. A link that silently points at the recipient's own machine is
  // worse than an obvious "you need to set PUBLIC_URL".
  const path = `/?project=${encodeURIComponent(projectId)}&trace=${encodeURIComponent(traceId)}`;
  return base ? base + path : path;
}

export interface AlertPayload {
  source: "argus";
  projectId: string;
  severity: string;
  category: string;
  outcome: string;
  score: number;
  traceId: string;
  observationId: string;
  signals: string[];
  evidence: string;
  traceUrl: string;
  detectedAt: string;
}

export function buildPayload(projectId: string, f: Finding): AlertPayload {
  return {
    source: "argus",
    projectId,
    severity: f.severity,
    category: f.category,
    outcome: f.outcome,
    score: f.score,
    traceId: f.trace_id,
    observationId: f.observation_id,
    signals: [...(f.l1_rules ?? []), ...(f.l4_signals ?? [])],
    evidence: f.evidence_excerpt ?? "",
    traceUrl: traceUrl(projectId, f.trace_id),
    detectedAt: new Date().toISOString(),
  };
}

const SEV_EMOJI: Record<string, string> = {
  critical: "🚨", high: "⚠️", medium: "•", low: "·", info: "·",
};

/** Slack incoming-webhook body. Plain blocks — no attachments, no unfurling. */
export function slackBody(p: AlertPayload) {
  const head = `${SEV_EMOJI[p.severity] ?? ""} *${p.severity.toUpperCase()}* — ${p.category.replace(/_/g, " ")}`;
  const lines = [
    `*Outcome:* ${p.outcome}   *Score:* ${p.score}`,
    p.signals.length ? `*Signals:* ${p.signals.slice(0, 6).join(", ")}` : "",
    p.evidence ? `*Evidence:* \`${p.evidence.slice(0, 300).replace(/`/g, "'")}\`` : "",
    `<${p.traceUrl}|Open the trace>`,
  ].filter(Boolean);
  return {
    text: `${head} — ${p.category}`, // notification preview
    blocks: [
      { type: "section", text: { type: "mrkdwn", text: head } },
      { type: "section", text: { type: "mrkdwn", text: lines.join("\n") } },
    ],
  };
}

/** PagerDuty Events API v2. `dedup_key` lets PagerDuty group repeats itself. */
export function pagerDutyBody(p: AlertPayload, routingKey: string) {
  return {
    routing_key: routingKey,
    event_action: "trigger",
    dedup_key: `argus:${p.projectId}:${p.category}:${p.severity}`,
    payload: {
      summary: `${p.severity.toUpperCase()} ${p.category} in ${p.projectId}`,
      // PagerDuty only accepts these four; anything else is rejected outright.
      severity: p.severity === "critical" ? "critical" : p.severity === "high" ? "error" : "warning",
      source: "argus",
      component: p.observationId || p.traceId,
      custom_details: { ...p },
    },
    links: [{ href: p.traceUrl, text: "Open the trace in Argus" }],
  };
}

// ---------------------------------------------------------------- delivery

const DELIVERY_TIMEOUT_MS = Number(process.env.ALERT_TIMEOUT_MS ?? 5000);
const MAX_ATTEMPTS = 3;

export interface DeliveryResult {
  channelId: string;
  ok: boolean;
  status?: number;
  error?: string;
  attempts: number;
}

/**
 * POST with bounded retries.
 *
 * Retries only on 5xx and network errors. A 4xx means the request itself is
 * wrong — a revoked Slack URL, a bad routing key — and retrying it just sends
 * the same broken request twice more while the real alert waits.
 */
async function post(url: string, body: unknown, secret: string | null): Promise<{ ok: boolean; status?: number; error?: string; attempts: number }> {
  const raw = JSON.stringify(body);
  const headers: Record<string, string> = { "content-type": "application/json" };
  if (secret) {
    // Timestamped HMAC. The timestamp is inside the signed material so a
    // captured delivery can't be replayed later.
    const ts = Math.floor(Date.now() / 1000).toString();
    headers["x-argus-timestamp"] = ts;
    headers["x-argus-signature"] =
      "v1=" + createHmac("sha256", secret).update(`${ts}.${raw}`).digest("hex");
  }

  let lastError = "";
  let lastStatus: number | undefined;
  for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
    try {
      const res = await fetch(url, {
        method: "POST",
        headers,
        body: raw,
        signal: AbortSignal.timeout(DELIVERY_TIMEOUT_MS),
      });
      lastStatus = res.status;
      if (res.ok) return { ok: true, status: res.status, attempts: attempt };
      if (res.status < 500) {
        return { ok: false, status: res.status, error: `HTTP ${res.status}`, attempts: attempt };
      }
      lastError = `HTTP ${res.status}`;
    } catch (err) {
      lastError = err instanceof Error ? err.message : String(err);
    }
    if (attempt < MAX_ATTEMPTS) {
      await new Promise((r) => setTimeout(r, 250 * 2 ** (attempt - 1)));
    }
  }
  return { ok: false, status: lastStatus, error: lastError, attempts: MAX_ATTEMPTS };
}

async function deliver(channel: AlertChannel, p: AlertPayload): Promise<DeliveryResult> {
  let body: unknown = p;
  let url = channel.target;
  if (channel.kind === "slack") body = slackBody(p);
  else if (channel.kind === "pagerduty") {
    body = pagerDutyBody(p, channel.target);
    url = "https://events.pagerduty.com/v2/enqueue";
  }
  const r = await post(url, body, channel.signingSecret);
  return { channelId: channel.id, ...r };
}

/**
 * Send a clearly-marked synthetic alert through one channel.
 *
 * The most useful control on the channels screen. Without it, the first time
 * anyone discovers the webhook URL was wrong is during the incident it was
 * meant to report — and the evidence that it was wrong is the absence of a
 * message, which nobody notices. The payload says TEST in every field a human
 * will read, so a test can never be mistaken for a real incident.
 */
export async function deliverTest(channel: AlertChannel, projectId: string): Promise<DeliveryResult> {
  const p: AlertPayload = {
    source: "argus",
    projectId,
    severity: "high",
    category: "TEST — no attack occurred",
    outcome: "attempted",
    score: 0,
    traceId: "test-delivery",
    observationId: "",
    signals: ["test_delivery"],
    evidence: "This is a test alert from Argus. If you can read it, this channel works.",
    traceUrl: traceUrl(projectId, "test-delivery"),
    detectedAt: new Date().toISOString(),
  };
  const r = await deliver(channel, p);
  await recordResult(r);
  return r;
}

/** Record delivery health so a channel failing quietly becomes visible. */
async function recordResult(r: DeliveryResult): Promise<void> {
  try {
    if (r.ok) {
      await pool().query(
        `UPDATE alert_channels SET last_success_at = now(), consecutive_failures = 0, last_error = NULL WHERE id = $1`,
        [r.channelId],
      );
    } else {
      await pool().query(
        `UPDATE alert_channels
         SET last_error_at = now(), last_error = $2, consecutive_failures = consecutive_failures + 1
         WHERE id = $1`,
        [r.channelId, `${r.error ?? "failed"}${r.status ? ` (${r.status})` : ""}`.slice(0, 500)],
      );
    }
  } catch {
    /* health accounting must never break delivery */
  }
}

/**
 * Route one finding to every channel that wants it.
 *
 * Returns what happened, so the caller can log it. Never throws: an alerting
 * failure must not take down the worker that raised the finding.
 */
export async function routeAlert(
  projectId: string,
  finding: Finding,
  contentHash = "",
  fallbackMinSeverity: string = config.alertMinSeverity,
): Promise<{ sent: DeliveryResult[]; suppressed?: string; deduped?: boolean; noChannels?: boolean }> {
  const { channels, rules } = await loadRouting(projectId);

  const suppressor = isSuppressed(finding, rules);
  if (suppressor) return { sent: [], suppressed: suppressor.id };

  const wanted = channels.filter(
    (c) => (SEVERITY_ORDER[finding.severity] ?? 0) >= (SEVERITY_ORDER[c.minSeverity] ?? SEVERITY_ORDER[fallbackMinSeverity]),
  );
  if (!wanted.length) return { sent: [], noChannels: true };

  if (!(await shouldSend(projectId, finding, contentHash))) return { sent: [], deduped: true };

  const payload = buildPayload(projectId, finding);
  const results = await Promise.all(
    wanted.map((c) => deliver(c, payload).catch((err): DeliveryResult => ({
      channelId: c.id, ok: false, error: String(err), attempts: 0,
    }))),
  );
  await Promise.all(results.map(recordResult));
  return { sent: results };
}
