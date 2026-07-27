/**
 * Alert channel and suppression management.
 *
 * Channel targets are credentials, not addresses. A Slack incoming-webhook URL
 * lets anyone holding it post as your app; a PagerDuty routing key lets anyone
 * holding it page your on-call. So they go in write-only: the API accepts them
 * and never returns them, and the UI shows a redacted form. Treating them as
 * mere configuration is how they end up in a screenshot in a support ticket.
 */
import { randomBytes } from "node:crypto";
import { invalidateAlertCache, type ChannelKind } from "@argus/shared";
import { pool } from "./db.js";
import { safeProjectId } from "./ids.js";

const KINDS: ChannelKind[] = ["webhook", "slack", "pagerduty", "email"];
const SEVERITIES = ["info", "low", "medium", "high", "critical"];

export interface ChannelView {
  id: string;
  kind: ChannelKind;
  label: string;
  /** Redacted — enough to recognise which endpoint this is, not enough to use. */
  targetHint: string;
  minSeverity: string;
  enabled: boolean;
  signed: boolean;
  lastSuccessAt: string | null;
  lastErrorAt: string | null;
  lastError: string | null;
  consecutiveFailures: number;
}

/**
 * Show enough to tell two channels apart, never enough to replay one.
 * For URLs that means scheme+host and the last few characters of the path —
 * a Slack webhook's secret is entirely in the path, so the path cannot be shown.
 */
function redact(kind: string, target: string): string {
  if (kind === "pagerduty") return `routing key ••••${target.slice(-4)}`;
  if (kind === "email") return target;
  try {
    const u = new URL(target);
    return `${u.protocol}//${u.host}/…${target.slice(-4)}`;
  } catch {
    return `••••${target.slice(-4)}`;
  }
}

const iso = (d: Date | null) => (d ? (d instanceof Date ? d.toISOString() : String(d)) : null);

export async function listChannels(projectId: string): Promise<ChannelView[]> {
  const safe = safeProjectId(projectId);
  if (!safe) return [];
  const { rows } = await pool.query<{
    id: string; kind: string; label: string; target: string; signing_secret: string | null;
    min_severity: string; enabled: boolean; last_success_at: Date | null;
    last_error_at: Date | null; last_error: string | null; consecutive_failures: number;
  }>(
    `SELECT id, kind, label, target, signing_secret, min_severity, enabled,
            last_success_at, last_error_at, last_error, consecutive_failures
     FROM alert_channels WHERE project_id = $1 ORDER BY created_at`,
    [safe],
  );
  return rows.map((r) => ({
    id: r.id,
    kind: r.kind as ChannelKind,
    label: r.label,
    targetHint: redact(r.kind, r.target),
    minSeverity: r.min_severity,
    enabled: r.enabled,
    signed: !!r.signing_secret,
    lastSuccessAt: iso(r.last_success_at),
    lastErrorAt: iso(r.last_error_at),
    lastError: r.last_error,
    consecutiveFailures: Number(r.consecutive_failures ?? 0),
  }));
}

export interface NewChannel {
  id: string;
  /** Returned once, for webhooks: the receiver needs it to verify signatures. */
  signingSecret?: string;
}

export async function createChannel(
  projectId: string,
  input: { kind?: string; label?: string; target?: string; minSeverity?: string; sign?: boolean },
  createdBy: string,
): Promise<NewChannel | { error: string }> {
  const safe = safeProjectId(projectId);
  if (!safe) return { error: "Unknown application." };

  const kind = String(input.kind || "") as ChannelKind;
  if (!KINDS.includes(kind)) return { error: "Pick a channel type." };

  const target = String(input.target || "").trim();
  if (!target) return { error: "Enter the destination for this channel." };

  if (kind === "webhook" || kind === "slack") {
    let u: URL;
    try { u = new URL(target); } catch { return { error: "That doesn't look like a URL." }; }
    // Refuse plaintext: the payload names the attack, the evidence excerpt and
    // the trace, and this is a security product.
    if (u.protocol !== "https:") return { error: "Use an https:// URL — alerts carry attack evidence." };
    if (kind === "slack" && !u.host.endsWith("slack.com")) {
      return { error: "That isn't a Slack webhook URL (expected hooks.slack.com)." };
    }
  }
  if (kind === "email" && !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(target)) {
    return { error: "Enter a valid email address." };
  }

  const minSeverity = SEVERITIES.includes(String(input.minSeverity)) ? String(input.minSeverity) : "high";
  // Signing only makes sense for a generic webhook — Slack and PagerDuty verify
  // by URL/key and reject unknown headers' semantics anyway.
  const signingSecret = kind === "webhook" && input.sign !== false ? randomBytes(24).toString("base64url") : null;

  const { rows } = await pool.query<{ id: string }>(
    `INSERT INTO alert_channels (project_id, kind, label, target, signing_secret, min_severity, created_by)
     VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`,
    [safe, kind, String(input.label || "").trim().slice(0, 120), target, signingSecret, minSeverity, createdBy || null],
  );
  invalidateAlertCache(safe);
  return signingSecret ? { id: rows[0].id, signingSecret } : { id: rows[0].id };
}

export async function deleteChannel(projectId: string, id: string): Promise<{ ok: true } | { error: string }> {
  const safe = safeProjectId(projectId);
  if (!safe) return { error: "Unknown application." };
  const r = await pool.query("DELETE FROM alert_channels WHERE id = $1 AND project_id = $2", [id, safe]);
  if (!r.rowCount) return { error: "Channel not found." };
  invalidateAlertCache(safe);
  return { ok: true };
}

/**
 * Send a synthetic alert through one channel.
 *
 * The single most useful thing a channel screen can offer. Otherwise the first
 * time anyone finds out the URL was wrong is during the incident it was
 * supposed to report.
 */
export async function testChannel(projectId: string, id: string): Promise<{ ok: boolean; error?: string }> {
  const safe = safeProjectId(projectId);
  if (!safe) return { ok: false, error: "Unknown application." };
  const { rows } = await pool.query<{
    id: string; kind: string; label: string; target: string; signing_secret: string | null; min_severity: string;
  }>(
    `SELECT id, kind, label, target, signing_secret, min_severity
     FROM alert_channels WHERE id = $1 AND project_id = $2`,
    [id, safe],
  );
  if (!rows.length) return { ok: false, error: "Channel not found." };

  const { deliverTest } = await import("@argus/shared");
  const r = await deliverTest({
    id: rows[0].id,
    kind: rows[0].kind as ChannelKind,
    label: rows[0].label,
    target: rows[0].target,
    signingSecret: rows[0].signing_secret,
    minSeverity: rows[0].min_severity,
  }, projectId);
  return r.ok ? { ok: true } : { ok: false, error: r.error ?? `HTTP ${r.status}` };
}

// ---------------------------------------------------------------- suppression

export interface SuppressionView {
  id: string;
  ruleId: string | null;
  category: string | null;
  scopeType: string;
  scopeValue: string;
  reason: string | null;
  createdBy: string | null;
  createdAt: string;
  expiresAt: string | null;
}

export async function listSuppressions(projectId: string): Promise<SuppressionView[]> {
  const safe = safeProjectId(projectId);
  if (!safe) return [];
  const { rows } = await pool.query<{
    id: string; rule_id: string | null; category: string | null; scope_type: string;
    scope_value: string; reason: string | null; created_by: string | null;
    created_at: Date; expires_at: Date | null;
  }>(
    `SELECT id, rule_id, category, scope_type, scope_value, reason, created_by, created_at, expires_at
     FROM suppression_rules WHERE project_id = $1 AND enabled ORDER BY created_at DESC`,
    [safe],
  );
  return rows.map((r) => ({
    id: r.id, ruleId: r.rule_id, category: r.category, scopeType: r.scope_type,
    scopeValue: r.scope_value, reason: r.reason, createdBy: r.created_by,
    createdAt: iso(r.created_at)!, expiresAt: iso(r.expires_at),
  }));
}

export async function createSuppression(
  projectId: string,
  input: { ruleId?: string; category?: string; scopeType?: string; scopeValue?: string; reason?: string; expiresInDays?: number },
  createdBy: string,
): Promise<{ id: string } | { error: string }> {
  const safe = safeProjectId(projectId);
  if (!safe) return { error: "Unknown application." };
  const ruleId = String(input.ruleId || "").trim() || null;
  const category = String(input.category || "").trim() || null;
  const scopeType = String(input.scopeType || "rule").trim();
  const scopeValue = String(input.scopeValue || "").trim();
  if (!ruleId && !category && !scopeValue) {
    return { error: "A suppression must name a rule, a category, or a tool — otherwise it silences everything." };
  }
  // A reason is mandatory. Six months on, an unexplained suppression is
  // indistinguishable from a mistake, and nobody dares remove it.
  const reason = String(input.reason || "").trim();
  if (!reason) return { error: "Say why this is being suppressed — future you will need to know." };

  const days = Number(input.expiresInDays);
  const expires = Number.isFinite(days) && days > 0 ? `now() + interval '${Math.floor(days)} days'` : "NULL";

  const { rows } = await pool.query<{ id: string }>(
    `INSERT INTO suppression_rules (project_id, rule_id, category, scope_type, scope_value, reason, created_by, expires_at)
     VALUES ($1, $2, $3, $4, $5, $6, $7, ${expires}) RETURNING id`,
    [safe, ruleId, category, scopeType, scopeValue, reason.slice(0, 500), createdBy || null],
  );
  invalidateAlertCache(safe);
  return { id: rows[0].id };
}

export async function deleteSuppression(projectId: string, id: string): Promise<{ ok: true } | { error: string }> {
  const safe = safeProjectId(projectId);
  if (!safe) return { error: "Unknown application." };
  const r = await pool.query("DELETE FROM suppression_rules WHERE id = $1 AND project_id = $2", [id, safe]);
  if (!r.rowCount) return { error: "Rule not found." };
  invalidateAlertCache(safe);
  return { ok: true };
}
