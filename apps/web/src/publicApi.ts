/**
 * Public read API (v1).
 *
 * The dashboard's own /api/* endpoints are shaped for the screens that consume
 * them: no pagination, capped at 100 rows, sorted for a table, authenticated by
 * a session cookie. None of that is usable by someone building against Argus.
 * This is the surface a customer's SOC dashboard, Grafana panel, SIEM connector
 * or nightly export talks to — API-key authenticated, cursor-paginated, and
 * stable enough to promise.
 *
 * Every query here uses ClickHouse query_params rather than string
 * interpolation. The dashboard queries build SQL by concatenation and are safe
 * because their inputs are sanitized identifiers, but that safety is a property
 * of the callers, and this surface takes arbitrary filter values from anyone
 * holding a read key. Parameters make it a property of the code.
 */
import { ch } from "@argus/shared";
import { safeProjectId } from "./ids.js";

const MAX_LIMIT = 1000;
const DEFAULT_LIMIT = 100;

export interface Page<T> {
  data: T[];
  /** Opaque cursor for the next page; null when the last page was returned. */
  nextCursor: string | null;
  hasMore: boolean;
}

export interface ListOptions {
  limit?: number;
  cursor?: string;
  since?: string;
  until?: string;
}

function clampLimit(n: unknown): number {
  const v = Number(n);
  if (!Number.isFinite(v) || v <= 0) return DEFAULT_LIMIT;
  return Math.min(MAX_LIMIT, Math.floor(v));
}

/**
 * Cursors are keyset, not offset.
 *
 * OFFSET pagination over a table that is being written to skips and repeats
 * rows: a new trace arriving between page 1 and page 2 shifts everything down,
 * so the reader silently misses one. For a security export, "silently missed
 * one" is the failure that matters. The cursor encodes the last row's sort key
 * (timestamp + id), so the next page continues from a fixed point regardless of
 * what has been inserted since.
 */
function encodeCursor(ts: string, id: string): string {
  return Buffer.from(`${ts}|${id}`, "utf8").toString("base64url");
}

function decodeCursor(cursor: string | undefined): { ts: string; id: string } | null {
  if (!cursor) return null;
  try {
    const [ts, id] = Buffer.from(cursor, "base64url").toString("utf8").split("|");
    if (!ts || id === undefined) return null;
    // The cursor is opaque to callers but still arrives from the network, so it
    // is validated rather than trusted: only ever used as a query parameter,
    // and shaped like the values we emit.
    if (!/^[\d\-: .]+$/.test(ts)) return null;
    return { ts, id };
  } catch {
    return null;
  }
}

/** Time-window clause shared by every list endpoint. */
function windowClause(opts: ListOptions, col: string): { sql: string; params: Record<string, unknown> } {
  const params: Record<string, unknown> = {};
  let sql = "";
  if (opts.since) { sql += ` AND ${col} >= {since:DateTime64(3)}`; params.since = opts.since; }
  if (opts.until) { sql += ` AND ${col} < {until:DateTime64(3)}`; params.until = opts.until; }
  return { sql, params };
}

async function query<T>(sql: string, params: Record<string, unknown>): Promise<T[]> {
  const rs = await ch().query({
    query: sql,
    query_params: params,
    format: "JSONEachRow",
    // Every list here selects `toString(<time column>) AS <same name>` so the
    // JSON carries a readable string. That alias then shadows the real column
    // for the WHERE clause, and a keyset cursor comparing a DateTime64 against
    // it fails with "No operation less between String and DateTime64(3)".
    // Preferring the column keeps the alias for output and the column for
    // comparison, which is what both need. (analytics() hit this same trap.)
    clickhouse_settings: { prefer_column_name_to_alias: 1 },
  });
  return rs.json<T>();
}

/**
 * Run a keyset-paginated list. Asks for one row more than requested: if it comes
 * back, there is another page, and we know that without a second COUNT query
 * over a table that could be billions of rows.
 */
async function paginate<T extends Record<string, unknown>>(
  buildSql: (extra: string) => string,
  params: Record<string, unknown>,
  opts: ListOptions,
  tsField: string,
  idField: string,
): Promise<Page<T>> {
  const limit = clampLimit(opts.limit);
  const cur = decodeCursor(opts.cursor);
  const p: Record<string, unknown> = { ...params, limit: limit + 1 };
  let extra = "";
  if (cur) {
    // Strictly "older than the cursor", with the id as a tiebreak so rows
    // sharing a timestamp are neither skipped nor repeated.
    extra = ` AND (${tsField} < {curTs:DateTime64(3)} OR (${tsField} = {curTs:DateTime64(3)} AND ${idField} < {curId:String}))`;
    p.curTs = cur.ts;
    p.curId = cur.id;
  }
  const rows = await query<T>(buildSql(extra), p);
  const hasMore = rows.length > limit;
  const data = hasMore ? rows.slice(0, limit) : rows;
  const last = data[data.length - 1];
  return {
    data,
    hasMore,
    nextCursor: hasMore && last ? encodeCursor(String(last[tsField]), String(last[idField])) : null,
  };
}

// ---------------------------------------------------------------- traces

export async function listTraces(projectId: string, opts: ListOptions = {}) {
  const pid = safeProjectId(projectId);
  if (!pid) return { data: [], nextCursor: null, hasMore: false };
  const w = windowClause(opts, "timestamp");
  return paginate(
    (extra) => `
      SELECT trace_id, name, environment, release, toString(timestamp) AS timestamp,
             session_id, user_id, tags, metadata
      FROM traces FINAL
      WHERE project_id = {pid:String} ${w.sql} ${extra}
      ORDER BY timestamp DESC, trace_id DESC
      LIMIT {limit:UInt32}`,
    { pid, ...w.params },
    opts,
    "timestamp",
    "trace_id",
  );
}

export async function getTrace(projectId: string, traceId: string) {
  const pid = safeProjectId(projectId);
  if (!pid) return null;
  const params = { pid, tid: traceId };
  const [trace] = await query<Record<string, unknown>>(
    `SELECT trace_id, name, environment, release, toString(timestamp) AS timestamp,
            session_id, user_id, tags, metadata
     FROM traces FINAL WHERE project_id = {pid:String} AND trace_id = {tid:String} LIMIT 1`,
    params,
  );
  if (!trace) return null;
  const observations = await query<Record<string, unknown>>(
    `SELECT observation_id, parent_id, type, name, toString(start_time) AS start_time,
            toString(end_time) AS end_time, model, provider, input_tokens, output_tokens,
            toFloat64(cost_usd) AS cost_usd, finish_reason, taint, taint_source,
            input_full AS input, output_full AS output, attributes
     FROM observations FINAL
     WHERE project_id = {pid:String} AND trace_id = {tid:String}
     ORDER BY start_time`,
    params,
  );
  const securityEvents = await query<Record<string, unknown>>(
    `SELECT event_id, observation_id, toString(detected_at) AS detected_at, category,
            severity, outcome, score, l1_rules, l2_scores, l3_verdict, l4_signals,
            evidence_excerpt, content_sha256, analyst_verdict
     FROM security_events FINAL
     WHERE project_id = {pid:String} AND trace_id = {tid:String}
     ORDER BY score DESC`,
    params,
  );
  return { trace, observations, securityEvents };
}

// ---------------------------------------------------------------- observations

export async function listObservations(
  projectId: string,
  opts: ListOptions & { traceId?: string; type?: string } = {},
) {
  const pid = safeProjectId(projectId);
  if (!pid) return { data: [], nextCursor: null, hasMore: false };
  const w = windowClause(opts, "start_time");
  const params: Record<string, unknown> = { pid, ...w.params };
  let filters = "";
  if (opts.traceId) { filters += " AND trace_id = {tid:String}"; params.tid = opts.traceId; }
  if (opts.type) { filters += " AND type = {otype:String}"; params.otype = opts.type; }
  return paginate(
    (extra) => `
      SELECT observation_id, trace_id, parent_id, type, name,
             toString(start_time) AS start_time, toString(end_time) AS end_time,
             model, provider, input_tokens, output_tokens,
             toFloat64(cost_usd) AS cost_usd, finish_reason, taint, content_sha256
      FROM observations FINAL
      WHERE project_id = {pid:String} ${w.sql} ${filters} ${extra}
      ORDER BY start_time DESC, observation_id DESC
      LIMIT {limit:UInt32}`,
    params,
    opts,
    "start_time",
    "observation_id",
  );
}

// ---------------------------------------------------------------- security events

export async function listSecurityEvents(
  projectId: string,
  opts: ListOptions & { severity?: string; category?: string; verdict?: string; outcome?: string } = {},
) {
  const pid = safeProjectId(projectId);
  if (!pid) return { data: [], nextCursor: null, hasMore: false };
  const w = windowClause(opts, "detected_at");
  const params: Record<string, unknown> = { pid, ...w.params };
  let filters = "";
  // Enum columns: an unknown value makes ClickHouse throw rather than return
  // nothing, so each is validated against the schema's own set first. A typo in
  // a filter should be an empty page or a 400, never a 500.
  if (opts.severity && SEVERITIES.has(opts.severity)) { filters += " AND severity = {sev:String}"; params.sev = opts.severity; }
  if (opts.category && CATEGORIES.has(opts.category)) { filters += " AND category = {cat:String}"; params.cat = opts.category; }
  if (opts.outcome && OUTCOMES.has(opts.outcome)) { filters += " AND outcome = {out:String}"; params.out = opts.outcome; }
  if (opts.verdict && VERDICTS.has(opts.verdict)) { filters += " AND analyst_verdict = {vd:String}"; params.vd = opts.verdict; }
  return paginate(
    (extra) => `
      SELECT event_id, trace_id, observation_id, toString(detected_at) AS detected_at,
             category, severity, outcome, score, l1_rules, l2_scores, l3_verdict,
             l4_signals, evidence_excerpt, content_sha256, analyst_verdict
      FROM security_events FINAL
      WHERE project_id = {pid:String} ${w.sql} ${filters} ${extra}
      ORDER BY detected_at DESC, event_id DESC
      LIMIT {limit:UInt32}`,
    params,
    opts,
    "detected_at",
    "event_id",
  );
}

export const SEVERITIES = new Set(["info", "low", "medium", "high", "critical"]);
export const OUTCOMES = new Set(["unknown", "attempted", "succeeded", "blocked"]);
export const VERDICTS = new Set(["unreviewed", "confirmed", "false_positive"]);
export const CATEGORIES = new Set([
  "direct_injection", "jailbreak", "indirect_injection", "exfiltration",
  "excessive_agency", "rag_poisoning", "prompt_leak", "pii_egress",
  "canary_triggered", "obfuscation",
]);

/** Which filter values a caller passed that we refused to honour. Returned as a
 *  400 rather than silently ignored — a monitoring query filtered on a typo'd
 *  severity would otherwise report "no critical events" forever. */
export function invalidFilters(opts: {
  severity?: string; category?: string; outcome?: string; verdict?: string;
}): string[] {
  const bad: string[] = [];
  if (opts.severity && !SEVERITIES.has(opts.severity)) bad.push(`severity=${opts.severity}`);
  if (opts.category && !CATEGORIES.has(opts.category)) bad.push(`category=${opts.category}`);
  if (opts.outcome && !OUTCOMES.has(opts.outcome)) bad.push(`outcome=${opts.outcome}`);
  if (opts.verdict && !VERDICTS.has(opts.verdict)) bad.push(`verdict=${opts.verdict}`);
  return bad;
}

// ---------------------------------------------------------------- summary

/** Aggregate counters for a window — the cheap endpoint a status board polls. */
export async function summary(projectId: string, opts: ListOptions = {}) {
  const pid = safeProjectId(projectId);
  if (!pid) return null;
  const ws = windowClause(opts, "detected_at");
  const wo = windowClause(opts, "start_time");
  const wt = windowClause(opts, "timestamp");

  const [sec] = await query<Record<string, unknown>>(
    `SELECT count() AS total,
            countIf(severity = 'critical') AS critical,
            countIf(severity = 'high') AS high,
            countIf(outcome = 'succeeded') AS succeeded,
            countIf(analyst_verdict = 'unreviewed') AS unreviewed
     FROM security_events FINAL WHERE project_id = {pid:String} ${ws.sql}`,
    { pid, ...ws.params },
  );
  const [obs] = await query<Record<string, unknown>>(
    `SELECT count() AS observations, sum(input_tokens + output_tokens) AS tokens,
            toFloat64(sum(cost_usd)) AS cost_usd
     FROM observations FINAL WHERE project_id = {pid:String} ${wo.sql}`,
    { pid, ...wo.params },
  );
  const [tr] = await query<Record<string, unknown>>(
    `SELECT count() AS traces, uniqExact(session_id) AS sessions, uniqExact(user_id) AS users
     FROM traces FINAL WHERE project_id = {pid:String} ${wt.sql}`,
    { pid, ...wt.params },
  );
  return { security: sec, usage: obs, traffic: tr };
}
