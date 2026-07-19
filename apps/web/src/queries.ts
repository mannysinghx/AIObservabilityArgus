import { ch } from "@argus/shared";
import { safeProjectId } from "./ids.js";

/**
 * Read-side ClickHouse queries for the dashboard (database `argus`). Tables are
 * ReplacingMergeTree, so reads use FINAL to dedupe incremental inserts.
 * `range` optionally restricts to a recent window.
 */

async function q<T = Record<string, unknown>>(sql: string): Promise<T[]> {
  const rs = await ch().query({ query: sql, format: "JSONEachRow" });
  return rs.json<T>();
}

const RANGES: Record<string, string> = { "24h": "1 DAY", "7d": "7 DAY", "30d": "30 DAY" };
function since(range: string | undefined, col: string): string {
  const iv = RANGES[range || ""];
  return iv ? `AND ${col} >= now() - INTERVAL ${iv}` : "";
}

// Project scoping. Every dashboard link carries ?project=<uuid> and every query
// below narrows to just that project, so one customer never sees another's
// traces or security events.
//
// FAIL CLOSED: a missing or unusable project id yields `AND 1 = 0` (no rows),
// never an empty string. An empty string would widen the query to every tenant
// in the table — so a caller that simply forgot to thread the project through
// would silently return the whole platform's data instead of erroring. That is
// exactly how the Prompts/Evals view leaked cross-tenant eval scores. An empty
// panel is a bug report; a populated one full of someone else's data is a
// breach.
function scoped(projectId: string | undefined, col = "project_id"): string {
  const safe = safeProjectId(projectId);
  return safe ? `AND ${col} = '${safe}'` : "AND 1 = 0";
}

// ---------------- Overview ----------------
export async function overview(range?: string, projectId?: string) {
  const se = since(range, "detected_at") + scoped(projectId);
  const ts = since(range, "timestamp") + scoped(projectId);
  const os = since(range, "start_time") + scoped(projectId);

  const [sec] = await q(`
    SELECT count() AS total,
           countIf(severity='critical') AS critical,
           countIf(severity='high') AS high,
           countIf(severity='critical' AND analyst_verdict='unreviewed') AS critical_unreviewed,
           countIf(analyst_verdict='unreviewed') AS unreviewed,
           countIf(category IN ('direct_injection','indirect_injection')) AS injections,
           countIf(category='indirect_injection') AS indirect,
           countIf(category='exfiltration') AS exfiltration,
           countIf(category='canary_triggered') AS canaries,
           countIf(category='jailbreak') AS jailbreaks,
           countIf(outcome='succeeded') AS succeeded,
           countIf(outcome='blocked') AS blocked
    FROM security_events FINAL WHERE 1 ${se}`);

  const [obs] = await q(`
    SELECT count() AS observations,
           countIf(type='generation') AS generations,
           countIf(type IN ('tool','retrieval')) AS tool_spans,
           countIf(type IN ('tool','retrieval') AND taint='untrusted_external') AS untrusted,
           sum(input_tokens+output_tokens) AS tokens,
           round(sum(cost_usd),4) AS cost
    FROM observations FINAL WHERE 1 ${os}`);

  const [tr] = await q(`
    SELECT count() AS traces, uniqExact(session_id) AS sessions,
           uniqExact(user_id) AS users
    FROM traces FINAL WHERE 1 ${ts}`);

  return { sec, obs, tr };
}

// ---------------- Threat Center ----------------
export async function threat(range?: string, projectId?: string) {
  const se = since(range, "detected_at") + scoped(projectId);
  const os = since(range, "start_time") + scoped(projectId);

  const bySeverity = await q(`SELECT severity, count() AS n FROM security_events FINAL WHERE 1 ${se} GROUP BY severity ORDER BY n DESC`);
  const byCategory = await q(`SELECT category, count() AS n FROM security_events FINAL WHERE 1 ${se} GROUP BY category ORDER BY n DESC`);
  const byOutcome = await q(`SELECT outcome, count() AS n FROM security_events FINAL WHERE 1 ${se} GROUP BY outcome ORDER BY n DESC`);

  const trend = await q(`
    SELECT toStartOfHour(detected_at) AS hour,
           multiIf(category='indirect_injection','indirect',
                   category IN ('direct_injection','jailbreak'),'direct','output') AS lane,
           count() AS n
    FROM security_events FINAL WHERE 1 ${se} GROUP BY hour, lane ORDER BY hour`);

  // Escalation funnel derived from what each layer touched.
  const [funnel] = await q(`
    SELECT
      (SELECT count() FROM observations FINAL WHERE 1 ${os})                         AS spans_scanned,
      countIf(length(l1_rules) > 0)                                                  AS l1_flags,
      countIf(length(l2_scores) > 0)                                                 AS l2_escalations,
      countIf(l3_verdict != '')                                                      AS l3_judged,
      countIf(length(l4_signals) > 0)                                                AS l4_signals,
      count()                                                                        AS events
    FROM security_events FINAL WHERE 1 ${se}`);

  // Detection layer hit counts.
  const layers = [
    { layer: "L1 heuristics", scope: "100% of content", n: Number(funnel?.l1_flags || 0) },
    { layer: "L2 classifiers", scope: "untrusted + escalations", n: Number(funnel?.l2_escalations || 0) },
    { layer: "L3 judge", scope: "escalations only", n: Number(funnel?.l3_judged || 0) },
    { layer: "L4 trace analysis", scope: "on trace completion", n: Number(funnel?.l4_signals || 0) },
  ];

  // Most-targeted surfaces: join events to their source observation. Scoped by
  // project on BOTH sides — trace_id/observation_id are caller-supplied and
  // never guaranteed unique across tenants (e.g. a fixed "smoke test" ID used
  // by many onboarding clients), so joining on those alone can silently pull
  // in another project's observation for a same-named span.
  const surfaces = await q(`
    SELECT o.type AS type, o.name AS name, count() AS events
    FROM (SELECT trace_id, observation_id FROM security_events FINAL WHERE observation_id != '' ${se}) se
    INNER JOIN (SELECT trace_id, observation_id, type, name FROM observations FINAL WHERE 1 ${scoped(projectId)}) o
      ON o.trace_id = se.trace_id AND o.observation_id = se.observation_id
    GROUP BY type, name ORDER BY events DESC LIMIT 8`);

  return { bySeverity, byCategory, byOutcome, trend, funnel, layers, surfaces };
}

export async function attackFeed(range?: string, limit = 100, projectId?: string) {
  return q(`
    SELECT event_id, trace_id, observation_id, toString(detected_at) AS detected_at,
           category, severity, outcome, round(score,1) AS score,
           l1_rules, l4_signals, l2_scores, l3_verdict, evidence_excerpt,
           content_sha256, analyst_verdict
    FROM security_events FINAL WHERE 1 ${since(range, "detected_at")}${scoped(projectId)}
    ORDER BY detected_at DESC LIMIT ${Number(limit)}`);
}

// ---------------- Incidents (derived) ----------------
export async function incidents(range?: string, projectId?: string) {
  const se = since(range, "detected_at") + scoped(projectId);
  // Trace-level incidents: any trace with a high/critical event.
  const traceIncidents = await q(`
    SELECT trace_id,
           max(severity) AS max_sev,
           count() AS events,
           groupUniqArray(category) AS categories,
           min(toString(detected_at)) AS first_seen,
           max(toString(detected_at)) AS last_seen,
           maxIf(evidence_excerpt, severity IN ('critical','high')) AS evidence
    FROM security_events FINAL
    WHERE severity IN ('critical','high') ${se}
    GROUP BY trace_id ORDER BY max_sev DESC, events DESC LIMIT 50`);

  // Cross-trace poisoned-source incidents: same content hash across >1 trace.
  const poisoned = await q(`
    SELECT content_sha256,
           uniqExact(trace_id) AS traces,
           count() AS events,
           max(severity) AS max_sev,
           groupUniqArray(category) AS categories,
           any(evidence_excerpt) AS evidence,
           min(toString(detected_at)) AS first_seen
    FROM security_events FINAL
    WHERE content_sha256 != '' ${se}
    GROUP BY content_sha256 HAVING traces > 1
    ORDER BY traces DESC LIMIT 20`);

  return { traceIncidents, poisoned };
}

// ---------------- Review queue ----------------
export async function reviewQueue(range?: string, projectId?: string) {
  return q(`
    SELECT event_id, trace_id, observation_id, toString(detected_at) AS detected_at,
           category, severity, outcome, round(score,1) AS score,
           l1_rules, l4_signals, evidence_excerpt
    FROM security_events FINAL
    WHERE analyst_verdict = 'unreviewed' ${since(range, "detected_at")}${scoped(projectId)}
    ORDER BY multiIf(severity='critical',5,severity='high',4,severity='medium',3,severity='low',2,1) DESC,
             detected_at DESC LIMIT 100`);
}

// ---------------- Sessions ----------------
export async function sessions(range?: string, projectId?: string) {
  const ts = since(range, "t.timestamp") + scoped(projectId, "t.project_id");
  // obs/sec subqueries are scoped by project too — trace_id alone isn't a
  // safe join key across tenants (see tracesList below for why).
  const pj = scoped(projectId);
  return q(`
    SELECT t.session_id AS session_id, t.user_id AS user_id,
           count() AS traces,
           min(toString(t.timestamp)) AS first_seen,
           max(toString(t.timestamp)) AS last_seen,
           sum(obs.n_obs) AS spans, round(sum(obs.cost),4) AS cost,
           sum(obs.tokens) AS tokens, sum(sec.n_events) AS events,
           max(sec.max_sev) AS max_sev
    FROM (SELECT * FROM traces FINAL) t
    LEFT JOIN (SELECT trace_id, count() AS n_obs, sum(input_tokens+output_tokens) AS tokens, sum(cost_usd) AS cost FROM observations FINAL WHERE 1 ${pj} GROUP BY trace_id) obs ON obs.trace_id=t.trace_id
    LEFT JOIN (SELECT trace_id, count() AS n_events, max(severity) AS max_sev FROM security_events FINAL WHERE 1 ${pj} GROUP BY trace_id) sec ON sec.trace_id=t.trace_id
    WHERE t.session_id != '' ${ts}
    GROUP BY session_id, user_id ORDER BY last_seen DESC LIMIT 100`);
}

// ---------------- Traces ----------------
export async function tracesList(range?: string, limit = 100, projectId?: string) {
  // obs/sec subqueries are scoped by project too, not just trace_id: trace_id
  // is caller-supplied and NOT guaranteed unique across tenants (e.g. every
  // onboarding client's "hello world" test used to share a literal trace_id —
  // fixed separately, but the query must not rely on that). Without this,
  // one project's row can silently sum in another project's spans/tokens/
  // cost/latency/security-event counts whenever two trace_ids collide.
  const pj = scoped(projectId);
  return q(`
    SELECT t.trace_id AS trace_id, t.name AS name, t.environment AS environment,
           toString(t.timestamp) AS timestamp, t.session_id AS session_id,
           obs.n_obs AS observations, obs.tokens AS tokens, obs.cost AS cost,
           obs.latency AS latency_ms,
           sec.n_events AS sec_events, sec.max_sev AS sec_max_severity
    FROM (SELECT * FROM traces FINAL WHERE 1 ${since(range, "timestamp")}${pj}) t
    LEFT JOIN (
      SELECT trace_id, count() AS n_obs, sum(input_tokens+output_tokens) AS tokens,
             sum(cost_usd) AS cost,
             -- assumeNotNull on a genuinely-null end_time silently returns the
             -- type's zero value (1970-01-01), producing a nonsensical deeply
             -- negative latency for spans with no end_time (e.g. a one-shot
             -- test message). Fall back to the span's own start_time instead,
             -- which degrades to a sane "0 ms" rather than garbage.
             dateDiff('millisecond', min(start_time), max(coalesce(end_time, start_time))) AS latency
      FROM observations FINAL WHERE 1 ${pj} GROUP BY trace_id
    ) obs ON obs.trace_id = t.trace_id
    LEFT JOIN (SELECT trace_id, count() AS n_events, max(severity) AS max_sev FROM security_events FINAL WHERE 1 ${pj} GROUP BY trace_id) sec ON sec.trace_id = t.trace_id
    ORDER BY t.timestamp DESC LIMIT ${Number(limit)}`);
}

export async function traceDetail(traceId: string, projectId?: string) {
  const safe = traceId.replace(/[^a-zA-Z0-9_-]/g, "");
  const pj = scoped(projectId);
  const [trace] = await q(`
    SELECT trace_id, name, environment, toString(timestamp) AS timestamp,
           session_id, user_id, tags, metadata
    FROM traces FINAL WHERE trace_id='${safe}' ${pj} LIMIT 1`);
  const observations = await q(`
    SELECT observation_id, parent_id, type, name,
           toString(start_time) AS start_time, toString(end_time) AS end_time,
           model, provider, input_tokens, output_tokens, round(cost_usd,6) AS cost,
           finish_reason, taint, taint_source, taint_influenced, attributes,
           substring(input_full,1,8000) AS input, substring(output_full,1,8000) AS output
    FROM observations FINAL WHERE trace_id='${safe}' ${pj} ORDER BY start_time`);
  const events = await q(`
    SELECT event_id, observation_id, category, severity, outcome, round(score,1) AS score,
           l1_rules, l4_signals, l2_scores, l3_verdict, evidence_excerpt, analyst_verdict
    FROM security_events FINAL WHERE trace_id='${safe}' ${pj} ORDER BY score DESC`);
  return { trace, observations, events };
}

// ---------------- Analytics ----------------
export async function analytics(range?: string, projectId?: string) {
  const os = since(range, "start_time") + scoped(projectId);
  const [totals] = await q(`
    SELECT count() AS observations, round(sum(cost_usd),4) AS cost,
           sum(input_tokens+output_tokens) AS tokens,
           sum(input_tokens) AS input_tokens, sum(output_tokens) AS output_tokens,
           round(avgIf(dateDiff('millisecond',start_time,end_time), end_time IS NOT NULL),0) AS avg_latency_ms,
           round(quantileIf(0.95)(dateDiff('millisecond',start_time,end_time), end_time IS NOT NULL),0) AS p95_latency_ms
    FROM observations FINAL WHERE 1 ${os}
    -- the sum(input_tokens) AS input_tokens alias shadows the input_tokens column
    -- referenced by sum(input_tokens+output_tokens); prefer the column so ClickHouse
    -- doesn't nest the aggregates (Aggregate-inside-aggregate error -> 503).
    SETTINGS prefer_column_name_to_alias = 1`);
  const byModel = await q(`
    SELECT model, count() AS calls, sum(input_tokens) AS input_tokens,
           sum(output_tokens) AS output_tokens, round(sum(cost_usd),4) AS cost,
           round(avg(dateDiff('millisecond',start_time,end_time)),0) AS avg_latency_ms
    FROM observations FINAL WHERE type='generation' AND model!='' ${os}
    GROUP BY model ORDER BY cost DESC`);
  const byType = await q(`SELECT type, count() AS n FROM observations FINAL WHERE 1 ${os} GROUP BY type ORDER BY n DESC`);
  const byProvider = await q(`SELECT provider, count() AS n FROM observations FINAL WHERE provider!='' ${os} GROUP BY provider ORDER BY n DESC`);
  const byEnv = await q(`SELECT environment, count() AS n FROM traces FINAL WHERE 1 ${since(range, "timestamp")}${scoped(projectId)} GROUP BY environment ORDER BY n DESC`);
  const costTrend = await q(`
    SELECT toStartOfHour(start_time) AS hour, round(sum(cost_usd),5) AS cost,
           sum(input_tokens+output_tokens) AS tokens
    FROM observations FINAL WHERE type='generation' ${os} GROUP BY hour ORDER BY hour`);
  return { totals, byModel, byType, byProvider, byEnv, costTrend };
}

// ---------------- Prompts / Evals (may be empty) ----------------
export async function prompts(projectId?: string) {
  // Prompt versions live in Postgres; scores (evals) in ClickHouse. `scores`
  // carries project_id like every other table — this query used to omit it and
  // returned every tenant's eval names and score distributions to any signed-in
  // user who could reach the view.
  const evalScores = await q(`
    SELECT name, count() AS n, round(avg(value),3) AS avg_value,
           round(min(value),3) AS min_value, round(max(value),3) AS max_value
    FROM scores FINAL WHERE source IN ('eval','annotation') ${scoped(projectId)}
    GROUP BY name ORDER BY n DESC LIMIT 50`).catch(() => []);
  return { evalScores };
}

// ---------------- Verdict write ----------------
export async function setVerdict(eventId: string, verdict: string, projectId?: string): Promise<boolean> {
  const allowed = ["unreviewed", "confirmed", "false_positive"];
  if (!allowed.includes(verdict)) throw new Error("invalid verdict");
  const safe = eventId.replace(/[^a-zA-Z0-9_-]/g, "");
  // Scoped by project, not just event_id. The caller's access is checked against
  // the project they *claim*, so looking the event up by id alone let a member of
  // any project set verdicts on another tenant's security events (event ids are
  // discoverable/guessable and the write re-inserts the row). The scope makes the
  // claimed project and the mutated row the same tenant, or nothing matches.
  const rows = await q<Record<string, unknown>>(`
    SELECT project_id, event_id, trace_id, observation_id,
           toString(detected_at) AS detected_at, category, severity, outcome, score,
           l1_rules, l2_scores, l3_verdict, l4_signals, evidence_excerpt,
           content_sha256, incident_id
    FROM security_events FINAL WHERE event_id='${safe}' ${scoped(projectId)} LIMIT 1`);
  if (!rows.length) return false;
  const r = rows[0];
  // Re-insert with the new verdict and a fresh event_ts; ReplacingMergeTree +
  // FINAL will surface this version on read.
  await ch().insert({
    table: "security_events",
    format: "JSONEachRow",
    values: [{
      ...r,
      analyst_verdict: verdict,
      event_ts: new Date().toISOString().replace("T", " ").replace("Z", ""),
    }],
  });
  return true;
}

export async function health() {
  try { await q(`SELECT 1`); return true; } catch { return false; }
}
