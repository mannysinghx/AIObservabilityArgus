import { ch } from "@argus/shared";

/**
 * Read-side ClickHouse queries for the dashboard. All read from the `argus`
 * database. Tables are ReplacingMergeTree, so we use FINAL to dedupe the
 * incremental inserts (data volumes here are dashboard-scale, so FINAL is fine).
 */

async function q<T = Record<string, unknown>>(sql: string): Promise<T[]> {
  const rs = await ch().query({ query: sql, format: "JSONEachRow" });
  return rs.json<T>();
}

export async function overview() {
  const [kpis] = await q(`
    SELECT
      count()                                                          AS total,
      countIf(severity = 'critical')                                   AS critical,
      countIf(severity = 'critical' AND analyst_verdict = 'unreviewed')AS critical_unreviewed,
      countIf(category IN ('direct_injection','indirect_injection'))   AS injections,
      countIf(category = 'indirect_injection')                         AS indirect,
      countIf(category = 'exfiltration')                               AS exfiltration,
      countIf(category = 'canary_triggered')                           AS canaries,
      countIf(outcome = 'succeeded')                                   AS succeeded
    FROM security_events FINAL
  `);

  const bySeverity = await q(`
    SELECT severity, count() AS n FROM security_events FINAL
    GROUP BY severity ORDER BY n DESC
  `);

  const byCategory = await q(`
    SELECT category, count() AS n FROM security_events FINAL
    GROUP BY category ORDER BY n DESC
  `);

  // Hourly trend grouped into three lanes for the stacked chart.
  const trend = await q(`
    SELECT toStartOfHour(detected_at) AS hour,
           multiIf(category = 'indirect_injection', 'indirect',
                   category IN ('direct_injection','jailbreak'), 'direct',
                   'output') AS lane,
           count() AS n
    FROM security_events FINAL
    GROUP BY hour, lane ORDER BY hour
  `);

  const [traceStats] = await q(`
    SELECT count() AS traces, uniqExact(trace_id) AS unique_traces
    FROM traces FINAL
  `);

  const [obsStats] = await q(`
    SELECT countIf(taint = 'untrusted_external') AS untrusted,
           count() AS total
    FROM observations FINAL
    WHERE type IN ('tool','retrieval')
  `);

  return { kpis, bySeverity, byCategory, trend, traceStats, obsStats };
}

export async function attackFeed(limit = 50) {
  return q(`
    SELECT event_id, trace_id, observation_id,
           toString(detected_at) AS detected_at,
           category, severity, outcome, round(score, 1) AS score,
           l1_rules, l4_signals, l2_scores, evidence_excerpt, analyst_verdict
    FROM security_events FINAL
    ORDER BY detected_at DESC
    LIMIT ${Number(limit)}
  `);
}

export async function tracesList(limit = 50) {
  return q(`
    SELECT t.trace_id AS trace_id, t.name AS name, t.environment AS environment,
           toString(t.timestamp) AS timestamp, t.session_id AS session_id,
           obs.n_obs AS observations, obs.tokens AS tokens, obs.cost AS cost,
           sec.n_events AS sec_events, sec.max_sev AS sec_max_severity
    FROM (SELECT * FROM traces FINAL) t
    LEFT JOIN (
      SELECT trace_id, count() AS n_obs,
             sum(input_tokens + output_tokens) AS tokens, sum(cost_usd) AS cost
      FROM observations FINAL GROUP BY trace_id
    ) obs ON obs.trace_id = t.trace_id
    LEFT JOIN (
      SELECT trace_id, count() AS n_events, max(severity) AS max_sev
      FROM security_events FINAL GROUP BY trace_id
    ) sec ON sec.trace_id = t.trace_id
    ORDER BY t.timestamp DESC
    LIMIT ${Number(limit)}
  `);
}

export async function traceDetail(traceId: string) {
  const safe = traceId.replace(/'/g, "");
  const [trace] = await q(`
    SELECT trace_id, name, environment, toString(timestamp) AS timestamp,
           session_id, user_id, tags
    FROM traces FINAL WHERE trace_id = '${safe}' LIMIT 1
  `);
  const observations = await q(`
    SELECT observation_id, parent_id, type, name,
           toString(start_time) AS start_time, toString(end_time) AS end_time,
           model, provider, input_tokens, output_tokens, round(cost_usd,6) AS cost,
           taint, taint_source, taint_influenced,
           substring(input_full, 1, 4000) AS input,
           substring(output_full, 1, 4000) AS output
    FROM observations FINAL WHERE trace_id = '${safe}'
    ORDER BY start_time
  `);
  const events = await q(`
    SELECT event_id, observation_id, category, severity, outcome,
           round(score,1) AS score, l1_rules, l4_signals, l2_scores,
           evidence_excerpt, analyst_verdict
    FROM security_events FINAL WHERE trace_id = '${safe}'
    ORDER BY score DESC
  `);
  return { trace, observations, events };
}

export async function analytics() {
  const byModel = await q(`
    SELECT model,
           count() AS calls,
           sum(input_tokens)  AS input_tokens,
           sum(output_tokens) AS output_tokens,
           round(sum(cost_usd), 4) AS cost
    FROM observations FINAL
    WHERE type = 'generation' AND model != ''
    GROUP BY model ORDER BY cost DESC
  `);
  const [totals] = await q(`
    SELECT count() AS observations,
           round(sum(cost_usd), 4) AS cost,
           sum(input_tokens + output_tokens) AS tokens,
           round(avg(dateDiff('millisecond', start_time, end_time)), 0) AS avg_latency_ms,
           round(quantile(0.95)(dateDiff('millisecond', start_time, end_time)), 0) AS p95_latency_ms
    FROM observations FINAL
    WHERE end_time IS NOT NULL
  `);
  const byType = await q(`
    SELECT type, count() AS n FROM observations FINAL GROUP BY type ORDER BY n DESC
  `);
  return { byModel, totals, byType };
}

export async function health() {
  try {
    await q(`SELECT 1`);
    return true;
  } catch {
    return false;
  }
}
