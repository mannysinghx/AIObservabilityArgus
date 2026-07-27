/**
 * Data retention and erasure.
 *
 * `projects.retention_days` has existed since the first migration and nothing
 * ever honoured it, so every trace, every span, and every raw ingested envelope
 * has been kept forever. For a product whose pitch is "point us at your LLM app
 * and we'll read everything it says to your customers", that is the single
 * biggest obstacle to anyone with a compliance team — and it is also just a
 * growing ClickHouse bill.
 *
 * Two operations, deliberately separate:
 *
 *   enforceRetention()  scheduled, per project, deletes anything past the
 *                       window. Routine housekeeping.
 *
 *   eraseSubject()      on demand, deletes everything about one end user across
 *                       every table. This is the GDPR Article 17 / CCPA request
 *                       path, and it is the one an auditor will ask to see
 *                       demonstrated.
 *
 * ClickHouse lightweight DELETE is asynchronous — it marks rows and merges them
 * away later. That is fine for retention and NOT fine for erasure, where the
 * caller needs to be able to say "it is gone". `eraseSubject` therefore waits
 * for the mutation to finish before reporting success.
 */
import { ch } from "./clickhouse.js";

/** Every table holding tenant telemetry. Adding a table without adding it here
 *  is how data survives a deletion it was supposed to be caught by, so this list
 *  is the one place to change. */
export const TENANT_TABLES = [
  "traces",
  "observations",
  "security_events",
  "scores",
  "raw_events",
] as const;

/** The column carrying the event time in each table — they differ. */
const TIME_COLUMN: Record<string, string> = {
  traces: "timestamp",
  observations: "start_time",
  security_events: "detected_at",
  scores: "timestamp",
  raw_events: "received_at",
};

/** Tables that record which end user a row belongs to. `traces` is the only one
 *  carrying user_id directly; the rest are reached through trace_id. */
const SUBJECT_ROOT = "traces";

const safeId = (s: string): string => String(s ?? "").replace(/[^a-zA-Z0-9_-]/g, "");

export interface RetentionResult {
  projectId: string;
  retentionDays: number;
  tables: string[];
  skipped?: string;
}

/**
 * Delete everything older than `retentionDays` for one project.
 *
 * A retentionDays of 0 or less means "keep forever" and is a no-op — treating
 * it as "delete everything" would turn a misconfigured or unset column into
 * silent, total data loss.
 */
export async function enforceRetention(
  projectId: string,
  retentionDays: number,
): Promise<RetentionResult> {
  const id = safeId(projectId);
  if (!id) return { projectId, retentionDays, tables: [], skipped: "invalid project id" };
  if (!Number.isFinite(retentionDays) || retentionDays <= 0) {
    return { projectId: id, retentionDays, tables: [], skipped: "retention disabled (keep forever)" };
  }

  const days = Math.floor(retentionDays);
  const done: string[] = [];
  for (const table of TENANT_TABLES) {
    const col = TIME_COLUMN[table];
    await ch().command({
      query:
        `DELETE FROM ${table} WHERE project_id = '${id}' ` +
        `AND ${col} < now() - INTERVAL ${days} DAY`,
    });
    done.push(table);
  }
  return { projectId: id, retentionDays: days, tables: done };
}

export interface EraseResult {
  projectId: string;
  subject: string;
  tracesMatched: number;
  tables: string[];
}

/**
 * Erase every record of one end user (`trace.user_id`) within a project.
 *
 * Resolves the subject's trace ids first, then deletes by trace id everywhere.
 * Going through trace ids rather than trying to match user_id per table matters:
 * observations, security_events, scores and raw_events have no user_id column,
 * so "delete where user_id = X" would silently miss four of the five tables and
 * leave the prompts and completions — the actual personal data — in place.
 */
export async function eraseSubject(projectId: string, subjectId: string): Promise<EraseResult> {
  const id = safeId(projectId);
  const subject = String(subjectId ?? "");
  if (!id || !subject) return { projectId: id, subject, tracesMatched: 0, tables: [] };

  const rs = await ch().query({
    query: `SELECT DISTINCT trace_id FROM ${SUBJECT_ROOT} WHERE project_id = {pid:String} AND user_id = {uid:String}`,
    query_params: { pid: id, uid: subject },
    format: "JSONEachRow",
  });
  const traceIds = (await rs.json<{ trace_id: string }>()).map((r) => safeId(r.trace_id)).filter(Boolean);

  if (!traceIds.length) return { projectId: id, subject, tracesMatched: 0, tables: [] };

  const list = traceIds.map((t) => `'${t}'`).join(",");
  const done: string[] = [];
  for (const table of TENANT_TABLES) {
    await ch().command({
      query: `DELETE FROM ${table} WHERE project_id = '${id}' AND trace_id IN (${list})`,
      // Erasure has to be synchronous. A lightweight DELETE normally returns as
      // soon as the mutation is queued, which would let us answer a
      // right-to-erasure request "done" while the rows are still readable.
      clickhouse_settings: { mutations_sync: "2" },
    });
    done.push(table);
  }
  return { projectId: id, subject, tracesMatched: traceIds.length, tables: done };
}

/** Delete every row belonging to a project. Used when an app is deleted. */
export async function purgeProject(projectId: string): Promise<{ projectId: string; tables: string[] }> {
  const id = safeId(projectId);
  if (!id) return { projectId, tables: [] };
  const done: string[] = [];
  for (const table of TENANT_TABLES) {
    await ch().command({ query: `DELETE FROM ${table} WHERE project_id = '${id}'` });
    done.push(table);
  }
  return { projectId: id, tables: done };
}
