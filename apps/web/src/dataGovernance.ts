/**
 * Data governance: the retention window, and the erasure request path.
 *
 * These are the two questions every security review asks — "how long do you keep
 * it" and "how do I get it deleted" — and until now the honest answers were
 * "forever" and "you can't". They live here rather than in settings.ts because
 * they behave differently from detection settings: retention is destructive and
 * irreversible, so it is audited, gated to owners for shortening, and reports
 * what it will delete before it does.
 */
import { eraseSubject, enforceRetention, type EraseResult } from "@argus/shared";
import { pool } from "./db.js";
import { safeProjectId } from "./ids.js";

export interface RetentionView {
  retentionDays: number;
  /** 0 means keep forever. */
  keepForever: boolean;
}

const DEFAULT_DAYS = Number(process.env.ARGUS_DEFAULT_RETENTION_DAYS ?? 30);

export async function getRetention(projectId: string): Promise<RetentionView> {
  const safe = safeProjectId(projectId);
  const { rows } = await pool.query<{ retention_days: number | null }>(
    "SELECT retention_days FROM projects WHERE id = $1",
    [safe],
  );
  const days = rows[0]?.retention_days ?? DEFAULT_DAYS;
  return { retentionDays: days, keepForever: days <= 0 };
}

/** Upper bound on the window. Not a policy judgement — just a guard against a
 *  fat-fingered 36500 that quietly means "forever" while looking deliberate. */
const MAX_DAYS = 3650;

export async function setRetention(
  projectId: string,
  days: number,
): Promise<RetentionView | { error: string }> {
  const safe = safeProjectId(projectId);
  if (!safe) return { error: "Unknown application." };
  if (!Number.isFinite(days) || days < 0) return { error: "Retention must be a number of days, or 0 to keep forever." };
  if (days > MAX_DAYS) return { error: `Retention can't exceed ${MAX_DAYS} days. Use 0 for "keep forever".` };
  const d = Math.floor(days);
  await pool.query("UPDATE projects SET retention_days = $2 WHERE id = $1", [safe, d]);
  return { retentionDays: d, keepForever: d <= 0 };
}

/**
 * Run the retention sweep for one project immediately.
 *
 * Shortening a window from 90 days to 7 and then waiting up to an hour for the
 * scheduled job is the wrong experience for the one setting people change
 * *because* they want data gone. This makes the change take effect when they
 * press the button.
 */
export async function applyRetentionNow(projectId: string) {
  const { retentionDays } = await getRetention(projectId);
  return enforceRetention(projectId, retentionDays);
}

/** Erase everything about one end user in this project. */
export async function eraseUser(projectId: string, subjectId: string): Promise<EraseResult | { error: string }> {
  const safe = safeProjectId(projectId);
  if (!safe) return { error: "Unknown application." };
  const subject = String(subjectId || "").trim();
  if (!subject) return { error: "Provide the user id to erase (the value your app sends as userId)." };
  return eraseSubject(safe, subject);
}

/**
 * How many traces an erasure would affect, without deleting anything.
 *
 * Erasure is irreversible and is driven by an id typed in by a human, so a
 * typo'd user id that silently matches nothing looks identical to a successful
 * erasure. Showing the count first turns that into a visible "0 traces — check
 * the id" before anything is destroyed.
 */
export async function previewErasure(projectId: string, subjectId: string): Promise<{ traces: number }> {
  const { ch } = await import("@argus/shared");
  const safe = safeProjectId(projectId);
  const subject = String(subjectId || "").trim();
  if (!safe || !subject) return { traces: 0 };
  const rs = await ch().query({
    query: "SELECT count(DISTINCT trace_id) AS n FROM traces WHERE project_id = {pid:String} AND user_id = {uid:String}",
    query_params: { pid: safe, uid: subject },
    format: "JSONEachRow",
  });
  const [row] = await rs.json<{ n: string }>();
  return { traces: Number(row?.n ?? 0) };
}
