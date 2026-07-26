/**
 * The retention sweep.
 *
 * Runs inside the worker rather than as a separate cron deployment, because a
 * scheduled job that lives somewhere else is a scheduled job that stops running
 * when someone forgets to redeploy it — and nobody notices a retention job that
 * has quietly stopped, because its output is an absence.
 *
 * Every pass logs what it deleted and how long it took, so "is retention
 * running?" is answerable from the logs rather than by inspecting row counts.
 */
import pg from "pg";
import { config, enforceRetention } from "@argus/shared";

const pool = new pg.Pool({ connectionString: config.databaseUrl, max: 2 });

/** How often to sweep. Hourly is far more often than daily retention needs,
 *  which is the point: a sweep that runs once a day takes up to a day to notice
 *  that someone shortened their retention window. */
const INTERVAL_MS = Number(process.env.RETENTION_INTERVAL_MS ?? 3_600_000);

const DEFAULT_DAYS = Number(process.env.ARGUS_DEFAULT_RETENTION_DAYS ?? 30);

export async function runRetentionPass(): Promise<{ projects: number; errors: number }> {
  const started = Date.now();
  let projects = 0;
  let errors = 0;

  const { rows } = await pool.query<{ id: string; retention_days: number | null }>(
    "SELECT id, retention_days FROM projects",
  );

  for (const row of rows) {
    const days = row.retention_days ?? DEFAULT_DAYS;
    try {
      const r = await enforceRetention(row.id, days);
      if (!r.skipped) projects++;
    } catch (err) {
      // One project's failure must not abort the sweep — otherwise a single
      // broken project means every project after it in the list never gets
      // swept, and the failure is invisible.
      errors++;
      console.error(`[retention] project ${row.id} failed:`, err);
    }
  }

  console.log(
    `[retention] swept ${projects}/${rows.length} project(s) in ${Date.now() - started}ms` +
      (errors ? `, ${errors} error(s)` : ""),
  );
  return { projects, errors };
}

let timer: NodeJS.Timeout | null = null;

export function startRetentionJob(): void {
  if (process.env.RETENTION_ENABLED === "0") {
    console.log("[retention] disabled by RETENTION_ENABLED=0");
    return;
  }
  const tick = () => {
    runRetentionPass().catch((err) => console.error("[retention] pass failed:", err));
  };
  // Deliberately not on boot: workers restart, and a deploy that cycles them a
  // few times would run several sweeps back to back against ClickHouse for no
  // benefit. The first sweep happens one interval in.
  timer = setInterval(tick, INTERVAL_MS);
  timer.unref?.();
  console.log(`[retention] scheduled every ${Math.round(INTERVAL_MS / 60_000)}m`);
}

export function stopRetentionJob(): void {
  if (timer) clearInterval(timer);
  timer = null;
}
