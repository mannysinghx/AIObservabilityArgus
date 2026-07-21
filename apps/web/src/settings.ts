/**
 * Per-application settings: read + write the detection_configs.config JSONB that
 * governs sampling, redaction, detection layers, and alerting. All validation
 * flows through @argus/shared `mergeConfig`, so the UI can send a partial or
 * full object and it's always stored as a complete, clamped, safe config.
 */
import { DEFAULT_DETECTION_CONFIG, mergeConfig, type DetectionConfig } from "@argus/shared";
import { pool } from "./db.js";

const safeId = (id: string): string => String(id || "").replace(/[^a-zA-Z0-9-]/g, "");

export interface SettingsView {
  config: DetectionConfig;
  version: number;
  updatedAt: string | null;
  updatedBy: string | null;
}

/** Current settings for a project, defaults applied. Never throws on a missing row. */
export async function getSettings(projectId: string): Promise<SettingsView> {
  const safe = safeId(projectId);
  const { rows } = await pool.query<{
    config: unknown; version: number; updated_at: Date | null; updated_by: string | null;
  }>(
    `SELECT config, version, updated_at, updated_by FROM detection_configs WHERE project_id = $1 LIMIT 1`,
    [safe],
  );
  const row = rows[0];
  return {
    config: row ? mergeConfig(row.config) : DEFAULT_DETECTION_CONFIG,
    version: row?.version ?? 0,
    updatedAt: row?.updated_at ? (row.updated_at instanceof Date ? row.updated_at.toISOString() : String(row.updated_at)) : null,
    updatedBy: row?.updated_by ?? null,
  };
}

/**
 * Replace a project's settings with a sanitized version of `incoming` (the UI
 * sends the full desired config). Upserts so a project with no row yet is
 * seeded, and bumps `version` for optimistic-concurrency / audit.
 */
export async function updateSettings(
  projectId: string,
  incoming: unknown,
  updatedBy: string,
): Promise<SettingsView> {
  const safe = safeId(projectId);
  const clean = mergeConfig(incoming);
  const { rows } = await pool.query<{ version: number; updated_at: Date }>(
    `INSERT INTO detection_configs (project_id, config, version, updated_by, updated_at)
       VALUES ($1, $2, 1, $3, now())
     ON CONFLICT (project_id) DO UPDATE
       SET config = $2, version = detection_configs.version + 1, updated_by = $3, updated_at = now()
     RETURNING version, updated_at`,
    [safe, JSON.stringify(clean), updatedBy || ""],
  );
  return {
    config: clean,
    version: rows[0]?.version ?? 1,
    updatedAt: rows[0]?.updated_at instanceof Date ? rows[0].updated_at.toISOString() : String(rows[0]?.updated_at),
    updatedBy: updatedBy || null,
  };
}
