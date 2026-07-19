import { createHash, randomBytes } from "node:crypto";
import pg from "pg";
import { ch, config } from "@argus/shared";

const pool = new pg.Pool({ connectionString: config.databaseUrl, max: 4 });

function sha256(s: string): string {
  return createHash("sha256").update(s).digest("hex");
}

function genKey(prefix: string): string {
  return `${prefix}-${randomBytes(18).toString("base64url")}`;
}

export interface NewProject {
  orgId: string;
  projectId: string;
  projectName: string;
  publicKey: string;
  secretKey: string; // plaintext — this is the ONLY time it's ever returned
}

/**
 * Self-service onboarding: create an org + project + API key pair in one
 * shot. No login required — the secret key IS the credential, same model as
 * most single-key API products. Each call creates a fresh org/project, so
 * concurrent clients never collide.
 */
export async function createProject(orgName: string, projectName: string): Promise<NewProject> {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    const orgRes = await client.query<{ id: string }>(
      `INSERT INTO organizations (name) VALUES ($1) RETURNING id`,
      [orgName.trim().slice(0, 200)],
    );
    const orgId = orgRes.rows[0].id;

    const projRes = await client.query<{ id: string }>(
      `INSERT INTO projects (org_id, name) VALUES ($1, $2) RETURNING id`,
      [orgId, projectName.trim().slice(0, 200)],
    );
    const projectId = projRes.rows[0].id;

    const publicKey = genKey("pk");
    const secretKey = genKey("sk");
    await client.query(
      `INSERT INTO api_keys (project_id, public_key, secret_hash, scopes) VALUES ($1, $2, $3, $4)`,
      [projectId, publicKey, sha256(secretKey), ["ingest"]],
    );

    // A permissive default detection config so scanning works immediately —
    // matches the shape documented in docs/04 §Detection config.
    await client.query(
      `INSERT INTO detection_configs (project_id, config) VALUES ($1, $2)`,
      [
        projectId,
        JSON.stringify({
          layers: {
            heuristics: { enabled: true, ruleset: "default-v1" },
            classifiers: { enabled: false, escalation_threshold: 0.75 },
            judge: { enabled: false, trigger: "escalation-only" },
            trace_analysis: { enabled: true, instruction_echo: true, exfil_flow: true },
          },
          taint: { tool_overrides: {} },
          canaries: { enabled: true },
          alerting: { min_severity: "high", channels: [] },
        }),
      ],
    );

    await client.query(
      `INSERT INTO audit_log (actor, action, target) VALUES ($1, $2, $3)`,
      ["self-onboarding", "project_created", projectId],
    );

    await client.query("COMMIT");
    return { orgId, projectId, projectName: projectName.trim(), publicKey, secretKey };
  } catch (err) {
    await client.query("ROLLBACK");
    throw err;
  } finally {
    client.release();
  }
}

// ---------------- Multi-tenant catalog ----------------
// The platform view: every customer (organization) and the applications
// (projects) under it, each with live KPIs. Tenant-generic — no hard-coded
// names. Once accounts land (Phase 2), this is filtered to the caller's orgs.

export interface ProjectStat {
  orgId: string;
  orgName: string;
  projectId: string;
  projectName: string;
  environment: string;
  traces: number;
  tokens: number;
  cost: number;
  secEvents: number;
  maxSev: string;
  lastSeen: string | null;
  createdAt: string;
}

async function chRows<T>(query: string): Promise<T[]> {
  const rs = await ch().query({ query, format: "JSONEachRow" });
  return rs.json<T>();
}

/** Every org + its projects, joined with per-project ClickHouse KPIs. */
export async function listProjectsWithStats(): Promise<ProjectStat[]> {
  const { rows: projects } = await pool.query<{
    project_id: string; project_name: string; org_id: string; org_name: string; created_at: Date;
  }>(
    `SELECT p.id AS project_id, p.name AS project_name,
            p.org_id, o.name AS org_name, p.created_at
     FROM projects p JOIN organizations o ON o.id = p.org_id
     ORDER BY o.name, p.created_at`,
  );

  // Per-project aggregates from ClickHouse (one grouped query per table, merged
  // by project_id — trace/observation counts don't share a table).
  const [traceStats, obsStats, secStats] = await Promise.all([
    chRows<{ project_id: string; traces: string; environment: string; last_seen: string }>(
      `SELECT project_id, count() AS traces,
              argMax(environment, timestamp) AS environment,
              toString(max(timestamp)) AS last_seen
       FROM traces FINAL GROUP BY project_id`,
    ),
    chRows<{ project_id: string; tokens: string; cost: string }>(
      `SELECT project_id, sum(input_tokens + output_tokens) AS tokens,
              round(sum(cost_usd), 4) AS cost
       FROM observations FINAL GROUP BY project_id`,
    ),
    chRows<{ project_id: string; sec_events: string; max_sev: string }>(
      `SELECT project_id, count() AS sec_events, max(severity) AS max_sev
       FROM security_events FINAL GROUP BY project_id`,
    ),
  ]);

  const byId = <T extends { project_id: string }>(rows: T[]) =>
    new Map(rows.map((r) => [r.project_id, r]));
  const tMap = byId(traceStats);
  const oMap = byId(obsStats);
  const sMap = byId(secStats);

  return projects.map((p) => {
    const t = tMap.get(p.project_id);
    const o = oMap.get(p.project_id);
    const s = sMap.get(p.project_id);
    return {
      orgId: p.org_id,
      orgName: p.org_name,
      projectId: p.project_id,
      projectName: p.project_name,
      environment: t?.environment || "",
      traces: Number(t?.traces || 0),
      tokens: Number(o?.tokens || 0),
      cost: Number(o?.cost || 0),
      secEvents: Number(s?.sec_events || 0),
      maxSev: s?.max_sev || "none",
      lastSeen: t?.last_seen || null,
      createdAt: p.created_at instanceof Date ? p.created_at.toISOString() : String(p.created_at),
    };
  });
}

export interface ProjectMeta {
  projectId: string;
  projectName: string;
  orgId: string;
  orgName: string;
}

/** Resolve one project's human-readable name + owning org, for the header. */
export async function getProjectMeta(id: string): Promise<ProjectMeta | null> {
  const safe = String(id || "").replace(/[^a-zA-Z0-9-]/g, "");
  if (!safe) return null;
  const { rows } = await pool.query<{
    project_id: string; project_name: string; org_id: string; org_name: string;
  }>(
    `SELECT p.id AS project_id, p.name AS project_name, p.org_id, o.name AS org_name
     FROM projects p JOIN organizations o ON o.id = p.org_id
     WHERE p.id = $1`,
    [safe],
  );
  const r = rows[0];
  return r
    ? { projectId: r.project_id, projectName: r.project_name, orgId: r.org_id, orgName: r.org_name }
    : null;
}

export interface ConnectionStatus {
  projectId: string;
  connected: boolean;
  traceCount: number;
  eventCount: number;
  lastSeenAt: string | null;
}

/** Has this project received any traces yet? Polled by the onboarding UI. */
export async function checkConnectionStatus(projectId: string): Promise<ConnectionStatus> {
  const safe = String(projectId || "").replace(/[^a-zA-Z0-9_-]/g, "");
  if (!safe) return { projectId: "", connected: false, traceCount: 0, eventCount: 0, lastSeenAt: null };

  const rs = await ch().query({
    query: `
      SELECT
        (SELECT count() FROM traces FINAL WHERE project_id = '${safe}') AS trace_count,
        (SELECT count() FROM security_events FINAL WHERE project_id = '${safe}') AS event_count,
        (SELECT toString(max(timestamp)) FROM traces FINAL WHERE project_id = '${safe}') AS last_seen`,
    format: "JSONEachRow",
  });
  const [row] = await rs.json<{ trace_count: string; event_count: string; last_seen: string }>();
  const traceCount = Number(row?.trace_count || 0);
  return {
    projectId: safe,
    connected: traceCount > 0,
    traceCount,
    eventCount: Number(row?.event_count || 0),
    lastSeenAt: row?.last_seen || null,
  };
}
