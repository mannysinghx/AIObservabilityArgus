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
