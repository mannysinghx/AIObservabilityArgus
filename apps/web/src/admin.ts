import { ch } from "@argus/shared";
import { pool } from "./db.js";
import { listProjectsWithStats } from "./onboarding.js";

// Platform-operator (super-admin) queries and mutations — cross-tenant. Every
// route that calls these is gated to platform admins in server.ts.

async function chOne<T = Record<string, string>>(sql: string): Promise<T> {
  const rs = await ch().query({ query: sql, format: "JSONEachRow" });
  const rows = await rs.json<T>();
  return rows[0] || ({} as T);
}

export interface AdminUser {
  id: string;
  email: string;
  name: string;
  emailVerified: boolean;
  isPlatformAdmin: boolean;
  orgCount: number;
  createdAt: string;
}

export async function listUsers(): Promise<AdminUser[]> {
  const { rows } = await pool.query<{
    id: string; email: string; name: string; email_verified: boolean; is_platform_admin: boolean; org_count: string; created_at: Date;
  }>(
    `SELECT u.id, u.email, u.name, u.email_verified, u.is_platform_admin,
            (SELECT count(*) FROM memberships m WHERE m.user_id = u.id) AS org_count,
            u.created_at
     FROM users u ORDER BY u.is_platform_admin DESC, u.created_at`,
  );
  return rows.map((r) => ({
    id: r.id, email: r.email, name: r.name,
    emailVerified: r.email_verified, isPlatformAdmin: r.is_platform_admin,
    orgCount: Number(r.org_count), createdAt: r.created_at.toISOString(),
  }));
}

export interface AdminOrg {
  id: string;
  name: string;
  projectCount: number;
  memberCount: number;
  createdAt: string;
}

export async function listOrgs(): Promise<AdminOrg[]> {
  const { rows } = await pool.query<{ id: string; name: string; projects: string; members: string; created_at: Date }>(
    `SELECT o.id, o.name,
            (SELECT count(*) FROM projects p WHERE p.org_id = o.id) AS projects,
            (SELECT count(*) FROM memberships m WHERE m.org_id = o.id) AS members,
            o.created_at
     FROM organizations o ORDER BY o.created_at`,
  );
  return rows.map((r) => ({
    id: r.id, name: r.name, projectCount: Number(r.projects), memberCount: Number(r.members), createdAt: r.created_at.toISOString(),
  }));
}

/** Platform-wide analytics across every customer. */
export async function platformOverview() {
  const [pg, traces, obs, sec, projects] = await Promise.all([
    pool.query<{ users: string; orgs: string; projects: string; admins: string }>(
      `SELECT (SELECT count(*) FROM users) AS users,
              (SELECT count(*) FROM organizations) AS orgs,
              (SELECT count(*) FROM projects) AS projects,
              (SELECT count(*) FROM users WHERE is_platform_admin) AS admins`,
    ),
    chOne<{ n: string }>("SELECT count() AS n FROM traces FINAL"),
    chOne<{ obs: string; tokens: string; cost: string }>(
      "SELECT count() AS obs, sum(input_tokens+output_tokens) AS tokens, round(sum(cost_usd),2) AS cost FROM observations FINAL",
    ),
    chOne<{ events: string; high: string; unreviewed: string }>(
      "SELECT count() AS events, countIf(severity IN ('high','critical')) AS high, countIf(analyst_verdict='unreviewed') AS unreviewed FROM security_events FINAL",
    ),
    listProjectsWithStats(await allOrgIdsLocal()),
  ]);
  const p = pg.rows[0];

  // Aggregate per-project stats into per-customer (org) rollups.
  const byOrg = new Map<string, { org: string; projects: number; tokens: number; cost: number; secEvents: number }>();
  for (const pr of projects) {
    const cur = byOrg.get(pr.orgId) || { org: pr.orgName, projects: 0, tokens: 0, cost: 0, secEvents: 0 };
    cur.projects += 1; cur.tokens += pr.tokens; cur.cost += pr.cost; cur.secEvents += pr.secEvents;
    byOrg.set(pr.orgId, cur);
  }
  const topOrgs = [...byOrg.values()].sort((a, b) => b.cost - a.cost).slice(0, 20);

  return {
    totals: {
      users: Number(p.users), admins: Number(p.admins), orgs: Number(p.orgs), projects: Number(p.projects),
      traces: Number(traces.n || 0), observations: Number(obs.obs || 0),
      tokens: Number(obs.tokens || 0), cost: Number(obs.cost || 0),
      securityEvents: Number(sec.events || 0), highCritical: Number(sec.high || 0), unreviewed: Number(sec.unreviewed || 0),
    },
    topOrgs,
  };
}

async function allOrgIdsLocal(): Promise<string[]> {
  const r = await pool.query<{ id: string }>("SELECT id FROM organizations");
  return r.rows.map((x) => x.id);
}

// ---------------- user management ----------------

export async function setPlatformAdmin(targetUserId: string, value: boolean): Promise<{ ok: true } | { error: string }> {
  if (!value) {
    const admins = await pool.query("SELECT count(*)::int AS n FROM users WHERE is_platform_admin");
    if ((admins.rows[0] as { n: number }).n <= 1) return { error: "Can't remove the last platform admin." };
  }
  await pool.query("UPDATE users SET is_platform_admin = $2 WHERE id = $1", [targetUserId, value]);
  return { ok: true };
}

export async function deleteUser(targetUserId: string): Promise<{ ok: true } | { error: string }> {
  const u = await pool.query<{ is_platform_admin: boolean }>("SELECT is_platform_admin FROM users WHERE id = $1", [targetUserId]);
  if (!u.rowCount) return { error: "User not found." };
  if (u.rows[0].is_platform_admin) {
    const admins = await pool.query("SELECT count(*)::int AS n FROM users WHERE is_platform_admin");
    if ((admins.rows[0] as { n: number }).n <= 1) return { error: "Can't delete the last platform admin." };
  }
  await pool.query("DELETE FROM users WHERE id = $1", [targetUserId]); // cascades memberships + sessions
  return { ok: true };
}

// ---------------- company (org) management ----------------

export async function createOrg(name: string): Promise<{ id: string } | { error: string }> {
  const n = String(name || "").trim().slice(0, 200);
  if (!n) return { error: "Name is required." };
  const r = await pool.query<{ id: string }>("INSERT INTO organizations (name) VALUES ($1) RETURNING id", [n]);
  return { id: r.rows[0].id };
}

export async function renameOrg(orgId: string, name: string): Promise<{ ok: true } | { error: string }> {
  const n = String(name || "").trim().slice(0, 200);
  if (!n) return { error: "Name is required." };
  const r = await pool.query("UPDATE organizations SET name = $2 WHERE id = $1", [orgId, n]);
  if (!r.rowCount) return { error: "Company not found." };
  return { ok: true };
}

/** Delete a company: purge its projects' ClickHouse data, then the Postgres org
 *  (which cascades projects, keys, configs, memberships). Irreversible. */
export async function deleteOrg(orgId: string): Promise<{ ok: true; projectsPurged: number }> {
  const { rows } = await pool.query<{ id: string }>("SELECT id FROM projects WHERE org_id = $1", [orgId]);
  const projectIds = rows.map((r) => r.id.replace(/[^a-zA-Z0-9-]/g, ""));
  if (projectIds.length) {
    const list = projectIds.map((id) => `'${id}'`).join(",");
    // `scores` is tenant data too — it was omitted here, so a deleted customer's
    // eval/annotation rows survived the purge.
    for (const tbl of ["traces", "observations", "security_events", "scores"]) {
      await ch().command({ query: `DELETE FROM ${tbl} WHERE project_id IN (${list})` });
    }
  }
  await pool.query("DELETE FROM organizations WHERE id = $1", [orgId]);
  return { ok: true, projectsPurged: projectIds.length };
}
