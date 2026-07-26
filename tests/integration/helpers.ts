/**
 * Fixtures for the tenant-isolation suite: two complete, unrelated customers
 * with data in both Postgres and ClickHouse, and a way to make authenticated
 * requests as either of them.
 *
 * Requests go through `app.inject()` against the real Fastify instance, not
 * against the query functions directly. That is the whole point — every
 * cross-tenant leak this codebase has had lived in route-level authorization
 * (a missing project scope, a mismatched id sanitizer, an id looked up without
 * its tenant), and none of them would have been visible from below the HTTP
 * layer.
 */
import { randomUUID } from "node:crypto";
import pg from "pg";
import { ch, config, toChDateTime } from "@argus/shared";
import { buildApp } from "../../apps/web/src/app.js";

export type App = Awaited<ReturnType<typeof buildApp>>;

export const pool = new pg.Pool({ connectionString: config.databaseUrl, max: 4 });

/** True when both databases answer — the suite skips itself otherwise. */
export async function infraAvailable(): Promise<boolean> {
  try {
    await pool.query("SELECT 1");
    await ch().query({ query: "SELECT 1", format: "JSONEachRow" });
    return true;
  } catch {
    return false;
  }
}

export interface Tenant {
  email: string;
  password: string;
  userId: string;
  orgId: string;
  projectId: string;
  cookie: string;
  traceId: string;
  observationId: string;
  eventId: string;
  secret: string; // a distinctive string that must never appear in the other tenant's responses
}

/** A signed-in user, their org, their app, and one trace's worth of data. */
export async function makeTenant(app: App, label: string): Promise<Tenant> {
  const nonce = randomUUID().slice(0, 8);
  const email = `${label}-${nonce}@example.test`;
  const password = "correct horse battery staple";
  const secret = `SECRET-${label}-${nonce}`;

  const signup = await app.inject({
    method: "POST",
    url: "/api/auth/signup",
    payload: { email, password, name: label, company: `${label} Ltd ${nonce}` },
  });
  if (signup.statusCode !== 200) {
    throw new Error(`signup failed for ${label}: ${signup.statusCode} ${signup.body}`);
  }
  const userId = signup.json().user.id as string;
  const cookie = extractCookie(signup.headers["set-cookie"]);

  // A brand-new account is a platform admin if it happens to be the first in
  // the database. Platform admins bypass tenant scoping by design, which would
  // make every assertion below vacuously pass — so demote to an ordinary user.
  await pool.query("UPDATE users SET is_platform_admin = false WHERE id = $1", [userId]);

  const org = await pool.query<{ org_id: string }>(
    "SELECT org_id FROM memberships WHERE user_id = $1 LIMIT 1",
    [userId],
  );
  const orgId = org.rows[0].org_id;

  const created = await app.inject({
    method: "POST",
    url: "/api/onboarding/projects",
    headers: { cookie },
    payload: { projectName: `${label} app`, orgId },
  });
  if (created.statusCode !== 200) {
    throw new Error(`project creation failed for ${label}: ${created.statusCode} ${created.body}`);
  }
  const projectId = created.json().projectId as string;

  const t = await seedClickHouse(projectId, secret);
  return { email, password, userId, orgId, projectId, cookie, secret, ...t };
}

/** One trace, one observation and one security event, all carrying `secret`. */
async function seedClickHouse(projectId: string, secret: string) {
  const traceId = `trace-${randomUUID()}`;
  const observationId = `obs-${randomUUID()}`;
  const eventId = `evt-${randomUUID()}`;
  const now = toChDateTime(new Date().toISOString());

  await ch().insert({
    table: "traces",
    format: "JSONEachRow",
    values: [{
      project_id: projectId, trace_id: traceId, session_id: `session-${secret}`,
      user_id: `user-${secret}`, name: secret, timestamp: now,
      environment: "production", release: "", metadata: {}, tags: [secret], event_ts: now,
    }],
  });

  await ch().insert({
    table: "observations",
    format: "JSONEachRow",
    values: [{
      project_id: projectId, trace_id: traceId, observation_id: observationId,
      parent_id: "", type: "generation", name: secret, start_time: now, end_time: now,
      model: `model-${secret}`, provider: "test", input_tokens: 11, output_tokens: 22,
      cost_usd: 0.5, finish_reason: "stop",
      input_preview: secret, output_preview: secret,
      input_full: secret, output_full: secret,
      content_sha256: "", taint: "untrusted_external", taint_source: "", taint_influenced: 0,
      attributes: {}, event_ts: now,
    }],
  });

  await ch().insert({
    table: "security_events",
    format: "JSONEachRow",
    values: [{
      project_id: projectId, event_id: eventId, trace_id: traceId,
      observation_id: observationId, detected_at: now, category: "indirect_injection",
      severity: "critical", outcome: "succeeded", score: 90,
      l1_rules: [secret], l2_scores: {}, l3_verdict: "", l4_signals: [secret],
      evidence_excerpt: secret, content_sha256: "", incident_id: "",
      analyst_verdict: "unreviewed", event_ts: now,
    }],
  });

  await ch().insert({
    table: "scores",
    format: "JSONEachRow",
    values: [{
      project_id: projectId, score_id: `score-${randomUUID()}`, trace_id: traceId,
      observation_id: observationId, name: secret, value: 0.9, string_value: "",
      source: "eval", comment: "", timestamp: now, event_ts: now,
    }],
  });

  return { traceId, observationId, eventId };
}

function extractCookie(setCookie: string | string[] | undefined): string {
  const raw = Array.isArray(setCookie) ? setCookie[0] : setCookie;
  if (!raw) throw new Error("no session cookie returned");
  return raw.split(";")[0];
}

/** Delete both tenants' rows so repeat runs stay independent. */
export async function cleanup(tenants: Tenant[]): Promise<void> {
  for (const t of tenants) {
    const id = t.projectId.replace(/[^a-zA-Z0-9-]/g, "");
    for (const tbl of ["traces", "observations", "security_events", "scores"]) {
      await ch().command({ query: `DELETE FROM ${tbl} WHERE project_id = '${id}'` }).catch(() => {});
    }
    await pool.query("DELETE FROM users WHERE id = $1", [t.userId]).catch(() => {});
    await pool.query("DELETE FROM organizations WHERE id = $1", [t.orgId]).catch(() => {});
  }
}
