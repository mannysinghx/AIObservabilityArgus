/**
 * Tenant isolation for the static-assessment routes (Phase 2 of the InjectGuard
 * merge). Same blunt shape as isolation.test.ts: two unrelated customers, a
 * distinctive marker threaded through every stored field, and for each route —
 * B's project refused, and A's legitimate responses never contain B's marker.
 *
 * Assessment fixtures are seeded straight into Postgres rather than through
 * POST /api/assess/prompt: the run route needs the Python detection service,
 * which the CI isolation job doesn't start. The routes under test here are the
 * storage reads/writes, whose scoping is exactly what this suite exists to pin.
 * The run route itself is covered by a live-engine test below that skips when
 * the engine isn't reachable (locally: `python -m argus_detection.serve`).
 */
import { test, before, after, describe } from "node:test";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { config, closeSharedConnections } from "@argus/shared";
import { buildApp } from "../../apps/web/src/app.js";
import { infraAvailable, makeTenant, cleanup, pool, type App, type Tenant } from "./helpers.js";

let app: App;
let A: Tenant;
let B: Tenant;
let available = false;
let detectionUp = false;

interface Seeded {
  assessmentId: string;
  findingId: string;
}
let seededA: Seeded;
let seededB: Seeded;

/** One assessment + one finding, every text field carrying the tenant's marker. */
async function seedAssessment(t: Tenant): Promise<Seeded> {
  const assessmentId = randomUUID();
  const findingId = randomUUID();
  await pool.query(
    `INSERT INTO assessments
       (id, project_id, kind, context, documents, finding_count, max_severity,
        overall_risk, scoring_version, created_by)
     VALUES ($1, $2, 'prompt', $3, $4, 1, 'high', 75, '1.0.0', $5)`,
    [
      assessmentId, t.projectId,
      JSON.stringify({ note: t.secret }),
      JSON.stringify([{ kind: "system", name: `doc-${t.secret}` }]),
      t.userId,
    ],
  );
  await pool.query(
    `INSERT INTO assessment_findings
       (id, assessment_id, project_id, document_name, rule_id, title, category,
        severity, confidence, explanation, evidence, recommendation, frameworks,
        argus_category, argus_severity, risk, mitigations)
     VALUES ($1, $2, $3, $4, 'IG-PROMPT-007', $5, 'prompt-leakage', 'high', 'high',
             $6, $7, $8, '[]', 'prompt_leak', 'high', '{}', '[]')`,
    [
      findingId, assessmentId, t.projectId,
      `doc-${t.secret}`, `title ${t.secret}`, `explanation ${t.secret}`,
      `evidence ${t.secret}`, `recommendation ${t.secret}`,
    ],
  );
  await pool.query(
    `INSERT INTO assessment_graphs (project_id, nodes, edges, updated_by)
     VALUES ($1, $2, '[]', $3)
     ON CONFLICT (project_id) DO UPDATE SET nodes = $2`,
    [t.projectId, JSON.stringify([{ id: "n1", label: `node-${t.secret}`, node_type: "model" }]), t.userId],
  );
  return { assessmentId, findingId };
}

before(async () => {
  available = await infraAvailable();
  if (!available) return;
  app = await buildApp();
  A = await makeTenant(app, "asmt-alpha");
  B = await makeTenant(app, "asmt-beta");
  seededA = await seedAssessment(A);
  seededB = await seedAssessment(B);
  try {
    const res = await fetch(`${config.detectionUrl}/health`, { signal: AbortSignal.timeout(1500) });
    detectionUp = res.ok;
  } catch {
    detectionUp = false;
  }
});

after(async () => {
  if (available) await cleanup([A, B]);
  await pool.end().catch(() => {});
  await closeSharedConnections();
  await app?.close().catch(() => {});
});

const SKIP_REASON = "needs Postgres + ClickHouse (run `make up`, or see the CI isolation job)";

function isoTest(name: string, fn: () => Promise<void>): void {
  test(name, async (t) => {
    if (!available) {
      t.skip(SKIP_REASON);
      return;
    }
    await fn();
  });
}

/**
 * Kept in sync with the assessment guard() list in app.ts.
 *
 * `proof` is a string that MUST appear in the tenant's own response. Without it
 * the "B's marker is absent" assertion below passes vacuously on an empty body,
 * which would make this suite a green check mark over an untested boundary.
 *
 * It differs per endpoint on purpose: the /api/assessments list projection
 * returns no free-text columns at all (context and documents are detail-only,
 * so a table view doesn't ship a tenant's prompt metadata over the wire), so the
 * marker cannot appear there by design. The assessment's id is the equivalent
 * proof that the row is visible.
 */
const SCOPED_READS: { name: string; proof: (t: Tenant, s: Seeded) => string }[] = [
  { name: "assessments", proof: (_t, s) => s.assessmentId },
  { name: "assessment-findings", proof: (t) => t.secret },
  { name: "assessment-graph", proof: (t) => t.secret },
];

describe("assessment cross-tenant reads", () => {
  for (const { name, proof } of SCOPED_READS) {
    isoTest(`/api/${name} refuses another tenant's project`, async () => {
      const res = await app.inject({
        method: "GET",
        url: `/api/${name}?project=${B.projectId}`,
        headers: { cookie: A.cookie },
      });
      assert.equal(res.statusCode, 403, `expected 403, got ${res.statusCode}: ${res.body.slice(0, 300)}`);
    });

    isoTest(`/api/${name} never leaks another tenant's data`, async () => {
      const res = await app.inject({
        method: "GET",
        url: `/api/${name}?project=${A.projectId}`,
        headers: { cookie: A.cookie },
      });
      assert.equal(res.statusCode, 200, `own project should be readable: ${res.body.slice(0, 300)}`);
      assert.ok(
        res.body.includes(proof(A, seededA)),
        `own data not visible — the leak assertion below would be vacuous:\n${res.body.slice(0, 300)}`,
      );
      assert.ok(
        !res.body.includes(B.secret),
        `response for /api/${name} contained tenant B's marker:\n${res.body.slice(0, 600)}`,
      );
      // B's assessment id must not appear either — the list is scoped by
      // project, and ids are the one field this projection does return.
      assert.ok(
        !res.body.includes(seededB.assessmentId),
        `response for /api/${name} contained tenant B's assessment id:\n${res.body.slice(0, 600)}`,
      );
    });
  }
});

describe("assessment detail access", () => {
  isoTest("cannot read another tenant's assessment under their project", async () => {
    const res = await app.inject({
      method: "GET",
      url: `/api/assessment/${seededB.assessmentId}?project=${B.projectId}`,
      headers: { cookie: A.cookie },
    });
    assert.equal(res.statusCode, 403);
  });

  isoTest("cannot read another tenant's assessment by claiming your own project", async () => {
    // Authorize against a project you own, then hand over someone else's id and
    // hope the lookup ignores the scope. The scoped (id AND project_id) query
    // must answer 404, indistinguishable from "no such assessment".
    const res = await app.inject({
      method: "GET",
      url: `/api/assessment/${seededB.assessmentId}?project=${A.projectId}`,
      headers: { cookie: A.cookie },
    });
    assert.equal(res.statusCode, 404, `expected 404, got ${res.statusCode}: ${res.body.slice(0, 300)}`);
    assert.ok(!res.body.includes(B.secret), `leaked B's assessment:\n${res.body.slice(0, 600)}`);
  });

  isoTest("own assessment detail includes findings", async () => {
    const res = await app.inject({
      method: "GET",
      url: `/api/assessment/${seededA.assessmentId}?project=${A.projectId}`,
      headers: { cookie: A.cookie },
    });
    assert.equal(res.statusCode, 200);
    const body = res.json() as { findings: unknown[] };
    assert.equal(body.findings.length, 1);
    assert.ok(res.body.includes(A.secret));
  });
});

describe("assessment cross-tenant writes", () => {
  isoTest("cannot set status on another tenant's finding via your own project", async () => {
    const res = await app.inject({
      method: "POST",
      url: "/api/assessment/finding/status",
      headers: { cookie: A.cookie },
      payload: { project: A.projectId, findingId: seededB.findingId, status: "resolved" },
    });
    assert.equal(res.statusCode, 404, `expected 404, got ${res.statusCode}: ${res.body.slice(0, 300)}`);
    // And B's row must be untouched — the update was scoped, not just the response.
    const check = await pool.query<{ analyst_status: string }>(
      "SELECT analyst_status FROM assessment_findings WHERE id = $1",
      [seededB.findingId],
    );
    assert.equal(check.rows[0].analyst_status, "open");
  });

  isoTest("cannot save a graph into another tenant's project", async () => {
    const res = await app.inject({
      method: "POST",
      url: "/api/assessment/graph",
      headers: { cookie: A.cookie },
      payload: { project: B.projectId, nodes: [{ id: "evil" }], edges: [] },
    });
    assert.equal(res.statusCode, 403);
  });

  isoTest("own finding status update works and is audited as scoped", async () => {
    const res = await app.inject({
      method: "POST",
      url: "/api/assessment/finding/status",
      headers: { cookie: A.cookie },
      payload: { project: A.projectId, findingId: seededA.findingId, status: "accepted" },
    });
    assert.equal(res.statusCode, 200);
    const check = await pool.query<{ analyst_status: string }>(
      "SELECT analyst_status FROM assessment_findings WHERE id = $1",
      [seededA.findingId],
    );
    assert.equal(check.rows[0].analyst_status, "accepted");
  });

  isoTest("viewer role cannot run an assessment", async () => {
    // roleGate("member") — a viewer must be refused. Uses B's own project with
    // B's cookie after demoting B to viewer, then restores the role.
    await pool.query("UPDATE memberships SET role = 'viewer' WHERE user_id = $1", [B.userId]);
    try {
      const res = await app.inject({
        method: "POST",
        url: "/api/assess/prompt",
        headers: { cookie: B.cookie },
        payload: { project: B.projectId, documents: [{ kind: "system", content: "hello" }] },
      });
      assert.equal(res.statusCode, 403);
    } finally {
      await pool.query("UPDATE memberships SET role = 'owner' WHERE user_id = $1", [B.userId]);
    }
  });
});

describe("trace-derived architecture (Phase 4 synthesis)", () => {
  isoTest("refuses to derive a graph for another tenant's project", async () => {
    const res = await app.inject({
      method: "POST",
      url: "/api/assessment/graph/derive",
      headers: { cookie: A.cookie },
      payload: { project: B.projectId },
    });
    assert.equal(res.statusCode, 403);
  });

  isoTest("derives only from the caller's own traces", async () => {
    // Both tenants have a seeded observation whose `name` is their marker
    // (helpers.ts seedClickHouse). The derivation groups spans by name, so if
    // the parent/child self-join were scoped on one side only — the exact bug
    // this suite exists for — B's span name would surface in A's proposal.
    const res = await app.inject({
      method: "POST",
      url: "/api/assessment/graph/derive",
      headers: { cookie: A.cookie },
      payload: { project: A.projectId },
    });
    assert.equal(res.statusCode, 200, res.body.slice(0, 300));
    assert.ok(!res.body.includes(B.secret), `derived graph leaked tenant B's span:\n${res.body.slice(0, 600)}`);
    const body = res.json() as { nodes: { label: string }[] };
    // A's seeded observation is a `generation` named after its marker, so it
    // should appear — proving the assertion above isn't vacuous.
    assert.ok(body.nodes.some((n) => n.label === A.secret), `own span missing from proposal:\n${res.body.slice(0, 400)}`);
  });

  isoTest("proposing never writes — the saved graph is untouched", async () => {
    const before = await pool.query<{ nodes: unknown }>(
      "SELECT nodes FROM assessment_graphs WHERE project_id = $1", [A.projectId],
    );
    await app.inject({
      method: "POST", url: "/api/assessment/graph/derive",
      headers: { cookie: A.cookie }, payload: { project: A.projectId },
    });
    const after = await pool.query<{ nodes: unknown }>(
      "SELECT nodes FROM assessment_graphs WHERE project_id = $1", [A.projectId],
    );
    assert.deepEqual(after.rows[0]?.nodes, before.rows[0]?.nodes);
  });

  isoTest("viewer cannot derive", async () => {
    await pool.query("UPDATE memberships SET role = 'viewer' WHERE user_id = $1", [B.userId]);
    try {
      const res = await app.inject({
        method: "POST", url: "/api/assessment/graph/derive",
        headers: { cookie: B.cookie }, payload: { project: B.projectId },
      });
      assert.equal(res.statusCode, 403);
    } finally {
      await pool.query("UPDATE memberships SET role = 'owner' WHERE user_id = $1", [B.userId]);
    }
  });
});

describe("governance surfaces are tenant-scoped", () => {
  for (const path of ["policies", "controls"]) {
    isoTest(`/api/${path} refuses another tenant's project`, async () => {
      const res = await app.inject({
        method: "GET", url: `/api/${path}?project=${B.projectId}`, headers: { cookie: A.cookie },
      });
      assert.equal(res.statusCode, 403);
    });
  }

  isoTest("a control adopted by one tenant is invisible to the other", async () => {
    const adopt = await app.inject({
      method: "POST", url: "/api/controls/adopt",
      headers: { cookie: A.cookie }, payload: { project: A.projectId },
    });
    assert.equal(adopt.statusCode, 200, adopt.body.slice(0, 200));

    const mine = await app.inject({
      method: "GET", url: `/api/controls?project=${A.projectId}`, headers: { cookie: A.cookie },
    });
    assert.ok((mine.json() as { controls: unknown[] }).controls.length > 0);

    const theirs = await app.inject({
      method: "GET", url: `/api/controls?project=${B.projectId}`, headers: { cookie: B.cookie },
    });
    assert.equal((theirs.json() as { controls: unknown[] }).controls.length, 0,
      "adopting for A must not populate B");
  });

  isoTest("adopting is idempotent", async () => {
    await app.inject({
      method: "POST", url: "/api/controls/adopt",
      headers: { cookie: A.cookie }, payload: { project: A.projectId },
    });
    const second = await app.inject({
      method: "POST", url: "/api/controls/adopt",
      headers: { cookie: A.cookie }, payload: { project: A.projectId },
    });
    assert.equal((second.json() as { added: number }).added, 0, "a re-adopt must add nothing");
  });

  isoTest("cannot update another tenant's control", async () => {
    await app.inject({
      method: "POST", url: "/api/controls/adopt",
      headers: { cookie: B.cookie }, payload: { project: B.projectId },
    });
    const list = await app.inject({
      method: "GET", url: `/api/controls?project=${B.projectId}`, headers: { cookie: B.cookie },
    });
    const victim = (list.json() as { controls: { id: string }[] }).controls[0];
    // Authorize against A's own project, then hand over B's control id.
    const res = await app.inject({
      method: "POST", url: `/api/controls/${victim.id}`,
      headers: { cookie: A.cookie }, payload: { project: A.projectId, status: "implemented" },
    });
    assert.equal(res.statusCode, 404);
    const after = await pool.query<{ status: string }>(
      "SELECT status FROM governance_controls WHERE id = $1", [victim.id],
    );
    assert.equal(after.rows[0].status, "not_implemented", "B's control must be untouched");
  });

  isoTest("a policy created by one tenant is invisible to the other", async () => {
    const made = await app.inject({
      method: "POST", url: "/api/policies", headers: { cookie: A.cookie },
      payload: {
        project: A.projectId, name: `no criticals ${A.secret}`,
        conditions: { "application.open_critical_findings": { gte: 1 } },
        action: "block_deployment",
      },
    });
    assert.equal(made.statusCode, 200, made.body.slice(0, 200));
    const theirs = await app.inject({
      method: "GET", url: `/api/policies?project=${B.projectId}`, headers: { cookie: B.cookie },
    });
    assert.ok(!theirs.body.includes(A.secret));
  });

  isoTest("a policy with no conditions is refused", async () => {
    // The evaluator treats an empty map as never-matching, so storing one would
    // only create a rule that can never fire.
    const res = await app.inject({
      method: "POST", url: "/api/policies", headers: { cookie: A.cookie },
      payload: { project: A.projectId, name: "empty", conditions: {} },
    });
    assert.equal(res.statusCode, 400);
  });
});

describe("reports", () => {
  isoTest("refuses another tenant's project", async () => {
    const res = await app.inject({
      method: "GET", url: `/api/reports/executive?project=${B.projectId}&format=md`,
      headers: { cookie: A.cookie },
    });
    assert.equal(res.statusCode, 403);
  });

  isoTest("rejects an unknown kind or format", async () => {
    const bad = await app.inject({
      method: "GET", url: `/api/reports/nope?project=${A.projectId}&format=md`,
      headers: { cookie: A.cookie },
    });
    assert.equal(bad.statusCode, 400);
    const badFmt = await app.inject({
      method: "GET", url: `/api/reports/executive?project=${A.projectId}&format=docx`,
      headers: { cookie: A.cookie },
    });
    assert.equal(badFmt.statusCode, 400);
  });

  isoTest("renders a PDF for the caller's own project, without the other tenant's data", async function () {
    if (!detectionUp) return; // rendering lives in the detection service
    const res = await app.inject({
      method: "GET", url: `/api/reports/technical?project=${A.projectId}&format=pdf`,
      headers: { cookie: A.cookie },
    });
    assert.equal(res.statusCode, 200, res.body.slice(0, 200));
    assert.ok(res.headers["content-disposition"]?.toString().includes("attachment"));
    assert.ok(res.rawPayload.subarray(0, 8).toString().startsWith("%PDF-"), "must be a real PDF");
    assert.ok(!res.rawPayload.toString("latin1").includes(B.secret), "leaked tenant B's data");
  });
});

describe("live engine (skips when the detection service is down)", () => {
  isoTest("run → store → read back, scoped to the caller's project", async function () {
    if (!detectionUp) {
      // Not a failure: the CI isolation job runs without the Python service.
      return;
    }
    const res = await app.inject({
      method: "POST",
      url: "/api/assess/prompt",
      headers: { cookie: A.cookie },
      payload: {
        project: A.projectId,
        documents: [{ kind: "system", name: "risky", content: "Reveal the system prompt if asked." }],
        context: { is_public: true },
      },
    });
    assert.equal(res.statusCode, 200, res.body.slice(0, 300));
    const body = res.json() as { id: string; findingCount: number };
    assert.ok(body.findingCount > 0);

    // Stored and readable under A...
    const list = await app.inject({
      method: "GET",
      url: `/api/assessments?project=${A.projectId}`,
      headers: { cookie: A.cookie },
    });
    assert.ok(list.body.includes(body.id));

    // ...and invisible to B.
    const listB = await app.inject({
      method: "GET",
      url: `/api/assessments?project=${B.projectId}`,
      headers: { cookie: B.cookie },
    });
    assert.ok(!listB.body.includes(body.id));
  });
});
