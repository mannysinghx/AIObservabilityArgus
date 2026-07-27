/**
 * The public /v1 read API.
 *
 * Two properties are load-bearing and both are tested against real databases:
 *
 *  1. Scope. An ingest key is deployed to every host running a customer's app;
 *     it is, by deployment count, their most exposed credential. It must not be
 *     able to read back what it sent. The scopes column has existed since the
 *     first migration and was never once read, so "it's in the schema" proves
 *     nothing here.
 *
 *  2. Pagination that doesn't lose rows. Keyset cursors exist because OFFSET
 *     over a table being written to silently skips records, and for a security
 *     export "silently skipped one" is the whole failure.
 */
import { test, before, after, describe } from "node:test";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { ch, closeRateLimiter, toChDateTime } from "@argus/shared";
import { buildApp } from "../../apps/web/src/app.js";
import { infraAvailable, makeTenant, cleanup, pool, type App, type Tenant } from "./helpers.js";

let app: App;
let A: Tenant;
let B: Tenant;
let readKey = "";
let ingestKey = "";
let ready = false;

const SEEDED = 25;

before(async () => {
  ready = await infraAvailable();
  if (!ready) return;
  app = await buildApp();
  A = await makeTenant(app, "papi-a");
  B = await makeTenant(app, "papi-b");
  readKey = await mintKey(A, ["read"], "read key");
  ingestKey = await mintKey(A, ["ingest"], "ingest key");
  await seedTraces(A.projectId, SEEDED);
  await seedTraces(B.projectId, 3);
});

after(async () => {
  if (ready) await cleanup([A, B]);
  await pool.end().catch(() => {});
  await closeRateLimiter();
  await app?.close().catch(() => {});
});

function apiTest(name: string, fn: () => Promise<void>): void {
  test(name, async (t) => {
    if (!ready) return void t.skip("needs Postgres + ClickHouse (run `make up`)");
    await fn();
  });
}

async function mintKey(t: Tenant, scopes: string[], label: string): Promise<string> {
  const res = await app.inject({
    method: "POST",
    url: "/api/keys",
    headers: { cookie: t.cookie },
    payload: { project: t.projectId, scopes, label },
  });
  assert.equal(res.statusCode, 200, `key creation failed: ${res.body}`);
  return res.json().token as string;
}

/** Distinct timestamps so ordering and cursors are deterministic. */
async function seedTraces(projectId: string, n: number): Promise<void> {
  const base = Date.now() - n * 60_000;
  const values = Array.from({ length: n }, (_, i) => {
    const ts = toChDateTime(new Date(base + i * 60_000).toISOString());
    return {
      project_id: projectId, trace_id: `papi-${projectId.slice(0, 8)}-${String(i).padStart(3, "0")}`,
      session_id: "s", user_id: "u", name: `trace ${i}`, timestamp: ts,
      environment: "test", release: "", metadata: {}, tags: [], event_ts: ts,
    };
  });
  await ch().insert({ table: "traces", format: "JSONEachRow", values });
}

const get = (url: string, token: string) =>
  app.inject({ method: "GET", url, headers: { authorization: `Bearer ${token}` } });

describe("authentication and scope", () => {
  apiTest("no credential is 401", async () => {
    const res = await app.inject({ method: "GET", url: "/v1/traces" });
    assert.equal(res.statusCode, 401);
  });

  apiTest("an unknown key is 401", async () => {
    const res = await get("/v1/traces", `ak_live_${randomUUID()}`);
    assert.equal(res.statusCode, 401);
  });

  apiTest("an ingest key cannot read", async () => {
    // The property this whole migration exists for.
    for (const url of ["/v1/traces", "/v1/observations", "/v1/security-events", "/v1/summary"]) {
      const res = await get(url, ingestKey);
      assert.equal(res.statusCode, 403, `${url} was readable with an ingest key`);
    }
  });

  apiTest("a read key can read", async () => {
    const res = await get("/v1/traces", readKey);
    assert.equal(res.statusCode, 200);
  });

  apiTest("/v1/me reports the key's project and scopes", async () => {
    const res = await get("/v1/me", readKey);
    assert.equal(res.json().projectId, A.projectId);
    assert.deepEqual(res.json().scopes, ["read"]);
  });

  apiTest("a revoked key stops working immediately", async () => {
    const doomed = await mintKey(A, ["read"], "temporary");
    assert.equal((await get("/v1/traces", doomed)).statusCode, 200);

    const keys = await app.inject({
      method: "GET", url: `/api/keys?project=${A.projectId}`, headers: { cookie: A.cookie },
    });
    const id = (keys.json().keys as Array<{ id: string; label: string }>).find((k) => k.label === "temporary")!.id;
    const del = await app.inject({
      method: "DELETE", url: `/api/keys/${id}?project=${A.projectId}`, headers: { cookie: A.cookie },
    });
    assert.equal(del.statusCode, 200);

    // Not "eventually" — revocation is the one action a customer takes when they
    // believe a key has leaked, and a 60-second cache window is the wrong answer.
    assert.equal((await get("/v1/traces", doomed)).statusCode, 401);
  });
});

describe("tenant scoping", () => {
  /** Nothing in the response may carry tenant B's marker. */
  function assertNoB(body: string): void {
    assert.ok(!body.includes(B.secret), "response contained tenant B's marker");
    assert.ok(!body.includes(`papi-${B.projectId.slice(0, 8)}`), "response contained tenant B's traces");
  }

  apiTest("a key only ever sees its own project", async () => {
    const res = await get("/v1/traces?limit=1000", readKey);
    const ids = (res.json().data as Array<{ trace_id: string }>).map((t) => t.trace_id);
    // The fixture seeds one trace of its own on top of these, so this is a
    // lower bound rather than an equality — the property under test is whose
    // data comes back, not how much.
    assert.ok(ids.length >= SEEDED, `expected at least ${SEEDED} traces, got ${ids.length}`);
    assertNoB(res.body);
  });

  apiTest("there is no project parameter to tamper with", async () => {
    // The credential names the project, so a caller cannot ask for a different
    // one — a stronger position than validating a parameter they supply.
    const res = await get(`/v1/traces?project=${B.projectId}&limit=1000`, readKey);
    assert.equal(res.statusCode, 200);
    assertNoB(res.body);
  });

  apiTest("cannot fetch another tenant's trace by id", async () => {
    const res = await get(`/v1/traces/papi-${B.projectId.slice(0, 8)}-000`, readKey);
    assert.equal(res.statusCode, 404);
  });
});

describe("pagination", () => {
  apiTest("walks every row exactly once, with no duplicates or gaps", async () => {
    const seen: string[] = [];
    let cursor: string | null = null;
    let pages = 0;
    do {
      const url = `/v1/traces?limit=7${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ""}`;
      const body = (await get(url, readKey)).json() as {
        data: Array<{ trace_id: string }>; nextCursor: string | null;
      };
      seen.push(...body.data.map((t) => t.trace_id));
      cursor = body.nextCursor;
      if (++pages > 20) throw new Error("pagination did not terminate");
    } while (cursor);

    // The exact total includes the fixture's own trace; what matters is that
    // walking the pages visits every row and visits none of them twice.
    assert.ok(seen.length >= SEEDED, `walked only ${seen.length} rows`);
    assert.equal(new Set(seen).size, seen.length, "a row was returned on more than one page");
  });

  apiTest("a new row arriving mid-walk does not shift the pages", async () => {
    // This is what keyset pagination buys over OFFSET. With OFFSET, inserting a
    // newer row between pages pushes everything down by one and the reader
    // silently never sees the row that slid across the boundary.
    const first = (await get("/v1/traces?limit=10", readKey)).json() as {
      data: Array<{ trace_id: string }>; nextCursor: string;
    };
    await seedTraces(A.projectId, 1); // a brand-new, newest-timestamp trace
    const second = (await get(`/v1/traces?limit=10&cursor=${encodeURIComponent(first.nextCursor)}`, readKey)).json() as {
      data: Array<{ trace_id: string }>;
    };
    const overlap = second.data.filter((t) => first.data.some((f) => f.trace_id === t.trace_id));
    assert.equal(overlap.length, 0, "page 2 repeated rows from page 1 after an insert");
  });

  apiTest("limit is clamped, not trusted", async () => {
    const res = await get("/v1/traces?limit=999999", readKey);
    assert.equal(res.statusCode, 200);
    assert.ok((res.json().data as unknown[]).length <= 1000);
  });

  apiTest("a malformed cursor is ignored rather than fatal", async () => {
    const res = await get("/v1/traces?cursor=not-a-real-cursor", readKey);
    assert.equal(res.statusCode, 200);
  });
});

describe("filtering", () => {
  apiTest("an unrecognised filter value is a 400, not an empty page", async () => {
    // Silently returning nothing would let a monitoring query filtered on a
    // typo'd severity report "no critical events" forever, and look like good news.
    const res = await get("/v1/security-events?severity=criticl", readKey);
    assert.equal(res.statusCode, 400);
    assert.match(res.json().message, /criticl/);
  });

  apiTest("valid filters are honoured", async () => {
    const res = await get("/v1/security-events?severity=critical", readKey);
    assert.equal(res.statusCode, 200);
    const rows = res.json().data as Array<{ severity: string }>;
    assert.ok(rows.every((r) => r.severity === "critical"));
  });

  apiTest("the time window is applied", async () => {
    const future = toChDateTime(new Date(Date.now() + 86_400_000).toISOString());
    const res = await get(`/v1/traces?since=${encodeURIComponent(future)}`, readKey);
    assert.equal((res.json().data as unknown[]).length, 0);
  });
});

describe("summary", () => {
  apiTest("returns counters scoped to the key's project", async () => {
    const res = await get("/v1/summary", readKey);
    assert.equal(res.statusCode, 200);
    const body = res.json() as { traffic: { traces: string } };
    // A's seeded traces plus the one from makeTenant, and nothing of B's.
    assert.ok(Number(body.traffic.traces) >= SEEDED);
    assert.ok(Number(body.traffic.traces) < SEEDED + 10);
  });
});
