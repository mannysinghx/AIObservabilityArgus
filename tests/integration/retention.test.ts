/**
 * Retention and erasure, against real ClickHouse.
 *
 * These cannot be usefully unit-tested. The failure modes are all in the
 * database's behaviour: which tables a DELETE actually reached, whether a
 * lightweight delete had taken effect by the time we answered, and whether rows
 * we never intended to touch are still there. Mocking ClickHouse would test the
 * mock.
 *
 * The negative assertions matter as much as the positive ones. A retention sweep
 * that deletes everything passes any test that only checks "old data is gone".
 */
import { test, before, after, describe } from "node:test";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import {
  ch, closeSharedConnections, enforceRetention, eraseSubject, purgeProject, toChDateTime,
  TENANT_TABLES,
} from "@argus/shared";
import { infraAvailable, pool } from "./helpers.js";

let ready = false;
const projectA = randomUUID();
const projectB = randomUUID();

before(async () => { ready = await infraAvailable(); });
after(async () => {
  if (ready) { await purgeProject(projectA); await purgeProject(projectB); }
  await pool.end().catch(() => {});
  await closeSharedConnections();
});

function dbTest(name: string, fn: () => Promise<void>): void {
  test(name, async (t) => {
    if (!ready) return void t.skip("needs ClickHouse (run `make up`)");
    await fn();
  });
}

const daysAgo = (n: number) => toChDateTime(new Date(Date.now() - n * 86_400_000).toISOString());

/** One trace plus a row in every other tenant table, at a chosen age. */
async function seed(projectId: string, userId: string, ageDays: number): Promise<string> {
  const traceId = `t-${randomUUID()}`;
  const ts = daysAgo(ageDays);
  await ch().insert({
    table: "traces", format: "JSONEachRow",
    values: [{ project_id: projectId, trace_id: traceId, session_id: "s", user_id: userId,
      name: "n", timestamp: ts, environment: "test", release: "", metadata: {}, tags: [], event_ts: ts }],
  });
  await ch().insert({
    table: "observations", format: "JSONEachRow",
    values: [{ project_id: projectId, trace_id: traceId, observation_id: `o-${randomUUID()}`,
      parent_id: "", type: "generation", name: "n", start_time: ts, end_time: ts, model: "m",
      provider: "p", input_tokens: 1, output_tokens: 1, cost_usd: 0, finish_reason: "stop",
      input_preview: "hello", output_preview: "hi", input_full: "hello", output_full: "hi",
      content_sha256: "", taint: "user", taint_source: "", taint_influenced: 0, attributes: {}, event_ts: ts }],
  });
  await ch().insert({
    table: "security_events", format: "JSONEachRow",
    values: [{ project_id: projectId, event_id: `e-${randomUUID()}`, trace_id: traceId,
      observation_id: "", detected_at: ts, category: "direct_injection", severity: "low",
      outcome: "attempted", score: 10, l1_rules: [], l2_scores: {}, l3_verdict: "", l4_signals: [],
      evidence_excerpt: "", content_sha256: "", incident_id: "", analyst_verdict: "unreviewed", event_ts: ts }],
  });
  await ch().insert({
    table: "scores", format: "JSONEachRow",
    values: [{ project_id: projectId, score_id: `s-${randomUUID()}`, trace_id: traceId,
      observation_id: "", name: "quality", value: 1, string_value: "", source: "eval",
      comment: "", timestamp: ts, event_ts: ts }],
  });
  await ch().insert({
    table: "raw_events", format: "JSONEachRow",
    values: [{ project_id: projectId, event_id: `r-${randomUUID()}`, kind: "trace",
      trace_id: traceId, received_at: ts, payload: '{"secret":"the full ingested payload"}' }],
  });
  return traceId;
}

async function countFor(table: string, projectId: string, traceId?: string): Promise<number> {
  const where = traceId
    ? "project_id = {pid:String} AND trace_id = {tid:String}"
    : "project_id = {pid:String}";
  const rs = await ch().query({
    query: `SELECT count() AS n FROM ${table} WHERE ${where}`,
    query_params: traceId ? { pid: projectId, tid: traceId } : { pid: projectId },
    format: "JSONEachRow",
  });
  const [row] = await rs.json<{ n: string }>();
  return Number(row?.n ?? 0);
}

describe("retention", () => {
  dbTest("deletes data past the window, in every table", async () => {
    const old = await seed(projectA, "u1", 60);
    for (const t of TENANT_TABLES) {
      assert.equal(await countFor(t, projectA, old), 1, `${t} was not seeded`);
    }
    await enforceRetention(projectA, 30);
    for (const t of TENANT_TABLES) {
      assert.equal(await countFor(t, projectA, old), 0, `${t} still holds data past the window`);
    }
  });

  dbTest("keeps data inside the window", async () => {
    const recent = await seed(projectA, "u2", 3);
    await enforceRetention(projectA, 30);
    // The assertion that stops "delete everything" from passing.
    assert.equal(await countFor("traces", projectA, recent), 1);
    assert.equal(await countFor("raw_events", projectA, recent), 1);
  });

  dbTest("reaches raw_events — the table that holds the full payloads", async () => {
    // Called out separately because raw_events is the one a hand-written table
    // list keeps omitting, and it is the one that matters most for a deletion
    // promise: it stores every ingested envelope verbatim.
    const old = await seed(projectA, "u3", 90);
    assert.equal(await countFor("raw_events", projectA, old), 1);
    await enforceRetention(projectA, 7);
    assert.equal(await countFor("raw_events", projectA, old), 0);
  });

  dbTest("never touches another project", async () => {
    const mine = await seed(projectA, "u4", 90);
    const theirs = await seed(projectB, "u4", 90);
    await enforceRetention(projectA, 1);
    assert.equal(await countFor("traces", projectA, mine), 0);
    assert.equal(await countFor("traces", projectB, theirs), 1, "swept another tenant's data");
  });

  dbTest("retention of 0 means keep forever, not delete everything", async () => {
    // The dangerous default. An unset or zero column must never be read as
    // "delete it all" — that turns a misconfiguration into total data loss.
    const old = await seed(projectB, "u5", 400);
    const r = await enforceRetention(projectB, 0);
    assert.ok(r.skipped, "expected the sweep to decline");
    assert.equal(await countFor("traces", projectB, old), 1);
  });

  dbTest("a negative or nonsense window is also a no-op", async () => {
    const old = await seed(projectB, "u6", 400);
    for (const bad of [-1, NaN, Infinity]) {
      const r = await enforceRetention(projectB, bad as number);
      assert.ok(r.skipped, `retention(${bad}) should decline`);
    }
    assert.equal(await countFor("traces", projectB, old), 1);
  });
});

describe("right to erasure", () => {
  dbTest("erases one person across every table, synchronously", async () => {
    const subject = `subject-${randomUUID()}`;
    const t1 = await seed(projectA, subject, 1);
    const t2 = await seed(projectA, subject, 5);

    const r = await eraseSubject(projectA, subject);
    assert.equal(r.tracesMatched, 2);

    // No polling, no sleep: eraseSubject waits for the mutation, because
    // answering a deletion request "done" while rows are still readable is the
    // one thing this function must not do.
    for (const trace of [t1, t2]) {
      for (const table of TENANT_TABLES) {
        assert.equal(await countFor(table, projectA, trace), 0, `${table} still has erased data`);
      }
    }
  });

  dbTest("leaves other people's data alone", async () => {
    const victim = `v-${randomUUID()}`;
    const bystander = `b-${randomUUID()}`;
    await seed(projectA, victim, 1);
    const keep = await seed(projectA, bystander, 1);
    await eraseSubject(projectA, victim);
    assert.equal(await countFor("traces", projectA, keep), 1);
    assert.equal(await countFor("observations", projectA, keep), 1);
  });

  dbTest("does not cross project boundaries", async () => {
    const shared = `shared-${randomUUID()}`;
    await seed(projectA, shared, 1);
    const other = await seed(projectB, shared, 1);
    await eraseSubject(projectA, shared);
    assert.equal(await countFor("traces", projectB, other), 1, "erased another tenant's rows");
  });

  dbTest("an unknown subject erases nothing and says so", async () => {
    const r = await eraseSubject(projectA, `nobody-${randomUUID()}`);
    assert.equal(r.tracesMatched, 0);
    assert.deepEqual(r.tables, [], "no deletes should have been issued");
  });

  dbTest("a blank subject id is refused", async () => {
    // Guard against "" matching every row with an empty user_id.
    const before = await countFor("traces", projectA);
    const r = await eraseSubject(projectA, "");
    assert.equal(r.tracesMatched, 0);
    assert.equal(await countFor("traces", projectA), before);
  });
});
