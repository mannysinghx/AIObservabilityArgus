/**
 * Consumer resilience, against real Redis.
 *
 * The behaviour under test is the one that used to be absent: what happens when
 * an event cannot be processed. Previously the batch was left unacked and the
 * loop moved on — and it moved on with cursor ">" (new messages only), so the
 * entry was never redelivered at all. It sat in the pending list forever:
 * unprocessed, uncounted and invisible, with the process still up and telemetry
 * quietly ceasing to land.
 *
 * Real Redis, not a mock. Everything that matters here — delivery counts,
 * pending lists, XACK semantics — is Redis's behaviour rather than ours, and a
 * mock would only encode our idea of it, which is exactly what was wrong.
 */
import { test, before, after, describe } from "node:test";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import Redis from "ioredis";
import { config, closeRateLimiter, ensureGroup, metrics } from "@argus/shared";
import { runConsumer, DLQ_KEY } from "../../apps/worker/src/consumer.js";

let r: Redis;
let ready = false;

before(async () => {
  r = new Redis(config.redisUrl, { maxRetriesPerRequest: 1, enableOfflineQueue: false, lazyConnect: true });
  try {
    await r.connect();
    await r.ping();
    ready = true;
  } catch {
    ready = false;
  }
});

after(async () => {
  await r?.quit().catch(() => r?.disconnect());
  await closeRateLimiter();
});

function redisTest(name: string, fn: () => Promise<void>): void {
  test(name, async (t) => {
    if (!ready) return void t.skip("needs Redis (run `make up`)");
    metrics.reset();
    await fn();
  });
}

/**
 * Create the consumer group before anything is pushed.
 *
 * ensureGroup creates groups at `$` — "deliver only what arrives after this
 * point" — which is right for a new deployment (it must not replay the entire
 * backlog on first boot), but means a test that pushes first and starts the
 * consumer second sees nothing at all.
 */
async function makeGroup(): Promise<string> {
  const group = `test-${randomUUID().slice(0, 8)}`;
  await ensureGroup("argus:ingest", group);
  return group;
}

async function pushEvent(payload: unknown): Promise<void> {
  await r.xadd("argus:ingest", "*", "event", JSON.stringify(payload));
}

/**
 * DLQ entries mentioning a marker.
 *
 * Scoped by marker rather than by stream length. Every test here shares one
 * stream and one DLQ, so "the DLQ got longer" is true for reasons unrelated to
 * the test asserting it — and "the DLQ did not get longer" is worse, because it
 * fails whenever a neighbouring test quarantines something.
 */
async function dlqEntriesFor(marker: string): Promise<string[]> {
  const entries = (await r.xrange(DLQ_KEY, "-", "+")) as Array<[string, string[]]>;
  return entries.map(([, fields]) => fields.join(" ")).filter((f) => f.includes(marker));
}

/**
 * Run the consumer until `until` is satisfied, then stop it.
 *
 * The consumer loops forever by design. Racing it against a fixed sleep — the
 * obvious approach — is wrong twice over: the assertion fires at an arbitrary
 * point mid-flight, and the losing side of the race keeps going, so every test
 * leaves a zombie consumer competing for the rest of the file. Polling the
 * actual condition and then aborting is both faster and deterministic.
 */
async function runUntil(
  group: string,
  handler: (events: unknown[]) => Promise<void>,
  until: () => Promise<boolean>,
  timeoutMs = 20_000,
): Promise<boolean> {
  const controller = new AbortController();
  const consumer = `test-${randomUUID().slice(0, 8)}`;
  const loop = runConsumer(group, consumer, handler as never, {
    batch: 10,
    blockMs: 50,
    signal: controller.signal,
  }).catch(() => {});

  const deadline = Date.now() + timeoutMs;
  let satisfied = false;
  while (Date.now() < deadline) {
    if (await until()) { satisfied = true; break; }
    await new Promise((res) => setTimeout(res, 100));
  }
  controller.abort();
  await loop;
  return satisfied;
}

describe("poison-pill handling", () => {
  redisTest("a permanently failing event is dead-lettered, and the group drains", async () => {
    const group = await makeGroup();
    const marker = `poison-${randomUUID()}`;
    await pushEvent({ projectId: marker, kind: "observation", payload: { traceId: "t", observationId: "o" } });

    let attempts = 0;
    const ok = await runUntil(
      group,
      async () => { attempts++; throw new Error("this event can never be processed"); },
      async () => (await dlqEntriesFor(marker)).length > 0,
    );
    assert.ok(ok, `never dead-lettered after ${attempts} attempts`);

    // Retried — but a bounded number of times, not forever.
    assert.ok(attempts >= 2, `expected retries, saw ${attempts}`);
    assert.ok(attempts <= 15, `retried ${attempts} times — the cap is not being applied`);

    // And out of the pending list, so the group can move past it. That is the
    // whole point: the pipeline drains instead of stopping.
    const pending = (await r.xpending("argus:ingest", group)) as unknown as [number, ...unknown[]];
    assert.equal(Number(pending[0]), 0, "the poison event is still blocking the group");
  });

  redisTest("the quarantined payload and reason are preserved", async () => {
    const group = await makeGroup();
    const marker = `inspect-${randomUUID()}`;
    await pushEvent({ projectId: marker, kind: "observation", payload: { traceId: "t" } });

    const ok = await runUntil(
      group,
      async () => { throw new Error("nope-distinctive-reason"); },
      async () => (await dlqEntriesFor(marker)).length > 0,
    );
    assert.ok(ok, "never dead-lettered");

    // Dead-lettering that discards the event turns a debuggable failure into a
    // mystery, so the envelope and the reason both have to survive.
    const mine = await dlqEntriesFor(marker);
    assert.match(mine[0], /nope-distinctive-reason/, "the failure reason was not recorded");
    assert.match(mine[0], /observation/, "the original payload was not preserved");
  });

  redisTest("unparseable entries are quarantined immediately", async () => {
    // They can never parse, so retrying them is pure waste — they must not
    // consume the retry budget that exists for transient failures.
    const group = await makeGroup();
    const marker = `notjson-${randomUUID()}`;
    await r.xadd("argus:ingest", "*", "event", `{not json at all ${marker}`);

    const ok = await runUntil(
      group,
      async () => {},
      async () => (await dlqEntriesFor(marker)).length > 0,
    );
    assert.ok(ok, "malformed entry was not dead-lettered");
    assert.match((await dlqEntriesFor(marker))[0], /unparseable/, "the reason should say it could not be parsed");
  });

  redisTest("good events still flow past a poison one", async () => {
    // The failure mode this replaces: one unprocessable event starving
    // everything queued behind it.
    const group = await makeGroup();
    const badMarker = `bad-${randomUUID()}`;
    const goodMarker = `good-${randomUUID()}`;
    await pushEvent({ projectId: badMarker, kind: "observation", payload: { traceId: "t" } });
    await pushEvent({ projectId: goodMarker, kind: "observation", payload: { traceId: "t" } });

    const seenGood = new Set<string>();
    const ok = await runUntil(
      group,
      async (events) => {
        const list = events as Array<{ projectId: string }>;
        if (list.some((e) => e.projectId === badMarker)) throw new Error("bad batch");
        for (const e of list) seenGood.add(e.projectId);
      },
      async () => seenGood.has(goodMarker),
    );
    assert.ok(ok, "the good event never got processed — the poison one blocked it");
  });

  redisTest("a transient failure recovers without dead-lettering", async () => {
    // Most failures are transient — ClickHouse restarting, a network blip. The
    // retry budget exists for exactly these, and they must not be quarantined.
    const group = await makeGroup();
    const marker = `transient-${randomUUID()}`;
    await pushEvent({ projectId: marker, kind: "observation", payload: { traceId: "t" } });

    let calls = 0;
    let processed = false;
    const ok = await runUntil(
      group,
      async () => {
        calls++;
        if (calls < 2) throw new Error("temporary");
        processed = true;
      },
      async () => processed,
    );
    assert.ok(ok, `the event never succeeded on retry (handler ran ${calls}x)`);
    assert.deepEqual(await dlqEntriesFor(marker), [], "a recoverable event was dead-lettered");
  });
});

describe("metrics emitted by the consumer", () => {
  redisTest("processed events and batch duration are recorded", async () => {
    const group = await makeGroup();
    const marker = `m-${randomUUID()}`;
    await pushEvent({ projectId: marker, kind: "observation", payload: { traceId: "t" } });

    let seen = false;
    const ok = await runUntil(group, async () => { seen = true; }, async () => seen);
    assert.ok(ok, "the event was never processed");

    const out = metrics.render();
    assert.match(out, /worker_events_processed_total/);
    assert.match(out, /worker_batch_duration_ms_count/);
  });

  redisTest("dead-letters are counted", async () => {
    const group = await makeGroup();
    const marker = `d-${randomUUID()}`;
    await pushEvent({ projectId: marker, kind: "observation", payload: { traceId: "t" } });
    const ok = await runUntil(
      group,
      async () => { throw new Error("always"); },
      async () => (await dlqEntriesFor(marker)).length > 0,
    );
    assert.ok(ok, "never dead-lettered");
    // A DLQ that grows silently is the same problem as a stalled queue.
    assert.match(metrics.render(), /worker_dlq_total/);
  });
});
