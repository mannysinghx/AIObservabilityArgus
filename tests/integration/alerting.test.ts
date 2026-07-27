/**
 * Alert routing, against a real HTTP receiver.
 *
 * Alerting is the part of a security product people notice only when it fails,
 * and it fails silently by construction: the symptom of a broken channel is the
 * absence of a message. So these tests stand up an actual server, send actual
 * deliveries at it, and assert on what arrived — including the signature, which
 * is the difference between a webhook a receiver can trust and one anybody who
 * learns the URL can forge incidents into.
 */
import { test, before, after, describe } from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
import { createHmac, randomUUID } from "node:crypto";
import {
  closeSharedConnections, isSuppressed, shouldSend, slackBody, pagerDutyBody, buildPayload,
  type Finding, type SuppressionRule,
} from "@argus/shared";
import { buildApp } from "../../apps/web/src/app.js";
import { infraAvailable, makeTenant, cleanup, pool, type App, type Tenant } from "./helpers.js";

interface Received { headers: Record<string, string | string[] | undefined>; body: string }

let app: App;
let T: Tenant;
let ready = false;
let server: Server;
let port = 0;
let received: Received[] = [];
/** Status the stub returns next; lets a test drive the retry path. */
let nextStatus = 200;

before(async () => {
  server = createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      received.push({ headers: req.headers, body });
      res.writeHead(nextStatus, { "content-type": "application/json" });
      res.end("{}");
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  port = (server.address() as { port: number }).port;

  ready = await infraAvailable();
  if (!ready) return;
  app = await buildApp();
  T = await makeTenant(app, "alerting");
});

after(async () => {
  if (ready) await cleanup([T]);
  await pool.end().catch(() => {});
  await closeSharedConnections();
  await app?.close().catch(() => {});
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

function dbTest(name: string, fn: () => Promise<void>): void {
  test(name, async (t) => {
    if (!ready) return void t.skip("needs Postgres + ClickHouse (run `make up`)");
    received = [];
    nextStatus = 200;
    await fn();
  });
}

const finding = (over: Partial<Finding> = {}): Finding => ({
  observation_id: "o1", trace_id: "t1", category: "indirect_injection",
  severity: "critical", outcome: "succeeded", score: 92,
  l1_rules: ["l1-ignore-previous"], l2_scores: {}, l3_verdict: "",
  l4_signals: ["exfil_flow"], evidence_excerpt: "outbound to attacker@evil.test",
  ...over,
});

async function addChannel(body: Record<string, unknown>) {
  const res = await app.inject({
    method: "POST", url: "/api/alerts/channels",
    headers: { cookie: T.cookie },
    payload: { project: T.projectId, ...body },
  });
  return { status: res.statusCode, body: res.json() as Record<string, string> };
}

describe("channel validation", () => {
  dbTest("refuses a plaintext http endpoint", async () => {
    // Alert payloads name the attack, quote the evidence and link the trace.
    const r = await addChannel({ kind: "webhook", target: `http://127.0.0.1:${port}/hook`, label: "insecure" });
    assert.equal(r.status, 400);
    assert.match(r.body.error, /https/);
  });

  dbTest("refuses a Slack channel pointed somewhere that isn't Slack", async () => {
    const r = await addChannel({ kind: "slack", target: "https://example.com/collect", label: "not slack" });
    assert.equal(r.status, 400);
  });

  dbTest("never returns the target once stored", async () => {
    await addChannel({ kind: "slack", target: "https://hooks.slack.com/services/T0/B0/xxxxSECRETxxxx", label: "sec" });
    const list = await app.inject({
      method: "GET", url: `/api/alerts/channels?project=${T.projectId}`, headers: { cookie: T.cookie },
    });
    // A Slack webhook's entire secret is in the path, so the path can't be
    // shown — this is a credential, not an address.
    assert.ok(!list.body.includes("xxxxSECRETxxxx"), "the webhook URL came back from the API");
    assert.match(list.body, /hooks\.slack\.com/); // still recognisable
  });
});

describe("delivery", () => {
  dbTest("a test delivery reaches the endpoint and is marked as a test", async () => {
    const created = await addChannel({
      kind: "webhook", target: `https://127.0.0.1:${port}/hook`, label: "https-only",
    });
    assert.equal(created.status, 200);
    // Point it at the plain-HTTP stub directly: creation enforces https, but
    // delivery must be exercised against a server we can actually inspect.
    await pool.query("UPDATE alert_channels SET target = $2 WHERE id = $1", [
      created.body.id, `http://127.0.0.1:${port}/hook`,
    ]);

    const res = await app.inject({
      method: "POST", url: "/api/alerts/channels/test",
      headers: { cookie: T.cookie },
      payload: { project: T.projectId, id: created.body.id },
    });
    assert.equal(res.json().ok, true, `test delivery failed: ${res.body}`);
    assert.equal(received.length, 1);
    const payload = JSON.parse(received[0].body);
    // Unmistakable: a test must never be read as a real incident.
    assert.match(payload.category, /TEST/);
  });

  dbTest("webhook deliveries are HMAC-signed over timestamp and body", async () => {
    const created = await addChannel({ kind: "webhook", target: `https://127.0.0.1:${port}/h`, label: "signed" });
    const secret = created.body.signingSecret;
    assert.ok(secret, "a webhook channel should be issued a signing secret");
    await pool.query("UPDATE alert_channels SET target = $2 WHERE id = $1", [
      created.body.id, `http://127.0.0.1:${port}/h`,
    ]);

    await app.inject({
      method: "POST", url: "/api/alerts/channels/test",
      headers: { cookie: T.cookie }, payload: { project: T.projectId, id: created.body.id },
    });

    const got = received.at(-1)!;
    const ts = got.headers["x-argus-timestamp"] as string;
    const sig = got.headers["x-argus-signature"] as string;
    assert.ok(ts && sig, "signature headers missing");
    const expected = "v1=" + createHmac("sha256", secret).update(`${ts}.${got.body}`).digest("hex");
    assert.equal(sig, expected, "signature does not verify");
    // The timestamp is inside the signed material, so a captured delivery
    // can't be replayed later with a fresh timestamp.
    const forged = "v1=" + createHmac("sha256", secret).update(`${Number(ts) + 600}.${got.body}`).digest("hex");
    assert.notEqual(sig, forged);
  });

  dbTest("a 4xx is not retried, a 5xx is", async () => {
    const created = await addChannel({ kind: "webhook", target: `https://127.0.0.1:${port}/r`, label: "retry" });
    await pool.query("UPDATE alert_channels SET target = $2 WHERE id = $1", [
      created.body.id, `http://127.0.0.1:${port}/r`,
    ]);

    // 400: the request itself is wrong. Retrying sends the same broken request
    // twice more while the real alert waits.
    nextStatus = 400;
    received = [];
    await app.inject({
      method: "POST", url: "/api/alerts/channels/test",
      headers: { cookie: T.cookie }, payload: { project: T.projectId, id: created.body.id },
    });
    assert.equal(received.length, 1, "a 4xx should not be retried");

    // 500: the far side is broken right now and may not be in a moment.
    nextStatus = 500;
    received = [];
    await app.inject({
      method: "POST", url: "/api/alerts/channels/test",
      headers: { cookie: T.cookie }, payload: { project: T.projectId, id: created.body.id },
    });
    assert.equal(received.length, 3, "a 5xx should be retried up to 3 attempts");
  });

  dbTest("delivery failures are recorded, so a dead channel is visible", async () => {
    const created = await addChannel({ kind: "webhook", target: `https://127.0.0.1:${port}/f`, label: "failing" });
    await pool.query("UPDATE alert_channels SET target = $2 WHERE id = $1", [
      created.body.id, `http://127.0.0.1:1/nothing-here`,
    ]);
    await app.inject({
      method: "POST", url: "/api/alerts/channels/test",
      headers: { cookie: T.cookie }, payload: { project: T.projectId, id: created.body.id },
    });
    const list = await app.inject({
      method: "GET", url: `/api/alerts/channels?project=${T.projectId}`, headers: { cookie: T.cookie },
    });
    const ch = (list.json().channels as Array<{ id: string; consecutiveFailures: number; lastError: string | null }>)
      .find((c) => c.id === created.body.id)!;
    assert.ok(ch.consecutiveFailures > 0, "a failing channel must not look healthy");
    assert.ok(ch.lastError, "the reason should be recorded");
  });
});

describe("dedup", () => {
  dbTest("the same incident only pages once inside the window", async () => {
    const project = `dedup-${randomUUID()}`;
    const f = finding();
    const hash = "content-hash-abc";
    assert.equal(await shouldSend(project, f, hash), true, "the first one must go out");
    assert.equal(await shouldSend(project, f, hash), false, "a repeat must not");
  });

  dbTest("different content is a different incident", async () => {
    const project = `dedup-${randomUUID()}`;
    assert.equal(await shouldSend(project, finding(), "hash-one"), true);
    assert.equal(await shouldSend(project, finding(), "hash-two"), true);
  });

  dbTest("a more severe finding on the same content still pages", async () => {
    // Escalation is news even when the source is one we've already reported.
    const project = `dedup-${randomUUID()}`;
    assert.equal(await shouldSend(project, finding({ severity: "high" }), "h"), true);
    assert.equal(await shouldSend(project, finding({ severity: "critical" }), "h"), true);
  });

  dbTest("dedup is per project", async () => {
    const hash = "shared-hash";
    assert.equal(await shouldSend(`p-${randomUUID()}`, finding(), hash), true);
    assert.equal(await shouldSend(`p-${randomUUID()}`, finding(), hash), true);
  });
});

describe("suppression", () => {
  const rule = (over: Partial<SuppressionRule>): SuppressionRule => ({
    id: "s1", ruleId: null, category: null, scopeType: "rule", scopeValue: "", ...over,
  });

  test("silences a named L1 rule", () => {
    assert.ok(isSuppressed(finding(), [rule({ ruleId: "l1-ignore-previous" })]));
  });

  test("silences a category", () => {
    assert.ok(isSuppressed(finding(), [rule({ category: "indirect_injection" })]));
  });

  test("leaves unrelated findings alone", () => {
    assert.equal(isSuppressed(finding(), [rule({ ruleId: "l1-something-else" })]), null);
    assert.equal(isSuppressed(finding(), [rule({ category: "jailbreak" })]), null);
  });

  test("an empty rule set suppresses nothing", () => {
    // The failure that would silently disable the whole product.
    assert.equal(isSuppressed(finding(), []), null);
  });

  dbTest("a rule without a reason is refused", async () => {
    const res = await app.inject({
      method: "POST", url: "/api/alerts/suppressions",
      headers: { cookie: T.cookie },
      payload: { project: T.projectId, ruleId: "l1-x" },
    });
    assert.equal(res.statusCode, 400);
    assert.match(res.json().error, /why/i);
  });

  dbTest("a rule naming nothing is refused", async () => {
    // Would otherwise silence every finding in the project.
    const res = await app.inject({
      method: "POST", url: "/api/alerts/suppressions",
      headers: { cookie: T.cookie },
      payload: { project: T.projectId, reason: "make it quiet" },
    });
    assert.equal(res.statusCode, 400);
  });
});

describe("payload shape", () => {
  test("slack body carries severity, evidence and a link", () => {
    const b = slackBody(buildPayload("p1", finding()));
    const text = JSON.stringify(b);
    assert.match(text, /CRITICAL/);
    assert.match(text, /attacker@evil.test/);
    assert.match(text, /Open the trace/);
  });

  test("pagerduty severity is mapped to a value it accepts", () => {
    // PagerDuty rejects anything outside critical/error/warning/info outright,
    // so an unmapped "high" would fail the whole delivery.
    const accepted = new Set(["critical", "error", "warning", "info"]);
    for (const sev of ["info", "low", "medium", "high", "critical"] as const) {
      const b = pagerDutyBody(buildPayload("p1", finding({ severity: sev })), "rk");
      assert.ok(accepted.has(b.payload.severity), `${sev} mapped to ${b.payload.severity}`);
    }
  });

  test("the trace link is relative when no public URL is set", () => {
    // Better an obviously-relative path than a link to the recipient's own
    // localhost, which is what the old hardcoded URL produced.
    const prev = process.env.PUBLIC_URL;
    delete process.env.PUBLIC_URL;
    const p = buildPayload("p1", finding());
    assert.ok(!p.traceUrl.includes("localhost"), `leaked a localhost link: ${p.traceUrl}`);
    if (prev) process.env.PUBLIC_URL = prev;
  });
});
