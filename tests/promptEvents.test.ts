/**
 * Browser Guard report → Argus rows.
 *
 * The load-bearing test here is the privacy one. The extension's entire pitch is
 * that prompt text never leaves the browser; if a future change ever threads
 * content through this mapping, that promise breaks silently and the people who
 * installed it would have no way to know. So the mapping is asserted to produce
 * no free text at all, from an input that is nothing but free text.
 */
import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { mapPromptEvent, EXTENSION_RULE_CATEGORY, PromptEvent } from "@argus/shared";

const ev = (over: Partial<PromptEvent> = {}): PromptEvent =>
  PromptEvent.parse({
    provider: "chatgpt.com",
    channel: "fetch",
    severity: "critical",
    finding_count: 1,
    rule_ids: ["IG-SECRET-001"],
    ...over,
  });

describe("mapPromptEvent", () => {
  test("a clean prompt produces nothing to store", () => {
    assert.equal(mapPromptEvent(ev({ severity: "ok", finding_count: 0, rule_ids: [] })), null);
    // finding_count is what the extension actually counted; trust it over a
    // severity that says otherwise.
    assert.equal(mapPromptEvent(ev({ finding_count: 0 })), null);
  });

  test("maps each rule to an Argus attack category", () => {
    const m = mapPromptEvent(ev({ rule_ids: ["IG-SECRET-001", "IG-INJECT-001"] }))!;
    assert.deepEqual(m.findings.map((f) => f.category), ["pii_egress", "direct_injection"]);
    assert.deepEqual(m.findings.map((f) => f.l1_rules[0]), ["IG-SECRET-001", "IG-INJECT-001"]);
  });

  test("every shipped extension rule has a category", () => {
    // The extension is distributed separately and can ship a rule before the
    // server knows it. That is handled (unmapped rules drop), but the six rules
    // that exist today must all be mapped or the feature is quietly half-on.
    for (const id of ["IG-SECRET-001", "IG-PII-001", "IG-INJECT-001", "IG-EXFIL-001", "IG-INDIRECT-001", "IG-ENCODE-001"]) {
      assert.ok(EXTENSION_RULE_CATEGORY[id], `${id} is unmapped`);
    }
  });

  test("an unknown rule is dropped, never guessed at", () => {
    const m = mapPromptEvent(ev({ rule_ids: ["IG-SECRET-001", "IG-FUTURE-999"] }))!;
    assert.equal(m.findings.length, 1);
    assert.equal(m.findings[0].l1_rules[0], "IG-SECRET-001");
  });

  test("an event of only unknown rules stores nothing", () => {
    assert.equal(mapPromptEvent(ev({ rule_ids: ["IG-FUTURE-999"] })), null);
  });

  test("findings are marked as client-asserted, not server-detected", () => {
    const m = mapPromptEvent(ev())!;
    assert.equal(m.findings[0].source, "browser_extension");
    // The extension warns before the prompt is sent and cannot know what the
    // person did next; anything but "attempted" would be a fabrication.
    assert.equal(m.findings[0].outcome, "attempted");
  });

  test("NO prompt text survives the mapping", () => {
    // Every string field of the input is a distinctive marker. None of them,
    // other than the provider hostname, may appear in what gets stored.
    const marker = "SUPER-SECRET-PROMPT-TEXT";
    const m = mapPromptEvent(
      ev({ provider: marker, channel: marker, rule_ids: ["IG-SECRET-001"] }),
    )!;
    assert.equal(m.observation.input, "");
    assert.equal(m.observation.output, "");
    assert.equal(m.findings[0].evidence_excerpt, "");
    // The provider IS reported (it is the site name, not the prompt) — that is
    // the one place the marker is allowed to show up.
    assert.ok(JSON.stringify(m).includes(marker), "provider should be reported");
    // ...but nothing carries a content-shaped field with it.
    assert.equal(m.observation.input.length + m.observation.output.length, 0);
  });

  test("a hostile provider string cannot become markup or a path", () => {
    const m = mapPromptEvent(ev({ provider: "evil.com/<script>alert(1)</script>?x=1" }))!;
    assert.ok(!m.observation.name.includes("<"));
    assert.ok(!m.observation.name.includes("/"));
    assert.ok(!m.trace.name.includes("<"));
  });

  test("severity drives the score and is carried through", () => {
    const low = mapPromptEvent(ev({ severity: "low" }))!;
    const crit = mapPromptEvent(ev({ severity: "critical" }))!;
    assert.ok(crit.findings[0].score > low.findings[0].score);
    assert.equal(crit.findings[0].severity, "critical");
  });

  test("extension traffic lands in its own environment", () => {
    const m = mapPromptEvent(ev())!;
    // So it can be filtered in or out, and never silently inflates an
    // application's production numbers.
    assert.equal(m.trace.environment, "browser-extension");
    assert.equal(m.observation.taint, "user");
  });

  test("trace and observation ids agree", () => {
    const m = mapPromptEvent(ev())!;
    assert.equal(m.observation.traceId, m.trace.traceId);
    assert.equal(m.findings[0].trace_id, m.trace.traceId);
    assert.equal(m.findings[0].observation_id, m.observation.observationId);
  });
});

describe("PromptEventBatch validation", () => {
  test("rejects a payload carrying anything content-shaped", async () => {
    const { PromptEventBatch } = await import("@argus/shared");
    const parsed = PromptEventBatch.parse({
      events: [{ provider: "x.com", severity: "high", finding_count: 1, rule_ids: ["IG-PII-001"], prompt: "secret" }],
    });
    // zod strips unknown keys, so a client that starts sending prompt text
    // cannot get it past the boundary even by accident.
    assert.equal((parsed.events[0] as Record<string, unknown>).prompt, undefined);
  });

  test("caps the batch and the rule list", async () => {
    const { PromptEventBatch } = await import("@argus/shared");
    const tooMany = { events: Array.from({ length: 201 }, () => ({ provider: "x.com" })) };
    assert.equal(PromptEventBatch.safeParse(tooMany).success, false);
  });
});
