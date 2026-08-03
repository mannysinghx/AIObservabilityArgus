/**
 * Unit tests for the query DSL in apps/web/src/queryIntent.ts (docs/15 §6,
 * phase 1). Only `validateQueryIntent` and `describeIntent` are exercised
 * here — pure functions, no ClickHouse. `runQueryIntent` dispatches to
 * publicApi.ts's listTraces/listSecurityEvents (real ch() calls) and belongs
 * in the integration suite once this is wired to a route, same split as
 * canaryCoverage.ts.
 *
 * These tests are the load-bearing ones for this feature: the whole point of
 * the design is that nothing gets from "arbitrary structured input" to "a
 * query that runs" without passing through validateQueryIntent first, so its
 * rejection behavior matters as much as its acceptance behavior.
 */
import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { validateQueryIntent, describeIntent, type QueryIntent } from "../apps/web/src/queryIntent.js";

describe("validateQueryIntent — acceptance", () => {
  test("a minimal trace intent is valid", () => {
    const result = validateQueryIntent({ entity: "trace" });
    assert.equal(result.ok, true);
    if (result.ok) assert.deepEqual(result.intent.filters, {});
  });

  test("a security_event intent with recognized filters is valid", () => {
    const result = validateQueryIntent({
      entity: "security_event",
      filters: { category: "exfiltration", severity: "critical" },
    });
    assert.equal(result.ok, true);
    if (result.ok) {
      assert.equal(result.intent.filters.category, "exfiltration");
      assert.equal(result.intent.filters.severity, "critical");
    }
  });

  test("since/until/limit/cursor pass through when well-formed", () => {
    const result = validateQueryIntent({
      entity: "trace",
      since: "2026-01-01T00:00:00Z",
      until: "2026-02-01T00:00:00Z",
      limit: 50,
      cursor: "abc123",
    });
    assert.equal(result.ok, true);
    if (result.ok) {
      assert.equal(result.intent.since, "2026-01-01T00:00:00Z");
      assert.equal(result.intent.until, "2026-02-01T00:00:00Z");
      assert.equal(result.intent.limit, 50);
      assert.equal(result.intent.cursor, "abc123");
    }
  });

  test("an intent with no filters key at all is valid (empty filters)", () => {
    const result = validateQueryIntent({ entity: "security_event" });
    assert.equal(result.ok, true);
    if (result.ok) assert.deepEqual(result.intent.filters, {});
  });
});

describe("validateQueryIntent — rejection", () => {
  test("rejects a non-object", () => {
    for (const bad of [null, "trace", 42, ["trace"]]) {
      const result = validateQueryIntent(bad);
      assert.equal(result.ok, false);
    }
  });

  test("rejects an unknown entity", () => {
    const result = validateQueryIntent({ entity: "assessment_finding" });
    assert.equal(result.ok, false);
    if (!result.ok) assert.match(result.errors[0], /entity must be one of/);
  });

  test("rejects a filter that isn't valid for the entity — trace has none", () => {
    const result = validateQueryIntent({ entity: "trace", filters: { severity: "critical" } });
    assert.equal(result.ok, false);
    if (!result.ok) assert.match(result.errors[0], /not valid for entity 'trace'/);
  });

  test("rejects a filter value that isn't in the enum, even though the key is valid", () => {
    const result = validateQueryIntent({
      entity: "security_event",
      filters: { severity: "extremely-bad" },
    });
    assert.equal(result.ok, false);
    if (!result.ok) assert.match(result.errors[0], /not a recognized value/);
  });

  test("rejects a non-string filter value rather than coercing it", () => {
    const result = validateQueryIntent({ entity: "security_event", filters: { severity: 5 } });
    assert.equal(result.ok, false);
    if (!result.ok) assert.match(result.errors[0], /must be a string/);
  });

  test("rejects an unparseable since/until", () => {
    const result = validateQueryIntent({ entity: "trace", since: "not-a-date" });
    assert.equal(result.ok, false);
    if (!result.ok) assert.match(result.errors[0], /since must be a parseable timestamp/);
  });

  test("rejects since >= until", () => {
    const result = validateQueryIntent({
      entity: "trace",
      since: "2026-02-01T00:00:00Z",
      until: "2026-01-01T00:00:00Z",
    });
    assert.equal(result.ok, false);
    if (!result.ok) assert.match(result.errors.join(" "), /since must be before until/);
  });

  test("rejects a non-positive or fractional limit", () => {
    for (const bad of [0, -5, 1.5, "100"]) {
      const result = validateQueryIntent({ entity: "trace", limit: bad });
      assert.equal(result.ok, false, `expected ${JSON.stringify(bad)} to be rejected`);
    }
  });

  test("rejects an empty-string cursor", () => {
    const result = validateQueryIntent({ entity: "trace", cursor: "" });
    assert.equal(result.ok, false);
  });

  test("collects every error at once rather than stopping at the first", () => {
    const result = validateQueryIntent({
      entity: "not-real",
      since: "not-a-date",
      limit: -1,
    });
    assert.equal(result.ok, false);
    if (!result.ok) assert.ok(result.errors.length >= 3, `expected >=3 errors, got ${result.errors.length}`);
  });

  test("filters must be an object, not an array or scalar", () => {
    const result = validateQueryIntent({ entity: "security_event", filters: ["critical"] });
    assert.equal(result.ok, false);
  });
});

describe("describeIntent", () => {
  test("names the entity and default limit for a bare intent", () => {
    const intent: QueryIntent = { entity: "trace", filters: {} };
    assert.equal(describeIntent(intent), "trace, limit 100");
  });

  test("includes filters, window and an explicit limit", () => {
    const intent: QueryIntent = {
      entity: "security_event",
      filters: { category: "exfiltration", severity: "critical" },
      since: "2026-01-01T00:00:00Z",
      limit: 25,
    };
    const summary = describeIntent(intent);
    assert.match(summary, /^security_event, where category=exfiltration and severity=critical, since 2026-01-01T00:00:00Z, limit 25$/);
  });

  test("notes when continuing from a cursor", () => {
    const intent: QueryIntent = { entity: "trace", filters: {}, cursor: "xyz" };
    assert.match(describeIntent(intent), /continuing from a cursor/);
  });
});
