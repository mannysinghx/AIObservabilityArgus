/**
 * Unit tests for the pure logic in apps/web/src/canaryCoverage.ts
 * (docs/15 §4, phase 1). Only `groupSamplesBySource` and `computeCoverage` are
 * exercised here — no ClickHouse/Postgres needed, since neither touches `ch()`
 * or `loadCanaries()`. `fetchRetrievalSamples`/`getCanaryCoverage` are thin
 * I/O wrappers around already-tested primitives and belong in the integration
 * suite once this is wired to a route, same split as the rest of this repo
 * (unit tests here, live-store tests under tests/integration/).
 */
import { test, describe } from "node:test";
import assert from "node:assert/strict";
import {
  computeCoverage,
  groupSamplesBySource,
  type RawRetrievalSample,
} from "../apps/web/src/canaryCoverage.js";
import { CANARY_PATTERN, hashCanary, type CanaryRef } from "@argus/shared";

function generatedCanary(label: string, value: string): CanaryRef {
  return { id: label, label, kind: "generated", tokenHash: hashCanary(value), value: "" };
}
function customCanary(label: string, value: string): CanaryRef {
  return { id: label, label, kind: "custom", tokenHash: hashCanary(value), value };
}

describe("groupSamplesBySource", () => {
  test("groups rows by source and keeps the most recent lastSeenAt regardless of input order", () => {
    const rows: RawRetrievalSample[] = [
      { sourceRef: "kb-1", observedAt: "2026-01-01T00:00:00Z", content: "old" },
      { sourceRef: "kb-1", observedAt: "2026-01-05T00:00:00Z", content: "newer" },
      { sourceRef: "kb-2", observedAt: "2026-01-03T00:00:00Z", content: "other source" },
    ];
    const grouped = groupSamplesBySource(rows);
    assert.equal(grouped.length, 2);
    const kb1 = grouped.find((g) => g.sourceRef === "kb-1")!;
    assert.equal(kb1.lastSeenAt, "2026-01-05T00:00:00Z");
    assert.deepEqual(kb1.contents, ["old", "newer"]);
  });

  test("caps content samples per source at maxSamplesPerSource", () => {
    const rows: RawRetrievalSample[] = Array.from({ length: 10 }, (_, i) => ({
      sourceRef: "kb-1",
      observedAt: `2026-01-0${(i % 9) + 1}T00:00:00Z`,
      content: `chunk-${i}`,
    }));
    const grouped = groupSamplesBySource(rows, 3);
    assert.equal(grouped[0].contents.length, 3);
  });

  test("empty input yields no sources", () => {
    assert.deepEqual(groupSamplesBySource([]), []);
  });
});

describe("computeCoverage", () => {
  test("a source containing a generated canary's raw value is covered, matched by hash", () => {
    const value = "argus-cnry-abc123XYZ_-";
    const canary = generatedCanary("system prompt tail", value);
    const sources = [{ sourceRef: "kb-1", lastSeenAt: "2026-01-01T00:00:00Z", contents: [`...text ${value} more text...`] }];
    const result = computeCoverage(sources, [canary]);
    assert.equal(result.totalSources, 1);
    assert.equal(result.coveredSources, 1);
    assert.equal(result.pct, 100);
    assert.deepEqual(result.staleSources, []);
  });

  test("text that merely looks like a canary but doesn't hash-match is NOT covered", () => {
    // Same shape (matches CANARY_PATTERN), different value — proves matching is
    // by hash, not by pattern alone, same discipline real canary detection uses.
    assert.match("argus-cnry-someOtherValue123", CANARY_PATTERN);
    const canary = generatedCanary("real one", "argus-cnry-abc123XYZ_-");
    const sources = [{ sourceRef: "kb-1", lastSeenAt: "2026-01-01T00:00:00Z", contents: ["argus-cnry-someOtherValue123"] }];
    const result = computeCoverage(sources, [canary]);
    assert.equal(result.coveredSources, 0);
  });

  test("a custom canary matches by substring", () => {
    const canary = customCanary("decoy record", "SSN-DECOY-990-11-2222");
    const sources = [{ sourceRef: "kb-1", lastSeenAt: "2026-01-01T00:00:00Z", contents: ["...contains SSN-DECOY-990-11-2222 inline..."] }];
    const result = computeCoverage(sources, [canary]);
    assert.equal(result.coveredSources, 1);
  });

  test("a source with no matching canary anywhere in its samples is stale", () => {
    const canary = generatedCanary("planted elsewhere", "argus-cnry-somewhereElse123");
    const sources = [{ sourceRef: "kb-uncovered", lastSeenAt: "2026-01-02T00:00:00Z", contents: ["plain retrieved text, nothing planted"] }];
    const result = computeCoverage(sources, [canary]);
    assert.equal(result.coveredSources, 0);
    assert.equal(result.pct, 0);
    assert.equal(result.staleSources.length, 1);
    assert.equal(result.staleSources[0].sourceRef, "kb-uncovered");
  });

  test("stale sources sort most-recently-active first", () => {
    const sources = [
      { sourceRef: "old", lastSeenAt: "2026-01-01T00:00:00Z", contents: ["nothing"] },
      { sourceRef: "recent", lastSeenAt: "2026-01-10T00:00:00Z", contents: ["nothing"] },
    ];
    const result = computeCoverage(sources, []);
    assert.deepEqual(result.staleSources.map((s) => s.sourceRef), ["recent", "old"]);
  });

  test("no sources at all yields pct: null, not a fabricated 0 or 100", () => {
    const result = computeCoverage([], [generatedCanary("x", "argus-cnry-x")]);
    assert.equal(result.totalSources, 0);
    assert.equal(result.pct, null);
  });

  test("no active canaries at all means every source is stale", () => {
    const sources = [{ sourceRef: "kb-1", lastSeenAt: "2026-01-01T00:00:00Z", contents: ["some retrieved text"] }];
    const result = computeCoverage(sources, []);
    assert.equal(result.coveredSources, 0);
    assert.equal(result.pct, 0);
  });

  test("matchedCanaryLabel names which canary covered a source, and is absent when uncovered", () => {
    const value = "argus-cnry-labelCheck123";
    const canary = generatedCanary("kb ingestion tail", value);
    const sources = [
      { sourceRef: "kb-covered", lastSeenAt: "2026-01-01T00:00:00Z", contents: [value] },
      { sourceRef: "kb-uncovered", lastSeenAt: "2026-01-01T00:00:00Z", contents: ["nothing planted here"] },
    ];
    const result = computeCoverage(sources, [canary]);
    const covered = result.sources.find((s) => s.sourceRef === "kb-covered")!;
    const uncovered = result.sources.find((s) => s.sourceRef === "kb-uncovered")!;
    assert.equal(covered.matchedCanaryLabel, "kb ingestion tail");
    assert.equal(uncovered.matchedCanaryLabel, undefined);
  });
});
