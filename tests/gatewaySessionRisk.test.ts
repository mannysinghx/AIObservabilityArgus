/**
 * Unit tests for the pure core of apps/gateway/src/sessionRisk.ts
 * (docs/15 §3, phase 1 — observe-only session risk tracking).
 *
 * Only accumulate/assess/describeAssessment are covered — pure functions, no
 * Redis. loadSessionRiskState/recordSessionRiskEvent touch redis() and
 * belong in the integration suite once this is wired to the gateway's
 * request path, same split as canaryCoverage.ts and queryIntent.ts.
 */
import { test, describe } from "node:test";
import assert from "node:assert/strict";
import {
  accumulate,
  assess,
  describeAssessment,
  DEFAULT_SESSION_RISK_CONFIG,
  type SessionRiskState,
} from "../apps/gateway/src/sessionRisk.js";

const T0 = "2026-01-01T00:00:00.000Z";
const addMinutes = (iso: string, m: number) => new Date(new Date(iso).getTime() + m * 60_000).toISOString();

describe("accumulate", () => {
  test("first event with no prior state starts the cumulative score at that event's score", () => {
    const state = accumulate(null, "s1", { score: 40, timestamp: T0 });
    assert.equal(state.cumulativeScore, 40);
    assert.equal(state.eventCount, 1);
    assert.equal(state.sessionId, "s1");
  });

  test("a second event at the same instant adds without decay", () => {
    const first = accumulate(null, "s1", { score: 40, timestamp: T0 });
    const second = accumulate(first, "s1", { score: 30, timestamp: T0 });
    assert.equal(second.cumulativeScore, 70);
    assert.equal(second.eventCount, 2);
  });

  test("a second event a full half-life later roughly halves the prior contribution", () => {
    const first = accumulate(null, "s1", { score: 100, timestamp: T0 }, { threshold: 150, halfLifeMs: 60_000 });
    const later = addMinutes(T0, 1); // exactly one half-life (60_000ms) later
    const second = accumulate(first, "s1", { score: 0, timestamp: later }, { threshold: 150, halfLifeMs: 60_000 });
    assert.ok(Math.abs(second.cumulativeScore - 50) < 0.01, `expected ~50, got ${second.cumulativeScore}`);
  });

  test("an event long after the half-life leaves the prior contribution negligible", () => {
    const first = accumulate(null, "s1", { score: 100, timestamp: T0 }, { threshold: 150, halfLifeMs: 60_000 });
    const muchLater = addMinutes(T0, 60); // 60 half-lives later
    const second = accumulate(first, "s1", { score: 5, timestamp: muchLater }, { threshold: 150, halfLifeMs: 60_000 });
    assert.ok(second.cumulativeScore < 5.01 && second.cumulativeScore >= 5, `expected ~5, got ${second.cumulativeScore}`);
  });

  test("an out-of-order event (timestamp not after the prior one) does not decay the prior score", () => {
    const first = accumulate(null, "s1", { score: 100, timestamp: T0 }, { threshold: 150, halfLifeMs: 60_000 });
    const earlier = addMinutes(T0, -5);
    const second = accumulate(first, "s1", { score: 10, timestamp: earlier }, { threshold: 150, halfLifeMs: 60_000 });
    // No decay applied (elapsed <= 0), so the full 100 carries forward plus the new 10.
    assert.equal(second.cumulativeScore, 110);
  });

  test("scores are clamped to [0, 100] before accumulating", () => {
    const over = accumulate(null, "s1", { score: 250, timestamp: T0 });
    assert.equal(over.cumulativeScore, 100);
    const under = accumulate(null, "s2", { score: -30, timestamp: T0 });
    assert.equal(under.cumulativeScore, 0);
    const nan = accumulate(null, "s3", { score: Number.NaN, timestamp: T0 });
    assert.equal(nan.cumulativeScore, 0);
  });

  test("eventCount increments across a realistic multi-event session", () => {
    let state: SessionRiskState | null = null;
    for (let i = 0; i < 5; i++) {
      state = accumulate(state, "s1", { score: 20, timestamp: addMinutes(T0, i) });
    }
    assert.equal(state!.eventCount, 5);
  });
});

describe("assess", () => {
  test("below threshold does not trip", () => {
    const state = accumulate(null, "s1", { score: 50, timestamp: T0 });
    const result = assess(state, { threshold: 150, halfLifeMs: 60_000 });
    assert.equal(result.wouldTrip, false);
  });

  test("at or above threshold trips", () => {
    const state = accumulate(null, "s1", { score: 100, timestamp: T0 });
    const exact = assess(state, { threshold: 100, halfLifeMs: 60_000 });
    assert.equal(exact.wouldTrip, true);
    const over = assess(state, { threshold: 99, halfLifeMs: 60_000 });
    assert.equal(over.wouldTrip, true);
  });

  test("a sustained low-grade pattern can cross the default threshold even though no single message would", () => {
    // Five messages each scoring 40 (well under any reasonable single-message
    // block threshold — gateway.ts's own default is 75) still build a pattern.
    let state: SessionRiskState | null = null;
    for (let i = 0; i < 5; i++) {
      state = accumulate(state, "s1", { score: 40, timestamp: addMinutes(T0, i) }, DEFAULT_SESSION_RISK_CONFIG);
    }
    const result = assess(state!, DEFAULT_SESSION_RISK_CONFIG);
    assert.equal(result.wouldTrip, true);
  });

  test("uses DEFAULT_SESSION_RISK_CONFIG when no config is passed", () => {
    const state = accumulate(null, "s1", { score: 200, timestamp: T0 }); // clamps to 100, still under default 150
    const result = assess(state);
    assert.equal(result.threshold, DEFAULT_SESSION_RISK_CONFIG.threshold);
    assert.equal(result.wouldTrip, false);
  });
});

describe("describeAssessment", () => {
  test("names the observe-only nature of a trip", () => {
    const state = accumulate(null, "s1", { score: 100, timestamp: T0 });
    const summary = describeAssessment(assess(state, { threshold: 50, halfLifeMs: 60_000 }));
    assert.match(summary, /WOULD TRIP \(observe-only — not enforced\)/);
    assert.match(summary, /session s1/);
  });

  test("reads as within threshold when it hasn't tripped", () => {
    const state = accumulate(null, "s1", { score: 10, timestamp: T0 });
    const summary = describeAssessment(assess(state, { threshold: 150, halfLifeMs: 60_000 }));
    assert.match(summary, /within threshold/);
  });
});
