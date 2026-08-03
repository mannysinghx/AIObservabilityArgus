/**
 * Session-level risk tracking for the gateway (docs/15 §3, phase 1 —
 * "observe-only: compute and log cumulative session risk, no enforcement —
 * same 'start in observe' discipline the message-level gateway already
 * recommends operators follow").
 *
 * gateway.ts's evaluate() judges one message at a time, by design — its own
 * docstring is explicit that a stateless, single-message check is what makes
 * the gateway's fail-open/hard-latency-budget guarantees possible. This
 * module does not change that. It's an entirely separate, additive layer:
 * given a sequence of per-message scores for the same session, it tracks
 * how suspicious the *session as a whole* has been, with older contributions
 * decaying over time so a burst from an hour ago doesn't permanently flag a
 * session that's been clean since.
 *
 * THIS PHASE ENFORCES NOTHING. `wouldTrip` is exactly that — a hypothetical.
 * Nothing in this module blocks, delays, or modifies a request. It isn't
 * called from server.ts yet, so today it changes no runtime behavior at all;
 * wiring it in (still observe-only: log what *would* have tripped) is the
 * next increment, and actual enforcement — pausing a specific tool call for
 * human approval — is a later one still, per docs/15's own phasing and its
 * explicit flag that this is the first proposal able to add latency to a
 * legitimate production write.
 *
 * Purely additive: gateway.ts and server.ts are unmodified; this only
 * imports the existing redis() client from @argus/shared.
 */
import { redis } from "@argus/shared";

// ---------------------------------------------------------------- pure core

export interface SessionRiskEvent {
  /** This message's score, 0-100 — the same scale gateway.ts's ScanVerdict
   *  already uses, so a caller can feed evaluate()'s output straight in. */
  score: number;
  timestamp: string; // ISO
}

export interface SessionRiskState {
  sessionId: string;
  cumulativeScore: number;
  eventCount: number;
  updatedAt: string; // ISO — timestamp of the most recent event folded in
}

export interface SessionRiskConfig {
  /** Cumulative score at/above which the breaker would trip. Deliberately
   *  higher than a single message's max (100) — this is about a *pattern*
   *  across messages, not one bad message, which the per-message gateway
   *  already handles on its own. */
  threshold: number;
  /** Prior contributions decay with this half-life, so a suspicious burst
   *  long ago stops mattering rather than accumulating forever. */
  halfLifeMs: number;
}

export const DEFAULT_SESSION_RISK_CONFIG: SessionRiskConfig = {
  threshold: 150,
  halfLifeMs: 30 * 60 * 1000, // 30 minutes
};

function clampScore(n: number): number {
  if (!Number.isFinite(n)) return 0;
  return Math.max(0, Math.min(100, n));
}

function decayed(priorScore: number, priorTimestamp: string, now: string, halfLifeMs: number): number {
  const elapsedMs = new Date(now).getTime() - new Date(priorTimestamp).getTime();
  // A non-positive gap means the new event is not strictly after the state we
  // have (clock skew, replay, or same-millisecond arrival) — treat the prior
  // score as un-decayed rather than let a negative exponent inflate it.
  if (!(elapsedMs > 0)) return priorScore;
  return priorScore * Math.pow(0.5, elapsedMs / halfLifeMs);
}

/**
 * Folds one new event into a session's risk state. Pure — no I/O, safe to
 * unit test directly, and safe to call speculatively (e.g. "what would this
 * look like") without touching Redis.
 */
export function accumulate(
  prior: SessionRiskState | null,
  sessionId: string,
  event: SessionRiskEvent,
  config: SessionRiskConfig = DEFAULT_SESSION_RISK_CONFIG,
): SessionRiskState {
  const carried = prior ? decayed(prior.cumulativeScore, prior.updatedAt, event.timestamp, config.halfLifeMs) : 0;
  return {
    sessionId,
    cumulativeScore: carried + clampScore(event.score),
    eventCount: (prior?.eventCount ?? 0) + 1,
    updatedAt: event.timestamp,
  };
}

export interface BreakerAssessment {
  sessionId: string;
  cumulativeScore: number;
  threshold: number;
  eventCount: number;
  /** Hypothetical only in this phase — see the module docstring. */
  wouldTrip: boolean;
}

export function assess(
  state: SessionRiskState,
  config: SessionRiskConfig = DEFAULT_SESSION_RISK_CONFIG,
): BreakerAssessment {
  return {
    sessionId: state.sessionId,
    cumulativeScore: state.cumulativeScore,
    threshold: config.threshold,
    eventCount: state.eventCount,
    wouldTrip: state.cumulativeScore >= config.threshold,
  };
}

/** A log-line-ready summary — this phase's entire "enforcement" is that
 *  something reads this and writes it down, per docs/15's phase-1 scope. */
export function describeAssessment(a: BreakerAssessment): string {
  const status = a.wouldTrip ? "WOULD TRIP (observe-only — not enforced)" : "within threshold";
  return `session ${a.sessionId}: cumulative risk ${a.cumulativeScore.toFixed(1)}/${a.threshold} after ${a.eventCount} event(s) — ${status}`;
}

// ---------------------------------------------------------------- Redis adapter
//
// Not exercised by unit tests below (needs live Redis) — same split as
// canaryCoverage.ts's fetch functions and queryIntent.ts's runQueryIntent.
// Not called from server.ts yet either; wiring it into the request path is
// the next increment, still observe-only.

const REDIS_KEY_PREFIX = "argus:gateway:session-risk:";
// Long enough to span a realistic session, short enough that an abandoned
// session's state doesn't linger in Redis indefinitely.
const STATE_TTL_S = 2 * 60 * 60;

function redisKey(projectId: string, sessionId: string): string {
  return `${REDIS_KEY_PREFIX}${projectId}:${sessionId}`;
}

/**
 * Loads a session's prior risk state. Fails CLOSED to "no history" on any
 * Redis error — the same posture canaries.ts's loadCanaries() takes, and for
 * the same reason: a database blip must never *invent* state. Here that
 * means a blip can only ever under-count risk, never fabricate it.
 */
export async function loadSessionRiskState(
  projectId: string,
  sessionId: string,
): Promise<SessionRiskState | null> {
  try {
    const raw = await redis().get(redisKey(projectId, sessionId));
    return raw ? (JSON.parse(raw) as SessionRiskState) : null;
  } catch {
    return null;
  }
}

/**
 * Records one event and returns the resulting assessment. Never throws on a
 * Redis failure — an accounting failure here must not break whatever caller
 * eventually sits on the request path, the same "never throws" discipline
 * canaries.ts's markCanaryTriggered() already follows.
 */
export async function recordSessionRiskEvent(
  projectId: string,
  sessionId: string,
  event: SessionRiskEvent,
  config: SessionRiskConfig = DEFAULT_SESSION_RISK_CONFIG,
): Promise<BreakerAssessment> {
  const prior = await loadSessionRiskState(projectId, sessionId);
  const next = accumulate(prior, sessionId, event, config);
  try {
    await redis().set(redisKey(projectId, sessionId), JSON.stringify(next), "EX", STATE_TTL_S);
  } catch {
    /* best-effort persistence; the assessment below is still returned */
  }
  return assess(next, config);
}
