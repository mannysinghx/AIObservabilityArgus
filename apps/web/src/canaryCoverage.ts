/**
 * Canary coverage reporting (docs/15 §4, phase 1 — "of all distinct retrieval
 * sources seen recently, what fraction have a live canary in them?").
 *
 * Canaries are, by design, the platform's one detector with no false-positive
 * story (see canaries.ts: "no benign explanation, which is why this is the
 * one signal that justifies waking someone at 3am"). This module doesn't
 * change what a canary is or how a hit is detected — it only answers a
 * question nothing today can answer: which retrieval sources actually have
 * one planted, and which don't.
 *
 * Read-only. No new tables, no new writes, no route wired to this yet — this
 * is the engine (docs/15's phase-1 scope: "ships value with zero new write
 * paths"). It's purely additive: nothing existing imports this module, and
 * this module only *consumes* existing exports (loadCanaries, CANARY_PATTERN,
 * hashCanary, ch, safeProjectId) without modifying any of them.
 *
 * Simplification worth being explicit about: "coverage" here means the
 * canary text appears anywhere in a source's recently-observed content, not
 * within a specific token window of a specific chunk boundary (the original
 * proposal's "within X tokens"). Token-windowed matching needs a tokenizer
 * and chunk boundaries this phase doesn't have; this is a coarser, honestly-
 * labeled first cut, not a hidden approximation of the fuller feature.
 */
import { ch, hashCanary, loadCanaries, CANARY_PATTERN, type CanaryRef } from "@argus/shared";
import { safeProjectId } from "./ids.js";

// ---------------------------------------------------------------- fetch

export interface RawRetrievalSample {
  sourceRef: string;
  observedAt: string;
  content: string;
}

// Bounds on what a single coverage query can cost: a large project's
// retrieval traffic must not turn this into an unbounded table scan every
// time someone opens the report.
const MAX_SAMPLE_ROWS = 5000;
const MAX_CONTENT_CHARS = 20_000;

/**
 * Recent retrieval-type observations for a project, newest first. `sourceRef`
 * mirrors the identity taint.py already uses for tool/retrieval overrides
 * (`taint_source` if the SDK set it, else `name`) — one definition of "which
 * source is this" shared with the taint classifier rather than a second one
 * invented here.
 */
export async function fetchRetrievalSamples(
  projectId: string,
  days = 30,
): Promise<RawRetrievalSample[]> {
  const safe = safeProjectId(projectId);
  if (!safe) return [];
  const windowDays = Math.max(1, Math.floor(days) || 30);
  const rs = await ch().query({
    query: `
      SELECT
        if(taint_source != '', taint_source, name) AS source_ref,
        start_time AS observed_at,
        substring(if(output_full != '', output_full, output_preview), 1, ${MAX_CONTENT_CHARS}) AS content
      FROM observations FINAL
      WHERE project_id = '${safe}'
        AND type = 'retrieval'
        AND start_time >= now() - INTERVAL ${windowDays} DAY
      ORDER BY start_time DESC
      LIMIT ${MAX_SAMPLE_ROWS}
    `,
    format: "JSONEachRow",
  });
  const rows = await rs.json<{ source_ref: string; observed_at: string; content: string }>();
  return rows
    .filter((r) => r.source_ref)
    .map((r) => ({ sourceRef: r.source_ref, observedAt: r.observed_at, content: r.content }));
}

// ---------------------------------------------------------------- pure logic

export interface SourceSamples {
  sourceRef: string;
  lastSeenAt: string;
  contents: string[];
}

/**
 * Groups raw rows by source, keeping the true most-recent `lastSeenAt` per
 * source regardless of input order, and up to `maxSamplesPerSource` content
 * samples. When the caller passes rows ordered newest-first (as
 * fetchRetrievalSamples does), the kept samples are also the most recent
 * ones — that ordering is the caller's responsibility, not assumed silently.
 */
export function groupSamplesBySource(
  rows: RawRetrievalSample[],
  maxSamplesPerSource = 3,
): SourceSamples[] {
  const bySource = new Map<string, { lastSeenAt: string; contents: string[] }>();
  for (const row of rows) {
    let entry = bySource.get(row.sourceRef);
    if (!entry) {
      entry = { lastSeenAt: row.observedAt, contents: [] };
      bySource.set(row.sourceRef, entry);
    } else if (new Date(row.observedAt).getTime() > new Date(entry.lastSeenAt).getTime()) {
      entry.lastSeenAt = row.observedAt;
    }
    if (entry.contents.length < maxSamplesPerSource) entry.contents.push(row.content);
  }
  return Array.from(bySource.entries()).map(([sourceRef, v]) => ({ sourceRef, ...v }));
}

export interface SourceCoverage {
  sourceRef: string;
  lastSeenAt: string;
  covered: boolean;
  matchedCanaryLabel?: string;
}

export interface CoverageResult {
  totalSources: number;
  coveredSources: number;
  /** 0-100, rounded. `null` when there are no retrieval sources at all — not
   *  applicable is not the same as fully covered, and reporting 100% for
   *  "nothing observed" would read as a false all-clear. */
  pct: number | null;
  /** Every source, covered or not — `matchedCanaryLabel` is set only when covered. */
  sources: SourceCoverage[];
  /** Uncovered sources, most-recently-active first — the actionable part. */
  staleSources: { sourceRef: string; lastSeenAt: string }[];
}

/** True if `content` contains a still-active canary — a generated one
 *  (matched by hash, the same discipline canary detection itself uses: the
 *  raw value is never compared, only its digest) or a custom one (matched by
 *  substring, the only option since a custom value has no derivable pattern). */
function findMatch(content: string, canaries: CanaryRef[]): CanaryRef | undefined {
  const generated = canaries.filter((c) => c.kind === "generated");
  if (generated.length) {
    const hashes = new Set(generated.map((c) => c.tokenHash));
    for (const candidate of content.match(CANARY_PATTERN) ?? []) {
      const hit = generated.find((c) => c.tokenHash === hashCanary(candidate));
      if (hit && hashes.has(hit.tokenHash)) return hit;
    }
  }
  return canaries.find((c) => c.kind === "custom" && c.value && content.includes(c.value));
}

export function computeCoverage(sources: SourceSamples[], canaries: CanaryRef[]): CoverageResult {
  const perSource: SourceCoverage[] = sources.map((s) => {
    const match = canaries.length
      ? s.contents.map((c) => findMatch(c, canaries)).find((m) => m)
      : undefined;
    return {
      sourceRef: s.sourceRef,
      lastSeenAt: s.lastSeenAt,
      covered: Boolean(match),
      matchedCanaryLabel: match?.label,
    };
  });

  const coveredSources = perSource.filter((s) => s.covered).length;
  const staleSources = perSource
    .filter((s) => !s.covered)
    .sort((a, b) => new Date(b.lastSeenAt).getTime() - new Date(a.lastSeenAt).getTime())
    .map(({ sourceRef, lastSeenAt }) => ({ sourceRef, lastSeenAt }));

  return {
    totalSources: perSource.length,
    coveredSources,
    pct: perSource.length ? Math.round((coveredSources / perSource.length) * 100) : null,
    sources: perSource,
    staleSources,
  };
}

// ---------------------------------------------------------------- orchestrator

/**
 * The full read: fetch recent retrieval sources + this project's active
 * canaries, and compute coverage. Not exposed through any route yet — a
 * caller (a future `GET /api/canaries/coverage`, or a script) wires this in
 * without this module needing to change.
 */
export async function getCanaryCoverage(projectId: string, days = 30): Promise<CoverageResult> {
  const [rows, canaries] = await Promise.all([
    fetchRetrievalSamples(projectId, days),
    loadCanaries(projectId),
  ]);
  return computeCoverage(groupSamplesBySource(rows), canaries);
}
