/**
 * The query DSL + compiler for the natural-language query copilot
 * (docs/15 §6, phase 1 — "ship the QueryIntent schema and deterministic
 * compiler first, exercised by hand-written intents (no LLM yet) — this
 * proves the compiler is safe before anything untrusted touches it").
 *
 * The one rule that matters more than any other in this file: **a QueryIntent
 * never becomes raw SQL.** The "compiler" doesn't generate a query string at
 * all — it validates the intent against a closed schema and then dispatches
 * to the *already-existing, already-parameterized, already-tested* list
 * functions in publicApi.ts (listTraces / listSecurityEvents), unmodified.
 * If a future caller feeds this module something an LLM produced from a
 * user's question, the worst case is "rejected: not a recognized filter" —
 * never "here is a query that runs".
 *
 * This is purely additive: publicApi.ts is imported, not changed, and this
 * module isn't wired to any HTTP route yet (that's the point where an NL
 * front-end would eventually attach — a separate, later step).
 */
import {
  CATEGORIES,
  OUTCOMES,
  SEVERITIES,
  VERDICTS,
  listSecurityEvents,
  listTraces,
  type Page,
} from "./publicApi.js";

// ---------------------------------------------------------------- schema
//
// Deliberately small and closed. Adding a new entity or filter means editing
// this file and its tests, not widening what a caller can express implicitly.
// "assessment_finding" is a deliberate omission for this phase: it lives in
// Postgres via a differently-shaped list function (limit-only, no cursor,
// ordered by observed_in_production) rather than ClickHouse's cursor-paginated
// shape, and forcing false uniformity onto it now would be exactly the kind
// of premature abstraction this codebase avoids elsewhere. Add it once this
// proves out, as its own reviewed increment.

export type QueryEntity = "trace" | "security_event";

const ENTITIES: ReadonlySet<QueryEntity> = new Set(["trace", "security_event"]);

export interface QueryFilters {
  category?: string;
  severity?: string;
  outcome?: string;
  verdict?: string;
}

export interface QueryIntent {
  entity: QueryEntity;
  filters: QueryFilters;
  since?: string;
  until?: string;
  limit?: number;
  cursor?: string;
}

// Which filter keys are even meaningful for a given entity. `trace` has none
// today — listTraces takes no category/severity/outcome/verdict — so an
// intent naming one is a validation error, not a silently-ignored no-op; the
// same "an unknown filter value returns 400, not an empty page" discipline
// publicApi.ts already holds for its own callers.
const ENTITY_FILTER_KEYS: Record<QueryEntity, ReadonlySet<keyof QueryFilters>> = {
  trace: new Set([]),
  security_event: new Set(["category", "severity", "outcome", "verdict"]),
};

// Reuses publicApi.ts's own enum sets rather than restating them — one
// definition of "what counts as a valid category", same drift concern this
// codebase names explicitly elsewhere (docs/14: "duplicated logic as a
// drift risk (taint.py / taint.ts)").
const FILTER_VALUE_SETS: Record<keyof QueryFilters, ReadonlySet<string>> = {
  category: CATEGORIES,
  severity: SEVERITIES,
  outcome: OUTCOMES,
  verdict: VERDICTS,
};

// ---------------------------------------------------------------- validation

export type ValidationResult =
  | { ok: true; intent: QueryIntent }
  | { ok: false; errors: string[] };

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function isValidTimestamp(v: unknown): v is string {
  return typeof v === "string" && v.length > 0 && !Number.isNaN(Date.parse(v));
}

/**
 * Validates an arbitrary value (e.g. parsed JSON from a request body, or an
 * LLM's structured output) against the closed QueryIntent schema. Every
 * rejection is collected, not just the first — a caller building an intent
 * programmatically (or an LLM retrying) benefits from seeing every problem at
 * once rather than fixing one field per round trip.
 */
export function validateQueryIntent(raw: unknown): ValidationResult {
  const errors: string[] = [];

  if (!isPlainObject(raw)) {
    return { ok: false, errors: ["a query intent must be a plain object"] };
  }

  const entityRaw = raw.entity;
  const entityValid = typeof entityRaw === "string" && ENTITIES.has(entityRaw as QueryEntity);
  if (!entityValid) {
    errors.push(`entity must be one of: ${[...ENTITIES].join(", ")} (got ${JSON.stringify(entityRaw)})`);
  }
  const entity = entityValid ? (entityRaw as QueryEntity) : undefined;

  const filters: QueryFilters = {};
  if (raw.filters !== undefined) {
    if (!isPlainObject(raw.filters)) {
      errors.push("filters must be an object");
    } else {
      const allowedKeys = entity ? ENTITY_FILTER_KEYS[entity] : new Set<keyof QueryFilters>();
      for (const [key, value] of Object.entries(raw.filters)) {
        if (!allowedKeys.has(key as keyof QueryFilters)) {
          errors.push(
            entity
              ? `filter '${key}' is not valid for entity '${entity}'`
              : `filter '${key}' cannot be validated without a valid entity`,
          );
          continue;
        }
        if (typeof value !== "string") {
          errors.push(`filter '${key}' must be a string (got ${JSON.stringify(value)})`);
          continue;
        }
        const validValues = FILTER_VALUE_SETS[key as keyof QueryFilters];
        if (!validValues.has(value)) {
          errors.push(`filter '${key}=${value}' is not a recognized value`);
          continue;
        }
        filters[key as keyof QueryFilters] = value;
      }
    }
  }

  let since: string | undefined;
  if (raw.since !== undefined) {
    if (!isValidTimestamp(raw.since)) errors.push(`since must be a parseable timestamp (got ${JSON.stringify(raw.since)})`);
    else since = raw.since;
  }

  let until: string | undefined;
  if (raw.until !== undefined) {
    if (!isValidTimestamp(raw.until)) errors.push(`until must be a parseable timestamp (got ${JSON.stringify(raw.until)})`);
    else until = raw.until;
  }
  if (since && until && Date.parse(since) >= Date.parse(until)) {
    errors.push("since must be before until");
  }

  let limit: number | undefined;
  if (raw.limit !== undefined) {
    const n = raw.limit;
    if (typeof n !== "number" || !Number.isFinite(n) || n <= 0 || !Number.isInteger(n)) {
      errors.push(`limit must be a positive integer (got ${JSON.stringify(n)})`);
    } else {
      limit = n; // the upper bound (1000) is still enforced downstream by publicApi's own clamp
    }
  }

  let cursor: string | undefined;
  if (raw.cursor !== undefined) {
    if (typeof raw.cursor !== "string" || !raw.cursor) errors.push("cursor must be a non-empty string");
    else cursor = raw.cursor;
  }

  if (errors.length > 0 || !entity) return { ok: false, errors };
  return { ok: true, intent: { entity, filters, since, until, limit, cursor } };
}

// ---------------------------------------------------------------- transparency
//
// "Always show the compiled query, never just the answer" (docs/15 §6) — an
// analyst trusting a security finding needs to see what was actually asked,
// the same transparency principle risk.py's stored rationale already follows.

export function describeIntent(intent: QueryIntent): string {
  const parts: string[] = [intent.entity];
  const filterParts = Object.entries(intent.filters)
    .filter((e): e is [string, string] => e[1] !== undefined)
    .map(([k, v]) => `${k}=${v}`);
  if (filterParts.length) parts.push(`where ${filterParts.join(" and ")}`);
  if (intent.since) parts.push(`since ${intent.since}`);
  if (intent.until) parts.push(`until ${intent.until}`);
  if (intent.cursor) parts.push("continuing from a cursor");
  parts.push(`limit ${intent.limit ?? 100}`);
  return parts.join(", ");
}

// ---------------------------------------------------------------- compile + run
//
// Not exercised by unit tests below: this is the thin I/O edge (it calls
// listTraces/listSecurityEvents, which touch ClickHouse), same split as
// canaryCoverage.ts's fetch/orchestrator functions. It belongs in the
// integration suite once this is wired to a route.

export interface QueryOutcome {
  intent: QueryIntent;
  compiledQuerySummary: string;
  page: Page<Record<string, unknown>>;
}

export type RunResult = { ok: true; outcome: QueryOutcome } | { ok: false; errors: string[] };

/**
 * Validates `rawIntent`, then dispatches it to the one existing, audited list
 * function for its entity. There is no third path — an entity that validation
 * accepted always maps to exactly one already-existing function call below.
 */
export async function runQueryIntent(projectId: string, rawIntent: unknown): Promise<RunResult> {
  const validated = validateQueryIntent(rawIntent);
  if (!validated.ok) return validated;
  const { intent } = validated;
  const opts = { since: intent.since, until: intent.until, limit: intent.limit, cursor: intent.cursor };

  const page =
    intent.entity === "trace"
      ? await listTraces(projectId, opts)
      : await listSecurityEvents(projectId, { ...opts, ...intent.filters });

  return { ok: true, outcome: { intent, compiledQuerySummary: describeIntent(intent), page } };
}
