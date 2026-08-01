import { z } from "zod";

/**
 * Canonical ingestion shapes. These mirror docs/05-data-model.md and the
 * detection service's Python models. The native batch endpoint accepts these
 * directly; the OTLP adapter normalizes spans into them.
 */

export const ObservationType = z.enum([
  "span",
  "generation",
  "retrieval",
  "tool",
  "event",
]);
export type ObservationType = z.infer<typeof ObservationType>;

export const TaintClass = z.enum([
  "system",
  "user",
  "untrusted_external",
  "model",
]);
export type TaintClass = z.infer<typeof TaintClass>;

export const ObservationInput = z.object({
  observationId: z.string(),
  traceId: z.string(),
  parentId: z.string().optional().default(""),
  type: ObservationType.default("span"),
  name: z.string().default(""),
  startTime: z.string(), // ISO-8601
  endTime: z.string().optional(),
  model: z.string().optional().default(""),
  provider: z.string().optional().default(""),
  role: z.string().optional().default(""),
  input: z.string().optional().default(""),
  output: z.string().optional().default(""),
  inputTokens: z.number().int().nonnegative().optional().default(0),
  outputTokens: z.number().int().nonnegative().optional().default(0),
  costUsd: z.number().nonnegative().optional().default(0),
  finishReason: z.string().optional().default(""),
  taint: TaintClass.optional(),
  taintSource: z.string().optional().default(""),
  attributes: z.record(z.string()).optional().default({}),
});
export type ObservationInput = z.infer<typeof ObservationInput>;

export const TraceInput = z.object({
  traceId: z.string(),
  name: z.string().default(""),
  sessionId: z.string().optional().default(""),
  userId: z.string().optional().default(""),
  timestamp: z.string(), // ISO-8601
  environment: z.string().optional().default("default"),
  release: z.string().optional().default(""),
  metadata: z.record(z.string()).optional().default({}),
  tags: z.array(z.string()).optional().default([]),
});
export type TraceInput = z.infer<typeof TraceInput>;

export const IngestBatch = z.object({
  traces: z.array(TraceInput).optional().default([]),
  observations: z.array(ObservationInput).optional().default([]),
});
export type IngestBatch = z.infer<typeof IngestBatch>;

/**
 * One Browser Guard report. The extension scans a prompt locally and sends the
 * VERDICT ONLY — which rules fired, how bad, on which site. Prompt text never
 * leaves the browser, so there is deliberately no content field here and adding
 * one later would break the promise the extension makes to its users.
 */
export const PromptEvent = z.object({
  provider: z.string().max(200).default("unknown"),
  channel: z.string().max(50).default("fetch"),
  severity: z.enum(["ok", "info", "low", "medium", "high", "critical"]).default("ok"),
  finding_count: z.number().int().min(0).max(100).default(0),
  rule_ids: z.array(z.string().max(60)).max(50).default([]),
  /** Client clock, advisory only — the server stamps its own time. */
  at: z.string().max(40).optional(),
});
export type PromptEvent = z.infer<typeof PromptEvent>;

export const PromptEventBatch = z.object({
  events: z.array(PromptEvent).max(200),
});
export type PromptEventBatch = z.infer<typeof PromptEventBatch>;

/** Envelope pushed onto the Redis stream, tagged with the authenticated project. */
export interface StreamEvent {
  projectId: string;
  /** 'finding' carries pre-computed findings from a client that did its own
   *  scanning; the worker persists them rather than scanning for them. */
  kind: "trace" | "observation" | "finding";
  payload: TraceInput | ObservationInput | Finding[];
}

/** Detection service response shapes (subset we consume). */
export interface Finding {
  observation_id: string;
  trace_id: string;
  category: string;
  severity: "info" | "low" | "medium" | "high" | "critical";
  outcome: "unknown" | "attempted" | "succeeded" | "blocked";
  score: number;
  l1_rules: string[];
  l2_scores: Record<string, number>;
  l3_verdict: string;
  l4_signals: string[];
  evidence_excerpt: string;
  /** Set when this is a canary finding — lets the worker stamp the canary as
   *  triggered without re-deriving which one matched. */
  canary_id?: string;
  /** Provenance. Omitted means 'server': the pipeline scanned content Argus
   *  holds, so the finding can be re-derived from the trace. 'browser_extension'
   *  means a client asserted it after scanning locally — there is no content to
   *  re-check, which an analyst triaging it needs to know. */
  source?: "server" | "browser_extension";
}
