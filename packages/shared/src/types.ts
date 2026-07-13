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

/** Envelope pushed onto the Redis stream, tagged with the authenticated project. */
export interface StreamEvent {
  projectId: string;
  kind: "trace" | "observation";
  payload: TraceInput | ObservationInput;
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
}
