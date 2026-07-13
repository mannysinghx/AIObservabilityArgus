import type { ObservationInput, ObservationType, TaintClass } from "./types.js";

/**
 * OTLP → Argus normalization using OpenTelemetry GenAI semantic conventions.
 * We accept the OTLP/HTTP JSON encoding (a subset sufficient for GenAI spans)
 * and map `gen_ai.*` / `argus.*` attributes onto our observation model.
 *
 * Ref: https://opentelemetry.io/docs/specs/semconv/gen-ai/
 */

interface OtlpKeyValue {
  key: string;
  value?: {
    stringValue?: string;
    intValue?: string | number;
    doubleValue?: number;
    boolValue?: boolean;
  };
}

interface OtlpSpan {
  traceId: string;
  spanId: string;
  parentSpanId?: string;
  name?: string;
  startTimeUnixNano?: string | number;
  endTimeUnixNano?: string | number;
  attributes?: OtlpKeyValue[];
}

interface OtlpScopeSpans {
  spans?: OtlpSpan[];
}
interface OtlpResourceSpans {
  scopeSpans?: OtlpScopeSpans[];
}
export interface OtlpTracePayload {
  resourceSpans?: OtlpResourceSpans[];
}

function attrValue(v?: OtlpKeyValue["value"]): string {
  if (!v) return "";
  if (v.stringValue !== undefined) return v.stringValue;
  if (v.intValue !== undefined) return String(v.intValue);
  if (v.doubleValue !== undefined) return String(v.doubleValue);
  if (v.boolValue !== undefined) return String(v.boolValue);
  return "";
}

function nanoToIso(n?: string | number): string {
  if (n === undefined) return new Date().toISOString();
  const ms = Number(BigInt(n as string) / 1_000_000n);
  return new Date(ms).toISOString();
}

/** Infer observation type from GenAI operation name / span attributes. */
function inferType(attrs: Record<string, string>, name: string): ObservationType {
  const op = attrs["gen_ai.operation.name"] ?? "";
  if (op === "chat" || op === "text_completion" || op === "generate_content")
    return "generation";
  if (op === "embeddings") return "generation";
  if (attrs["gen_ai.tool.name"] || name.startsWith("tool")) return "tool";
  if (
    attrs["db.system"] ||
    attrs["gen_ai.retrieval.source"] ||
    name.includes("retriev")
  )
    return "retrieval";
  return "span";
}

export function otlpToObservations(payload: OtlpTracePayload): ObservationInput[] {
  const out: ObservationInput[] = [];
  for (const rs of payload.resourceSpans ?? []) {
    for (const ss of rs.scopeSpans ?? []) {
      for (const span of ss.spans ?? []) {
        const attrs: Record<string, string> = {};
        for (const kv of span.attributes ?? []) {
          attrs[kv.key] = attrValue(kv.value);
        }
        const type = inferType(attrs, span.name ?? "");
        const taint = (attrs["argus.taint"] as TaintClass) || undefined;
        out.push({
          observationId: span.spanId,
          traceId: span.traceId,
          parentId: span.parentSpanId ?? "",
          type,
          name: attrs["gen_ai.tool.name"] ?? span.name ?? "",
          startTime: nanoToIso(span.startTimeUnixNano),
          endTime: span.endTimeUnixNano ? nanoToIso(span.endTimeUnixNano) : undefined,
          model: attrs["gen_ai.request.model"] ?? attrs["gen_ai.response.model"] ?? "",
          provider: attrs["gen_ai.system"] ?? "",
          role: attrs["gen_ai.message.role"] ?? "",
          // Content: GenAI conventions keep prompt/completion in events/attrs;
          // we accept a pragmatic set of attribute keys for the text body.
          input:
            attrs["gen_ai.prompt"] ??
            attrs["gen_ai.input.messages"] ??
            attrs["argus.content"] ??
            "",
          output:
            attrs["gen_ai.completion"] ?? attrs["gen_ai.output.messages"] ?? "",
          inputTokens: Number(attrs["gen_ai.usage.input_tokens"] ?? 0),
          outputTokens: Number(attrs["gen_ai.usage.output_tokens"] ?? 0),
          costUsd: 0,
          finishReason: attrs["gen_ai.response.finish_reasons"] ?? "",
          taint,
          taintSource: attrs["argus.taint.source"] ?? "",
          attributes: attrs,
        });
      }
    }
  }
  return out;
}
