import type { ObservationInput, TaintClass } from "@argus/shared";

/**
 * Lightweight taint inference for storage/UI (mirrors the detection service's
 * taint.py). The detection service remains the source of truth for security
 * decisions; this just labels stored observations so the trace view can tint
 * untrusted spans without a round-trip.
 */
export function inferTaint(
  obs: ObservationInput,
  toolOverrides: Record<string, string> = {},
): TaintClass {
  if (obs.taint) return obs.taint;
  if (obs.type === "retrieval" || obs.type === "tool") {
    const key = obs.taintSource || obs.name;
    if (toolOverrides[key] === "trusted" || toolOverrides[obs.name] === "trusted")
      return "system";
    return "untrusted_external";
  }
  const role = (obs.role || "").toLowerCase();
  if (role === "system") return "system";
  if (role === "user") return "user";
  if (role === "assistant" || role === "model") return "model";
  if (obs.type === "generation") return "model";
  return "user";
}
