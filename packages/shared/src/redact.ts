/**
 * Content redaction applied at ingest, before anything is stored. Two modes:
 *
 *  - mask_pii: replace common PII (emails, cards, SSNs, phones, IPs, keys/tokens)
 *    with typed placeholders. Injection payloads ("ignore previous instructions",
 *    exfil URLs) are NOT PII, so they survive — detection still works on masked text.
 *  - drop_content: blank the text entirely. Maximum privacy; note this also blinds
 *    the detectors, which have nothing left to scan.
 *
 * Order matters: card/SSN/IP patterns run before the looser phone pattern so a
 * card number isn't half-eaten as a phone number first.
 */
import type { RedactionMode } from "./settings.js";

const PATTERNS: Array<[RegExp, string]> = [
  [/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g, "[EMAIL]"],
  [/\b(?:sk|pk|ak|rk|api)[-_][A-Za-z0-9\-_]{12,}\b/gi, "[KEY]"],
  [/\bBearer\s+[A-Za-z0-9._\-]+/gi, "Bearer [TOKEN]"],
  [/\b(?:\d[ -]?){13,19}\b/g, "[CARD]"],
  [/\b\d{3}-\d{2}-\d{4}\b/g, "[SSN]"],
  [/\b(?:\d{1,3}\.){3}\d{1,3}\b/g, "[IP]"],
  [/\b\+?\d[\d ()\-.]{8,}\d\b/g, "[PHONE]"],
];

export function maskPII(text: string): string {
  let out = text;
  for (const [re, repl] of PATTERNS) out = out.replace(re, repl);
  return out;
}

/** Apply a redaction mode to one string. `off` is the identity. */
export function redactText(text: string | undefined, mode: RedactionMode): string | undefined {
  if (!text || mode === "off") return text;
  if (mode === "drop_content") return "[REDACTED]";
  return maskPII(text);
}

/**
 * Redact the free-text fields of an observation in place-safe fashion (returns a
 * shallow clone). Only `input`/`output` carry model/tool/user content; ids,
 * types, timings, and token counts are left untouched.
 */
export function redactObservation<T extends { input?: string; output?: string }>(
  obs: T,
  mode: RedactionMode,
): T {
  if (mode === "off") return obs;
  return { ...obs, input: redactText(obs.input, mode), output: redactText(obs.output, mode) };
}
