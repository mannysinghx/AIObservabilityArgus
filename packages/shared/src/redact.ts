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

// NOTE ON REGEX SHAPE: these run synchronously in the ingest request path, over
// text an attacker fully controls, so quantifiers are bounded on principle. To
// be clear about what that is and isn't buying: the previous patterns were
// *measured* against adversarial inputs (long digit runs, dense separators,
// failing suffixes) and did not backtrack pathologically — V8 handles them
// linearly. Bounding them is defence in depth against a future edit, not the
// repair of a live vulnerability.
//
// The substantive change is correctness. Card and phone were two overlapping
// patterns competing for the same digits, and whichever ran first won: a
// 13-digit phone number could be masked as [CARD], and the card pattern's
// optional separators would happily straddle two unrelated numbers. Matching a
// flat digit run once and classifying it by digit count in code decides the
// question in one place, and reads as what it means.
const DIGIT_RUN = /\b\d[\d ().-]{7,21}\d\b/g;

const PATTERNS: Array<[RegExp, string]> = [
  [/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g, "[EMAIL]"],
  [/\b(?:sk|pk|ak|rk|api)[-_][A-Za-z0-9\-_]{12,64}\b/gi, "[KEY]"],
  [/\bBearer\s+[A-Za-z0-9._\-]{1,512}/gi, "Bearer [TOKEN]"],
  [/\b\d{3}-\d{2}-\d{4}\b/g, "[SSN]"],
  [/\b(?:\d{1,3}\.){3}\d{1,3}\b/g, "[IP]"],
];

/** Above this, redaction is skipped and the content is dropped instead. A
 *  megabyte of prose is not a real prompt; it is either a bug or an attempt to
 *  make us spend CPU. Dropping is the safe direction — it cannot leak. */
const MAX_MASK_LENGTH = 512 * 1024;

/**
 * Replace card- and phone-shaped digit runs. One pass over flat digit runs,
 * classified by digit count: 13–19 digits is a card, 8–15 is a phone. Anything
 * else (order numbers, timestamps, long ids) is left alone.
 */
function maskDigitRuns(text: string): string {
  return text.replace(DIGIT_RUN, (match) => {
    const digits = match.replace(/\D/g, "").length;
    if (digits >= 13 && digits <= 19) return "[CARD]";
    if (digits >= 8 && digits <= 15) return "[PHONE]";
    return match;
  });
}

export function maskPII(text: string): string {
  if (text.length > MAX_MASK_LENGTH) return "[REDACTED: oversized content]";
  let out = text;
  for (const [re, repl] of PATTERNS) out = out.replace(re, repl);
  // Digit runs last: emails, keys and SSNs are already gone, so a run of digits
  // reaching here is genuinely a bare number rather than part of a token.
  return maskDigitRuns(out);
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
