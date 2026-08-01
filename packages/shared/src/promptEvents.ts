/**
 * Browser Guard reports → Argus traces, observations and findings.
 *
 * The extension watches someone using ChatGPT, Claude, Gemini and friends, scans
 * what they are about to send *in the browser*, and reports the verdict. Prompt
 * text never leaves the machine — that is the promise the extension makes, and
 * it is why these events carry no content.
 *
 * Mapping them onto the normal data model rather than giving them a private
 * table is what makes them useful: they land in Threat Center, Traces and
 * Analytics, inherit per-project retention and scoping, and go through the same
 * alerting and suppression as everything else. The absence of content is
 * already a supported state (a project with redaction set to `drop_content`
 * stores exactly the same shape), so nothing downstream needs special cases.
 *
 * What they are NOT is server-verified. Every finding produced here carries
 * `source: "browser_extension"` so an analyst can tell an assertion from a
 * detection Argus can re-derive.
 */
import { randomUUID } from "node:crypto";
import { ObservationInput, TraceInput } from "./types.js";
import type { Finding, PromptEvent } from "./types.js";

/**
 * Extension rule → Argus category.
 *
 * The extension names weaknesses in what a person is about to paste; Argus's
 * taxonomy names attack classes. Same translation problem the assessment
 * engine's taxonomy.ts solves, and the same rule: never invent a category —
 * an unmapped rule is dropped rather than guessed at, so a new extension rule
 * shipping ahead of the server cannot silently pollute the data.
 */
export const EXTENSION_RULE_CATEGORY: Record<string, string> = {
  // A credential pasted into a third-party chat app is that credential leaving
  // the organization, which is what pii_egress covers.
  "IG-SECRET-001": "pii_egress",
  "IG-PII-001": "pii_egress",
  "IG-INJECT-001": "direct_injection",
  "IG-EXFIL-001": "exfiltration",
  "IG-INDIRECT-001": "indirect_injection",
  "IG-ENCODE-001": "obfuscation",
};

type Sev = Finding["severity"];
const SEVERITIES: Sev[] = ["info", "low", "medium", "high", "critical"];
/** Indicative score per severity band. The extension's rules are exact-match
 *  patterns (a Luhn-valid card number, an `sk-` key), so confidence is high and
 *  these sit near the top of each band. */
const SCORE: Record<Sev, number> = { info: 10, low: 30, medium: 55, high: 78, critical: 92 };

const asSeverity = (s: string): Sev | null =>
  (SEVERITIES as string[]).includes(s) ? (s as Sev) : null;

/** Strip anything that isn't a plain hostname before it becomes a span name. */
const safeProvider = (p: string): string =>
  (p || "unknown").replace(/[^a-zA-Z0-9._:-]/g, "").slice(0, 100) || "unknown";

export interface MappedPromptEvent {
  trace: TraceInput;
  observation: ObservationInput;
  findings: Finding[];
}

/**
 * Map one report. Returns null for a clean prompt: the extension reports every
 * scan so its popup can show "247 checked, 3 risky", but storing a row per
 * keystroke-free prompt would swamp the trace store to record that nothing
 * happened. Counts belong in the popup; Argus stores the events that matter.
 */
export function mapPromptEvent(ev: PromptEvent, now = new Date()): MappedPromptEvent | null {
  const severity = asSeverity(ev.severity);
  if (!severity || ev.finding_count <= 0) return null;

  const provider = safeProvider(ev.provider);
  const traceId = `bg-${randomUUID()}`;
  const observationId = `bg-${randomUUID()}`;
  const ts = now.toISOString();

  // Built through the schemas rather than cast into them: the same defaults and
  // validation every other ingestion path gets, so a mapping mistake here fails
  // at the boundary instead of becoming a malformed row.
  const trace = TraceInput.parse({
    traceId,
    name: provider,
    timestamp: ts,
    // A distinct environment so extension traffic is one filter away from being
    // included or excluded, and never silently mixed into an app's production
    // numbers.
    environment: "browser-extension",
    metadata: { channel: ev.channel, provider },
    tags: ["browser-extension", provider],
  });

  const observation = ObservationInput.parse({
    traceId,
    observationId,
    type: "generation",
    name: provider,
    startTime: ts,
    endTime: ts,
    // No content, by design. See the module header.
    input: "",
    output: "",
    // The person typing is the source, and the extension sees the prompt before
    // the model does — the same reasoning the gateway uses for its own spans.
    taint: "user",
    attributes: { "argus.source": "browser_extension", "argus.provider": provider },
  });

  // One finding per mapped rule. An event whose rules are all unmapped produces
  // no findings, and therefore no rows — see the drop-don't-guess note above.
  const findings: Finding[] = [];
  for (const ruleId of ev.rule_ids) {
    const category = EXTENSION_RULE_CATEGORY[ruleId];
    if (!category) continue;
    findings.push({
      observation_id: observationId,
      trace_id: traceId,
      category,
      severity,
      // The extension warns before the prompt is sent and cannot know whether
      // the person went ahead, so claiming "succeeded" would be a fabrication
      // and "blocked" would be worse. Attempted is what was actually observed.
      outcome: "attempted",
      score: SCORE[severity],
      l1_rules: [ruleId],
      l2_scores: {},
      l3_verdict: "",
      l4_signals: [],
      // No excerpt: the extension never sends the text, and inventing one would
      // undo the reason it doesn't.
      evidence_excerpt: "",
      source: "browser_extension",
    });
  }
  if (findings.length === 0) return null;

  return { trace, observation, findings };
}
