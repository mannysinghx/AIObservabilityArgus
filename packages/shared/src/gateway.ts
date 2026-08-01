/**
 * Gateway mode: policy evaluation for the inline proxy.
 *
 * Everything else in Argus is off the critical path — it observes and reports,
 * and if it breaks, the customer's application is unaffected. The gateway is
 * the opposite: it sits between the app and the model provider, which makes
 * every property here a production-availability property rather than a
 * detection one.
 *
 * Three rules follow from that, and they are not negotiable:
 *
 *   1. FAIL OPEN, always, by default. If detection is slow, down, or throwing,
 *      the request goes through unscanned. A security tool that takes the
 *      customer's product offline when it has a bad day gets removed the same
 *      week, and then it protects nothing. Fail-closed exists, but as an
 *      explicit opt-in for people who have decided that trade themselves.
 *
 *   2. A hard latency budget. The scan races a deadline; whichever finishes
 *      first decides. Slow is treated exactly like down.
 *
 *   3. Blocking is a narrow, high-confidence action. Only direct injection and
 *      jailbreak on user input, only above a deliberately high threshold. This
 *      layer sees one message with no trace context, so it cannot judge the
 *      cross-span attacks that are Argus's actual speciality — pretending
 *      otherwise here would mean blocking real users to catch attacks this code
 *      is not equipped to see.
 */
import { config } from "./config.js";

export type GatewayMode = "observe" | "block";
export type FailureMode = "open" | "closed";

export interface GatewayPolicy {
  mode: GatewayMode;
  /** Score (0-100) at or above which a request is refused in block mode. */
  blockThreshold: number;
  /** Milliseconds detection gets before the request proceeds regardless. */
  latencyBudgetMs: number;
  /** What to do when detection is unavailable. */
  onFailure: FailureMode;
  /** Which finding categories may cause a block. Always a subset of BLOCKABLE;
   *  a project can narrow this but never widen it beyond what one message
   *  without trace context can honestly support. */
  blockCategories?: Set<string>;
}

export const DEFAULT_GATEWAY_POLICY: GatewayPolicy = {
  // Observe by default. Turning a new install into an inline blocker without
  // the operator explicitly asking is how you break someone's production.
  mode: "observe",

  // 75 is measured, not guessed. Against the labelled corpus
  // (services/detection/argus_detection/corpus/span_corpus.jsonl, 20 attacks
  // and 20 hard negatives — blog posts about injection, fiction quoting it,
  // support text that mentions previous instructions):
  //
  //     threshold | attacks blocked | benign wrongly blocked
  //        90     |      2/20       |        0/20
  //        85     |      4/20       |        0/20
  //        75     |      7/20       |        0/20
  //        70     |     10/20       |        0/20
  //
  // Every benign item scores 0.0, so the corpus alone would justify going far
  // lower. It doesn't justify it in production: 20 negatives is thin evidence,
  // and real traffic contains phrasings this corpus has never seen. 75 is the
  // point where at least two independent rules must fire — one heuristic is a
  // hint, two is a pattern — which is a principled line rather than a curve-fit
  // to a small sample.
  //
  // The asymmetry that sets this: a false block is a user who cannot use the
  // product, while a missed detection is still caught, recorded and alerted on
  // by the async pipeline seconds later. Those costs are nowhere near equal.
  blockThreshold: 75,

  latencyBudgetMs: 300,
  onFailure: "open",
};

export function gatewayPolicyFromEnv(): GatewayPolicy {
  const d = DEFAULT_GATEWAY_POLICY;
  const mode = process.env.GATEWAY_MODE === "block" ? "block" : "observe";
  const onFailure = process.env.GATEWAY_ON_FAILURE === "closed" ? "closed" : "open";
  const num = (v: string | undefined, fallback: number, lo: number, hi: number) => {
    const n = Number(v);
    return Number.isFinite(n) ? Math.min(hi, Math.max(lo, n)) : fallback;
  };
  return {
    mode,
    blockThreshold: num(process.env.GATEWAY_BLOCK_THRESHOLD, d.blockThreshold, 0, 100),
    latencyBudgetMs: num(process.env.GATEWAY_LATENCY_BUDGET_MS, d.latencyBudgetMs, 10, 5000),
    onFailure,
  };
}

/** Categories a single message, with no trace context, can be trusted to judge. */
export const BLOCKABLE = new Set(["direct_injection", "jailbreak"]);

/**
 * Fold a project's stored gateway settings into the deployment-wide policy.
 *
 * The environment sets what the proxy does by default; a project may narrow or
 * widen its own behaviour within the bounds the code allows. Three rules:
 *
 *   - `inherit` (the default) changes nothing, so adding per-project settings
 *     is a no-op until someone deliberately opts in.
 *   - An empty category list means "use the built-in set", not "block nothing".
 *     A stored empty array is far more likely to be an unset field than an
 *     instruction to disable blocking while leaving block mode on, and the
 *     dangerous reading of an ambiguous config is the wrong one to take.
 *   - Categories outside BLOCKABLE were already dropped by mergeConfig; the
 *     intersection here is belt-and-braces for configs written before that
 *     validation existed.
 */
export function withProjectSettings(
  policy: GatewayPolicy,
  settings?: { mode?: string; block_threshold?: number; block_categories?: string[] } | null,
): GatewayPolicy {
  if (!settings) return policy;
  const mode = settings.mode === "block" || settings.mode === "observe" ? settings.mode : policy.mode;
  const t = Number(settings.block_threshold);
  const categories = (settings.block_categories ?? []).filter((c) => BLOCKABLE.has(c));
  return {
    ...policy,
    mode,
    blockThreshold: Number.isFinite(t) ? Math.min(100, Math.max(0, t)) : policy.blockThreshold,
    blockCategories: categories.length ? new Set(categories) : policy.blockCategories,
  };
}

export interface ScanVerdict {
  blocked: boolean;
  score: number;
  category: string;
  reason: string;
  /** True when detection didn't answer in time or errored. */
  degraded: boolean;
  latencyMs: number;
}

interface DetectionFinding {
  category: string;
  severity: string;
  score: number;
  evidence_excerpt?: string;
}

/**
 * Scan one message and decide whether to allow it.
 *
 * `content` is the user-supplied text only — not the system prompt. Scanning
 * your own system prompt guarantees a match on every request, since a system
 * prompt is by nature a list of instructions.
 */
export async function evaluate(
  projectId: string,
  content: string,
  policy: GatewayPolicy,
): Promise<ScanVerdict> {
  const started = Date.now();
  const allow = (reason: string, degraded = false): ScanVerdict => ({
    blocked: false, score: 0, category: "", reason, degraded, latencyMs: Date.now() - started,
  });

  if (!content.trim()) return allow("empty content");

  let findings: DetectionFinding[];
  try {
    const headers: Record<string, string> = { "content-type": "application/json" };
    if (config.detectionApiKey) headers.authorization = `Bearer ${config.detectionApiKey}`;

    const res = await fetch(`${config.detectionUrl}/v1/scan`, {
      method: "POST",
      headers,
      body: JSON.stringify({
        project_id: projectId,
        observation: {
          observation_id: "gateway",
          trace_id: "gateway",
          type: "span",
          name: "gateway",
          content,
          role: "user",
          // Explicitly user-tainted. The gateway sees the request before the
          // model does, so this is by definition direct input, and mislabelling
          // it would relabel findings as `indirect_injection`.
          taint: "user",
          taint_source: "",
          model: "",
          attributes: {},
        },
        tool_overrides: {},
        // L2 is a model forward pass. Not on a synchronous path with a
        // sub-second budget; the async pipeline runs it moments later.
        enable_l2: false,
      }),
      // The budget is enforced here, on the socket. A scan that hasn't answered
      // in time IS a scan that failed, and treating "slow" as anything other
      // than "unavailable" is how a proxy becomes the outage.
      signal: AbortSignal.timeout(policy.latencyBudgetMs),
    });
    if (!res.ok) throw new Error(`detection ${res.status}`);
    findings = ((await res.json()) as { findings?: DetectionFinding[] }).findings ?? [];
  } catch (err) {
    const degraded = { degraded: true, latencyMs: Date.now() - started };
    if (policy.onFailure === "closed") {
      return {
        blocked: true, score: 0, category: "unavailable",
        reason: `detection unavailable and policy is fail-closed: ${String(err)}`,
        ...degraded,
      };
    }
    return allow(`detection unavailable, allowed (fail-open): ${String(err)}`, true);
  }

  // A project may narrow the blockable set; it can never widen it past what a
  // single message with no trace context can honestly judge.
  const blockable = policy.blockCategories ?? BLOCKABLE;
  const worst = findings
    .filter((f) => blockable.has(f.category) && BLOCKABLE.has(f.category))
    .sort((a, b) => b.score - a.score)[0];

  if (!worst) return allow("no blockable finding");
  if (policy.mode !== "block") {
    return { ...allow("observe mode"), score: worst.score, category: worst.category };
  }
  if (worst.score < policy.blockThreshold) {
    return { ...allow("below block threshold"), score: worst.score, category: worst.category };
  }

  return {
    blocked: true,
    score: worst.score,
    category: worst.category,
    reason: worst.evidence_excerpt || "matched a high-confidence injection pattern",
    degraded: false,
    latencyMs: Date.now() - started,
  };
}
