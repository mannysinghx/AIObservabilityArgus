/**
 * Per-application detection config — the single source of truth for what a
 * customer can tune from the Argus UI, and the loader the runtime services use
 * to apply it. Stored as JSONB in Postgres `detection_configs.config` (snake_case
 * so the stored row maps 1:1 to this shape).
 *
 * This is the "config lives in Argus, not the customer's app" contract: the SDK
 * carries nothing but the ingest key; sampling, redaction, which detection
 * layers run, and alert thresholds are all read from here at request time.
 *
 * Everything fails OPEN to DEFAULT_DETECTION_CONFIG — a bad or missing config row
 * must never block ingestion or scanning.
 */
import pg from "pg";
import { config } from "./config.js";

export type RedactionMode = "off" | "mask_pii" | "drop_content";
export type Severity = "info" | "low" | "medium" | "high" | "critical";

export interface DetectionConfig {
  /** Head sampling: fraction of traces to keep (0..1). Applies to BOTH storage
   *  and scanning — a sampled-out trace is never seen again, so keep at 1 unless
   *  cost forces otherwise. */
  sampling: { trace_sample_rate: number };
  /** Scrub sensitive text before it is stored. `mask_pii` leaves injection
   *  payloads intact (so detection still works); `drop_content` removes the text
   *  entirely (maximum privacy, but blinds detection). */
  redaction: { mode: RedactionMode };
  layers: {
    heuristics: { enabled: boolean; ruleset: string };
    classifiers: { enabled: boolean; escalation_threshold: number };
    judge: { enabled: boolean; trigger: string };
    trace_analysis: { enabled: boolean; instruction_echo: boolean; exfil_flow: boolean };
  };
  canaries: { enabled: boolean };
  alerting: { min_severity: Severity; channels: string[] };
  /** Inline gateway blocking, per application (Phase 4b).
   *
   *  Previously the gateway's policy came only from environment variables,
   *  which meant one deployment-wide setting: turning on blocking for the app
   *  that wanted it turned it on for every tenant sharing the proxy. These are
   *  the same three knobs, per project.
   *
   *  `mode: "inherit"` means "whatever the deployment is configured to do" and
   *  is the default, so adding this section changes nothing until someone opts
   *  a project in. Empty `block_categories` likewise means "use the built-in
   *  list" rather than "block nothing", because a stored empty array is far
   *  more likely to be an unset field than a deliberate instruction to disable
   *  the feature while leaving block mode on. */
  gateway: {
    mode: "inherit" | "observe" | "block";
    block_threshold: number;
    block_categories: string[];
  };
}

export const DEFAULT_DETECTION_CONFIG: DetectionConfig = {
  sampling: { trace_sample_rate: 1 },
  redaction: { mode: "off" },
  layers: {
    heuristics: { enabled: true, ruleset: "default-v1" },
    classifiers: { enabled: false, escalation_threshold: 0.75 },
    judge: { enabled: false, trigger: "escalation-only" },
    trace_analysis: { enabled: true, instruction_echo: true, exfil_flow: true },
  },
  canaries: { enabled: true },
  alerting: { min_severity: "high", channels: [] },
  gateway: { mode: "inherit", block_threshold: 75, block_categories: [] },
};

const SEVERITIES: Severity[] = ["info", "low", "medium", "high", "critical"];
const REDACTION_MODES: RedactionMode[] = ["off", "mask_pii", "drop_content"];

export type GatewayConfigMode = "inherit" | "observe" | "block";
const GATEWAY_MODES: GatewayConfigMode[] = ["inherit", "observe", "block"];
/** Kept in step with BLOCKABLE in gateway.ts — the categories a single message
 *  with no trace context can be trusted to judge. Duplicated as a literal here
 *  rather than imported because settings.ts is loaded by ingest and the worker,
 *  which have no business pulling in the gateway module; the gateway's own test
 *  asserts the two lists agree. */
const GATEWAY_BLOCKABLE = ["direct_injection", "jailbreak"];

// ---- coercion helpers: every field validated + clamped, never trusts input ----
const asObj = (v: unknown): Record<string, unknown> =>
  v && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : {};
const bool = (v: unknown, d: boolean): boolean => (typeof v === "boolean" ? v : d);
const str = (v: unknown, d: string): string => (typeof v === "string" && v ? v : d);
function num(v: unknown, d: number, lo: number, hi: number): number {
  const n = typeof v === "number" ? v : Number(v);
  if (!Number.isFinite(n)) return d;
  return Math.min(hi, Math.max(lo, n));
}

/**
 * Validate + fill an arbitrary stored/submitted value into a complete, safe
 * DetectionConfig. Unknown keys are dropped; out-of-range values are clamped;
 * missing fields fall back to the default. Use this on BOTH read (tolerate old
 * rows) and write (sanitize what the UI sends).
 */
export function mergeConfig(raw: unknown): DetectionConfig {
  const r = asObj(raw);
  const d = DEFAULT_DETECTION_CONFIG;
  const layers = asObj(r.layers);
  const alerting = asObj(r.alerting);
  const sev = str(alerting.min_severity, d.alerting.min_severity);
  const mode = str(asObj(r.redaction).mode, d.redaction.mode) as RedactionMode;
  return {
    sampling: { trace_sample_rate: num(asObj(r.sampling).trace_sample_rate, d.sampling.trace_sample_rate, 0, 1) },
    redaction: { mode: REDACTION_MODES.includes(mode) ? mode : d.redaction.mode },
    layers: {
      heuristics: {
        enabled: bool(asObj(layers.heuristics).enabled, d.layers.heuristics.enabled),
        ruleset: str(asObj(layers.heuristics).ruleset, d.layers.heuristics.ruleset),
      },
      classifiers: {
        enabled: bool(asObj(layers.classifiers).enabled, d.layers.classifiers.enabled),
        escalation_threshold: num(asObj(layers.classifiers).escalation_threshold, d.layers.classifiers.escalation_threshold, 0, 1),
      },
      judge: {
        enabled: bool(asObj(layers.judge).enabled, d.layers.judge.enabled),
        trigger: str(asObj(layers.judge).trigger, d.layers.judge.trigger),
      },
      trace_analysis: {
        enabled: bool(asObj(layers.trace_analysis).enabled, d.layers.trace_analysis.enabled),
        instruction_echo: bool(asObj(layers.trace_analysis).instruction_echo, d.layers.trace_analysis.instruction_echo),
        exfil_flow: bool(asObj(layers.trace_analysis).exfil_flow, d.layers.trace_analysis.exfil_flow),
      },
    },
    canaries: { enabled: bool(asObj(r.canaries).enabled, d.canaries.enabled) },
    alerting: {
      min_severity: (SEVERITIES.includes(sev as Severity) ? sev : d.alerting.min_severity) as Severity,
      channels: Array.isArray(alerting.channels) ? alerting.channels.map(String).slice(0, 20) : [],
    },
    gateway: (() => {
      const g = asObj(r.gateway);
      const m = str(g.mode, d.gateway.mode);
      return {
        mode: (GATEWAY_MODES.includes(m as GatewayConfigMode) ? m : d.gateway.mode) as GatewayConfigMode,
        block_threshold: num(g.block_threshold, d.gateway.block_threshold, 0, 100),
        // Only categories the single-message gateway is equipped to judge are
        // accepted. A project cannot opt itself into blocking on, say,
        // indirect_injection — that verdict needs trace context the proxy does
        // not have, and honouring it would block real users to catch an attack
        // this layer cannot actually see.
        block_categories: Array.isArray(g.block_categories)
          ? [...new Set(g.block_categories.map(String).filter((c) => GATEWAY_BLOCKABLE.includes(c)))]
          : [],
      };
    })(),
  };
}

// ------------------------ runtime loader (ingest + worker) ------------------------
let _pool: pg.Pool | null = null;
function pool(): pg.Pool {
  return (_pool ??= new pg.Pool({ connectionString: config.databaseUrl, max: 4 }));
}

const cache = new Map<string, { cfg: DetectionConfig; expires: number }>();
const TTL_MS = 30_000; // config changes take effect within ~30s, no restart

/**
 * The per-project config, cached ~30s. Fails open to defaults on any error or
 * missing row so a config problem can never take down ingestion or scanning.
 */
export async function loadProjectConfig(projectId: string): Promise<DetectionConfig> {
  const hit = cache.get(projectId);
  if (hit && hit.expires > Date.now()) return hit.cfg;
  let cfg = DEFAULT_DETECTION_CONFIG;
  try {
    const res = await pool().query<{ config: unknown }>(
      "SELECT config FROM detection_configs WHERE project_id = $1 LIMIT 1",
      [projectId],
    );
    cfg = mergeConfig(res.rows[0]?.config);
  } catch {
    // fail open — never block the request/scan path on a config read
  }
  cache.set(projectId, { cfg, expires: Date.now() + TTL_MS });
  return cfg;
}
