/**
 * Canary tokens: the highest-confidence detector in the product.
 *
 * A canary is a unique marker planted somewhere it should never travel from — a
 * system prompt, an internal document, a database record. Every other layer here
 * infers intent from text and can be argued with. A canary firing is not an
 * inference: this exact string was in a place it could only have come from, and
 * now it is in an outbound span. There is no benign explanation, which is why
 * this is the one signal that justifies waking someone at 3am.
 *
 * Storage. Generated canaries have a known format, so detection can extract
 * candidates from span content and compare *hashes* — the raw value is written
 * down once, shown to the customer, and never stored or sent anywhere again.
 * Custom canaries (a string the customer already planted) cannot be matched
 * without holding the string, so those are stored in the clear. The distinction
 * is surfaced in the UI rather than papered over.
 */
import pg from "pg";
import { createHash, randomBytes } from "node:crypto";
import { config } from "./config.js";

/** The distinctive, greppable prefix that makes hash-only matching possible. */
export const CANARY_PREFIX = "argus-cnry-";

/**
 * Matches a generated canary in arbitrary text. Deliberately loose on length so
 * a token that was truncated or re-encoded downstream still produces a candidate
 * — the hash comparison is what decides, and a false candidate costs one sha256.
 */
export const CANARY_PATTERN = new RegExp(`${CANARY_PREFIX}[A-Za-z0-9_-]{8,64}`, "g");

export type CanaryKind = "generated" | "custom";

export interface CanaryRef {
  id: string;
  label: string;
  kind: CanaryKind;
  /** sha256 of the token (generated) or of the raw value (custom). */
  tokenHash: string;
  /** Raw value — custom canaries only; empty for generated. */
  value: string;
}

export function hashCanary(v: string): string {
  return createHash("sha256").update(v).digest("hex");
}

export function mintCanary(): string {
  return CANARY_PREFIX + randomBytes(18).toString("base64url");
}

// ---------------------------------------------------------------- loader
let _pool: pg.Pool | null = null;
function pool(): pg.Pool {
  return (_pool ??= new pg.Pool({ connectionString: config.databaseUrl, max: 4 }));
}

const cache = new Map<string, { refs: CanaryRef[]; expires: number }>();
const TTL_MS = 30_000;

/**
 * Active canaries for a project, cached ~30s.
 *
 * Fails CLOSED to an empty list, unlike loadProjectConfig which fails open. The
 * asymmetry is deliberate: a missing config should not stop telemetry flowing,
 * but a database blip must never *invent* a canary hit. An empty list means "we
 * checked nothing", which is a false negative — bad, but recoverable and
 * visible in the logs. A spurious critical incident that pages a security team
 * at 3am destroys trust in the one signal that was supposed to be unarguable.
 */
export async function loadCanaries(projectId: string): Promise<CanaryRef[]> {
  const hit = cache.get(projectId);
  if (hit && hit.expires > Date.now()) return hit.refs;
  let refs: CanaryRef[] = [];
  try {
    const res = await pool().query<{
      id: string; label: string | null; kind: string; token_hash: string; value: string | null;
    }>(
      `SELECT id, label, kind, token_hash, value FROM canaries
       WHERE project_id = $1 AND revoked_at IS NULL`,
      [projectId],
    );
    refs = res.rows.map((r) => ({
      id: r.id,
      label: r.label ?? "",
      kind: (r.kind === "custom" ? "custom" : "generated") as CanaryKind,
      tokenHash: r.token_hash,
      value: r.kind === "custom" ? (r.value ?? "") : "",
    }));
  } catch {
    refs = [];
  }
  cache.set(projectId, { refs, expires: Date.now() + TTL_MS });
  return refs;
}

/** Drop the cache for a project — called when canaries change. */
export function invalidateCanaryCache(projectId: string): void {
  cache.delete(projectId);
}

/** Record that a canary fired. Never throws: an accounting failure must not
 *  swallow the incident it was describing. */
export async function markCanaryTriggered(canaryId: string): Promise<void> {
  try {
    await pool().query(
      `UPDATE canaries SET last_triggered_at = now(), trigger_count = trigger_count + 1
       WHERE id = $1`,
      [canaryId],
    );
  } catch {
    /* the security_event row is the record of truth; this is just convenience */
  }
}
