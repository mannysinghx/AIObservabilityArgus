/**
 * Canary management: mint, list, revoke.
 *
 * The raw value of a generated canary is returned exactly once, at creation,
 * and is never stored — only its sha256. That is not ceremony copied from API
 * keys: it is what makes the whole design work. Detection matches by digest, so
 * nothing downstream ever needs the plaintext, and a database dump doesn't hand
 * an attacker the list of markers to avoid tripping.
 */
import { hashCanary, invalidateCanaryCache, mintCanary, type CanaryKind } from "@argus/shared";
import { pool } from "./db.js";
import { safeProjectId } from "./ids.js";

export interface CanaryRow {
  id: string;
  label: string;
  kind: CanaryKind;
  createdAt: string;
  createdBy: string | null;
  lastTriggeredAt: string | null;
  triggerCount: number;
  /** Custom canaries only — the customer supplied this, so showing it back is
   *  not a disclosure. Generated canaries return "" forever after creation. */
  value: string;
}

const iso = (d: Date | null): string | null =>
  d ? (d instanceof Date ? d.toISOString() : String(d)) : null;

export async function listCanaries(projectId: string): Promise<CanaryRow[]> {
  const safe = safeProjectId(projectId);
  if (!safe) return [];
  const { rows } = await pool.query<{
    id: string; label: string | null; kind: string; created_at: Date; created_by: string | null;
    last_triggered_at: Date | null; trigger_count: number; value: string | null;
  }>(
    `SELECT id, label, kind, created_at, created_by, last_triggered_at, trigger_count, value
     FROM canaries WHERE project_id = $1 AND revoked_at IS NULL
     ORDER BY created_at DESC`,
    [safe],
  );
  return rows.map((r) => ({
    id: r.id,
    label: r.label ?? "",
    kind: (r.kind === "custom" ? "custom" : "generated") as CanaryKind,
    createdAt: iso(r.created_at)!,
    createdBy: r.created_by,
    lastTriggeredAt: iso(r.last_triggered_at),
    triggerCount: Number(r.trigger_count ?? 0),
    value: r.kind === "custom" ? (r.value ?? "") : "",
  }));
}

export interface NewCanary {
  id: string;
  label: string;
  kind: CanaryKind;
  /** Shown once. For a generated canary this is the only time it exists outside
   *  the customer's own systems. */
  value: string;
}

export async function createCanary(
  projectId: string,
  label: string,
  createdBy: string,
  customValue?: string,
): Promise<NewCanary | { error: string }> {
  const safe = safeProjectId(projectId);
  if (!safe) return { error: "Unknown application." };

  const cleanLabel = String(label || "").trim().slice(0, 200);
  if (!cleanLabel) return { error: "Give the canary a label so you know where you planted it." };

  const custom = String(customValue || "").trim();
  const kind: CanaryKind = custom ? "custom" : "generated";

  if (kind === "custom") {
    // Short markers collide with ordinary language and would page someone on
    // every trace that happens to contain the word.
    if (custom.length < 12) {
      return { error: "A custom canary must be at least 12 characters — shorter values match by accident." };
    }
    if (custom.length > 500) return { error: "That value is too long to be a canary." };
  }

  const value = kind === "generated" ? mintCanary() : custom;
  const tokenHash = hashCanary(value);

  try {
    const { rows } = await pool.query<{ id: string }>(
      `INSERT INTO canaries (project_id, token_hash, label, kind, value, created_by)
       VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`,
      // Only a custom canary's value is retained; a generated one keeps its hash
      // and nothing else.
      [safe, tokenHash, cleanLabel, kind, kind === "custom" ? value : null, createdBy || null],
    );
    invalidateCanaryCache(safe);
    return { id: rows[0].id, label: cleanLabel, kind, value };
  } catch (err) {
    // The unique index on token_hash is what guarantees an alert can name whose
    // data leaked; a duplicate would make that ambiguous.
    if ((err as { code?: string }).code === "23505") {
      return { error: "That canary value is already registered." };
    }
    throw err;
  }
}

/**
 * Revoke by marking, not deleting. A canary that fired last month is evidence,
 * and the security_events rows referencing it must keep resolving to something
 * with a label — an incident that reads "canary <deleted> fired" is not an
 * incident anyone can investigate.
 */
export async function revokeCanary(projectId: string, canaryId: string): Promise<{ ok: true } | { error: string }> {
  const safe = safeProjectId(projectId);
  if (!safe) return { error: "Unknown application." };
  const res = await pool.query(
    `UPDATE canaries SET revoked_at = now()
     WHERE id = $1 AND project_id = $2 AND revoked_at IS NULL`,
    [canaryId, safe],
  );
  if (!res.rowCount) return { error: "Canary not found." };
  invalidateCanaryCache(safe);
  return { ok: true };
}
