/**
 * Governance controls (InjectGuard merge — controls port).
 *
 * Findings tell you what is wrong today. Controls are the standing commitments
 * you have made — "retrieved content is treated as untrusted", "writes need
 * human approval" — with an owner, a status, and a review cadence. Auditors ask
 * about the second kind, and until now Argus could only answer the first.
 *
 * One behaviour deliberately differs from InjectGuard's version: seeding the
 * baseline catalog there happened as a side effect of listing controls, so a
 * plain GET wrote ten rows. Reads that mutate are how a page refresh becomes a
 * data change and how a viewer ends up writing to the database. Here seeding is
 * an explicit action a member takes.
 */
import { pool } from "./db.js";
import { safeProjectId } from "./ids.js";

export interface ControlRow {
  id: string;
  control_key: string;
  domain: string;
  objective: string;
  description: string;
  status: string;
  owner: string;
  review_frequency: string;
  evidence: string;
  frameworks: { framework: string; requirement: string }[];
  last_reviewed_at: string | null;
  updated_at: string;
}

export const CONTROL_STATUSES = new Set([
  "not_implemented",
  "in_progress",
  "implemented",
  "not_applicable",
]);

interface CatalogControl {
  control_key: string;
  domain: string;
  objective: string;
  description: string;
  review_frequency: string;
  frameworks: { framework: string; requirement: string }[];
}

/**
 * The baseline catalog: one representative control per domain that matters for
 * an LLM application, each mapped to the framework requirement an auditor will
 * cite. Ported verbatim from InjectGuard so the framework mappings stay
 * consistent with the finding-level ones.
 */
export const CONTROL_CATALOG: CatalogControl[] = [
  { control_key: "GOV-1", domain: "governance", objective: "AI risk governance ownership",
    description: "Assign accountable owners for AI security risk.",
    review_frequency: "annual", frameworks: [{ framework: "NIST-AI-RMF", requirement: "GOVERN" }] },
  { control_key: "INV-1", domain: "inventory", objective: "Maintain an AI application inventory",
    description: "All AI applications are registered and classified by risk tier.",
    review_frequency: "quarterly", frameworks: [{ framework: "NIST-AI-RMF", requirement: "MAP" }] },
  { control_key: "PE-1", domain: "prompt_engineering", objective: "Prompt separation standard",
    description: "System instructions are separated from untrusted input via delimiters/roles.",
    review_frequency: "quarterly", frameworks: [{ framework: "OWASP-LLM", requirement: "LLM01" }] },
  { control_key: "RAG-1", domain: "rag_security", objective: "Retrieval treated as untrusted",
    description: "Retrieved content is sanitized and never followed as instructions.",
    review_frequency: "quarterly", frameworks: [{ framework: "OWASP-LLM", requirement: "LLM01" }] },
  { control_key: "TOOL-1", domain: "tool_security", objective: "Tool allowlisting",
    description: "Agents may only invoke an explicit allowlist of least-privilege tools.",
    review_frequency: "quarterly", frameworks: [{ framework: "OWASP-LLM", requirement: "LLM08" }] },
  { control_key: "OUT-1", domain: "output_handling", objective: "Secure output rendering",
    description: "Model output rendered with raw HTML disabled and sanitized.",
    review_frequency: "quarterly", frameworks: [{ framework: "OWASP-LLM", requirement: "LLM02" }] },
  { control_key: "HO-1", domain: "human_oversight", objective: "Human approval for high-impact actions",
    description: "Write/irreversible actions require server-side human approval.",
    review_frequency: "quarterly", frameworks: [{ framework: "OWASP-LLM", requirement: "LLM08" }] },
  { control_key: "TEST-1", domain: "testing", objective: "Adversarial prompt-injection testing",
    description: "Applications undergo prompt-injection assessment before and after release.",
    review_frequency: "quarterly", frameworks: [{ framework: "NIST-GENAI", requirement: "MS-2.6" }] },
  { control_key: "MON-1", domain: "monitoring", objective: "Security monitoring & audit",
    description: "Security-relevant activity is logged to a tamper-evident audit trail.",
    review_frequency: "quarterly", frameworks: [{ framework: "NIST-AI-RMF", requirement: "MEASURE" }] },
  { control_key: "IR-1", domain: "incident_response", objective: "AI incident response plan",
    description: "A documented playbook exists for prompt-injection and data-exposure incidents.",
    review_frequency: "annual", frameworks: [{ framework: "NIST-AI-RMF", requirement: "MANAGE" }] },
  // Model supply chain (docs/18). Every control above is about how the
  // application handles text; these are about what it is allowed to load, which
  // is the only lever that helps against a payload that executes at
  // deserialization — before the first token exists. OWASP LLM05 had no
  // controls and no rules until L0; adoptCatalog is idempotent, so existing
  // projects pick these up on their next adopt without disturbing any status
  // somebody already set.
  { control_key: "SUP-1", domain: "supply_chain", objective: "Model artifacts pinned by digest",
    description: "Models are resolved by content hash, never by a mutable tag or branch.",
    review_frequency: "quarterly", frameworks: [{ framework: "OWASP-LLM", requirement: "LLM05" }] },
  { control_key: "SUP-2", domain: "supply_chain", objective: "No code-capable serialization in production",
    description: "Production weights are stored in safetensors or another format that cannot execute on load.",
    review_frequency: "quarterly", frameworks: [{ framework: "OWASP-LLM", requirement: "LLM05" }] },
  { control_key: "SUP-3", domain: "supply_chain", objective: "Model registry access controlled and audited",
    description: "Registry writes are restricted to a release pipeline and every write is logged.",
    review_frequency: "quarterly", frameworks: [{ framework: "OWASP-LLM", requirement: "LLM05" }] },
  { control_key: "SUP-4", domain: "supply_chain", objective: "Model artifacts signed and verified",
    description: "Artifacts carry a verifiable signature that is checked before they are loaded.",
    review_frequency: "quarterly", frameworks: [{ framework: "NIST-AI-RMF", requirement: "MANAGE" }] },
];

export async function listControls(projectId: string): Promise<ControlRow[]> {
  const safe = safeProjectId(projectId);
  if (!safe) return [];
  const { rows } = await pool.query<ControlRow>(
    `SELECT id, control_key, domain, objective, description, status, owner,
            review_frequency, evidence, frameworks, last_reviewed_at, updated_at
     FROM governance_controls WHERE project_id = $1
     ORDER BY control_key`,
    [safe],
  );
  return rows;
}

/**
 * Copy the baseline catalog into a project. Idempotent — ON CONFLICT DO NOTHING
 * means adopting a catalog that grew later adds only the new controls and never
 * resets a status somebody set.
 */
export async function adoptCatalog(projectId: string, by: string | null): Promise<number> {
  const safe = safeProjectId(projectId);
  if (!safe) return 0;
  let added = 0;
  for (const c of CONTROL_CATALOG) {
    const r = await pool.query(
      `INSERT INTO governance_controls
         (project_id, control_key, domain, objective, description, review_frequency,
          frameworks, updated_by)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
       ON CONFLICT (project_id, control_key) DO NOTHING`,
      [safe, c.control_key, c.domain, c.objective, c.description, c.review_frequency,
       JSON.stringify(c.frameworks), by],
    );
    added += r.rowCount ?? 0;
  }
  return added;
}

export interface ControlUpdate {
  status?: string;
  owner?: string;
  evidence?: string;
}

export async function updateControl(
  projectId: string,
  id: string,
  u: ControlUpdate,
  by: string | null,
): Promise<{ error: string } | { ok: true }> {
  const safe = safeProjectId(projectId);
  const safeId = safeProjectId(id);
  if (!safe || !safeId) return { error: "invalid id" };
  if (u.status && !CONTROL_STATUSES.has(u.status)) {
    return { error: `status must be one of: ${[...CONTROL_STATUSES].join(", ")}` };
  }
  if ((u.owner ?? "").length > 200 || (u.evidence ?? "").length > 2000) {
    return { error: "owner or evidence too long" };
  }
  // COALESCE so a partial update (just the status, say) doesn't blank the
  // owner someone set last week. Scoped by (id AND project_id) like every
  // other write in this codebase.
  const r = await pool.query(
    `UPDATE governance_controls
     SET status = COALESCE($1, status),
         owner = COALESCE($2, owner),
         evidence = COALESCE($3, evidence),
         last_reviewed_at = CASE WHEN $1 IS NOT NULL THEN now() ELSE last_reviewed_at END,
         updated_by = $4,
         updated_at = now()
     WHERE id = $5 AND project_id = $6`,
    [u.status ?? null, u.owner ?? null, u.evidence ?? null, by, safeId, safe],
  );
  if (r.rowCount === 0) return { error: "control not found" };
  return { ok: true };
}

/** Status counts, for the coverage summary. */
export async function coverage(projectId: string): Promise<Record<string, number>> {
  const safe = safeProjectId(projectId);
  if (!safe) return {};
  const { rows } = await pool.query<{ status: string; n: string }>(
    `SELECT status, count(*) AS n FROM governance_controls
     WHERE project_id = $1 GROUP BY status`,
    [safe],
  );
  const out: Record<string, number> = {};
  for (const r of rows) out[r.status] = Number(r.n);
  return out;
}
