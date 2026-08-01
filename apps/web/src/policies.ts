/**
 * Governance policies (Phase 4b): storage, and the facts they are judged against.
 *
 * The evaluator itself lives in the detection service and is never
 * reimplemented here — this module's job is to keep the rules, assemble an
 * honest picture of the application, and ask the engine for a verdict. That
 * split is deliberate: the matcher's fail-closed semantics (unknown field or
 * unknown operator never matches) are pinned by tests over there, and a second
 * implementation in TypeScript would be one more thing to drift.
 *
 * What a policy can ask about is exactly what `buildContext` can prove — the
 * architecture the team described, and the findings their assessments actually
 * produced. Nothing is invented to fill a gap: a fact Argus cannot establish is
 * simply absent, and the evaluator treats absent as no-match.
 */
import { config } from "@argus/shared";
import { pool } from "./db.js";
import { safeProjectId } from "./ids.js";

export interface PolicyRow {
  id: string;
  policy_key: string;
  name: string;
  description: string;
  conditions: Record<string, unknown>;
  action: string;
  result_severity: string;
  message: string;
  enabled: boolean;
  created_at: string;
}

export const POLICY_ACTIONS = new Set(["warn", "block_deployment", "block_assessment_approval"]);
const SEVERITIES = new Set(["critical", "high", "medium", "low", "informational"]);

/** Actions that gate something. `warn` is advisory; these are not. */
export const BLOCKING_ACTIONS = new Set(["block_deployment", "block_assessment_approval"]);

export async function listPolicies(projectId: string): Promise<PolicyRow[]> {
  const safe = safeProjectId(projectId);
  if (!safe) return [];
  const { rows } = await pool.query<PolicyRow>(
    `SELECT id, policy_key, name, description, conditions, action, result_severity,
            message, enabled, created_at
     FROM assessment_policies WHERE project_id = $1
     ORDER BY created_at DESC`,
    [safe],
  );
  return rows;
}

export interface PolicyInput {
  policyKey?: string;
  name?: string;
  description?: string;
  conditions?: Record<string, unknown>;
  action?: string;
  resultSeverity?: string;
  message?: string;
}

/** Reject a policy that could not do anything useful, with a reason a user can act on. */
export function validatePolicy(p: PolicyInput): string | null {
  if (!p.name?.trim()) return "name required";
  if (!p.conditions || typeof p.conditions !== "object" || Array.isArray(p.conditions)) {
    return "conditions must be an object";
  }
  // The evaluator treats an empty condition map as never-matching (an empty
  // rule that fired on everything would be the worst possible default), so
  // accepting one here would just store a policy that can never do anything.
  if (Object.keys(p.conditions).length === 0) return "add at least one condition";
  if (Object.keys(p.conditions).length > 20) return "at most 20 conditions";
  if (p.action && !POLICY_ACTIONS.has(p.action)) {
    return `action must be one of: ${[...POLICY_ACTIONS].join(", ")}`;
  }
  if (p.resultSeverity && !SEVERITIES.has(p.resultSeverity)) return "invalid severity";
  return null;
}

const slug = (s: string) =>
  s.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 60) || "policy";

export async function createPolicy(
  projectId: string,
  p: PolicyInput,
  createdBy: string | null,
): Promise<{ error: string } | PolicyRow> {
  const safe = safeProjectId(projectId);
  if (!safe) return { error: "invalid project" };
  const key = slug(p.policyKey || p.name || "");
  try {
    const { rows } = await pool.query<PolicyRow>(
      `INSERT INTO assessment_policies
         (project_id, policy_key, name, description, conditions, action,
          result_severity, message, created_by)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
       RETURNING id, policy_key, name, description, conditions, action,
                 result_severity, message, enabled, created_at`,
      [
        safe, key, p.name!.trim(), p.description ?? "", JSON.stringify(p.conditions),
        p.action ?? "warn", p.resultSeverity ?? "medium", p.message ?? "", createdBy,
      ],
    );
    return rows[0];
  } catch (err) {
    // The unique (project_id, policy_key) is the likely failure and the only
    // one a caller can fix, so name it rather than returning a 500.
    if (String(err).includes("duplicate key")) return { error: "a policy with that name already exists" };
    throw err;
  }
}

export async function setPolicyEnabled(
  projectId: string,
  id: string,
  enabled: boolean,
): Promise<boolean> {
  const safe = safeProjectId(projectId);
  const safeId = safeProjectId(id);
  if (!safe || !safeId) return false;
  const r = await pool.query(
    `UPDATE assessment_policies SET enabled = $1 WHERE id = $2 AND project_id = $3`,
    [enabled, safeId, safe],
  );
  return (r.rowCount ?? 0) > 0;
}

export async function deletePolicy(projectId: string, id: string): Promise<boolean> {
  const safe = safeProjectId(projectId);
  const safeId = safeProjectId(id);
  if (!safe || !safeId) return false;
  const r = await pool.query(
    `DELETE FROM assessment_policies WHERE id = $1 AND project_id = $2`,
    [safeId, safe],
  );
  return (r.rowCount ?? 0) > 0;
}

// ---------------- evaluation ----------------

/**
 * The facts a policy may condition on, assembled from what this project has
 * actually recorded. Two sources, both already tenant-scoped:
 *
 *   - the architecture graph the team described (components, write tools,
 *     approval flags, retrieval, tenant boundaries)
 *   - their assessment findings (open counts by severity, worst risk, and
 *     whether any weakness has been seen exploited in production)
 *
 * Absent facts stay absent. The evaluator fails closed on unknown paths, so an
 * application nobody has described yet simply doesn't match policies that ask
 * about its architecture — which is the correct answer, not a bug.
 */
export async function buildContext(projectId: string): Promise<Record<string, unknown>> {
  const safe = safeProjectId(projectId);
  if (!safe) return {};

  const [graph, counts] = await Promise.all([
    pool.query<{ nodes: { node_type?: string; can_write?: boolean; requires_approval?: boolean; trust_level?: string }[]; edges: { tenant_boundary?: boolean }[] }>(
      `SELECT nodes, edges FROM assessment_graphs WHERE project_id = $1`, [safe],
    ),
    pool.query<{ severity: string; n: string; observed: string }>(
      `SELECT argus_severity AS severity, count(*) AS n,
              count(*) FILTER (WHERE observed_in_production) AS observed
       FROM assessment_findings
       WHERE project_id = $1 AND analyst_status = 'open'
       GROUP BY argus_severity`, [safe],
    ),
  ]);

  const nodes = graph.rows[0]?.nodes ?? [];
  const edges = graph.rows[0]?.edges ?? [];
  const tools = nodes.filter((n) => n.node_type === "tool");
  const writeTools = tools.filter((t) => t.can_write);

  const bySeverity = new Map(counts.rows.map((r) => [r.severity, Number(r.n)]));
  const observedTotal = counts.rows.reduce((t, r) => t + Number(r.observed || 0), 0);

  const application: Record<string, unknown> = {
    described: nodes.length > 0,
    component_count: nodes.length,
    has_write_capable_tools: writeTools.length > 0,
    // Every write-capable tool must be gated for this to be true. "Some of them
    // are approved" is not an approval control.
    human_approval_enabled: writeTools.length > 0 && writeTools.every((t) => t.requires_approval),
    has_retrieval: nodes.some((n) => n.node_type === "document_source" || n.node_type === "vector_database"),
    has_untrusted_component: nodes.some((n) => n.trust_level === "untrusted"),
    crosses_tenant_boundary: edges.some((e) => e.tenant_boundary),
    open_critical_findings: bySeverity.get("critical") ?? 0,
    open_high_findings: bySeverity.get("high") ?? 0,
    open_findings: [...bySeverity.values()].reduce((a, b) => a + b, 0),
    observed_in_production_findings: observedTotal,
  };
  return { application };
}

export interface PolicyDecision {
  id: string;
  policyKey: string;
  name: string;
  matched: boolean;
  action: string;
  severity: string;
  message: string | null;
}

/**
 * Evaluate every enabled policy for a project. Read-only: this reports what the
 * rules say, and callers decide what to do about it. Nothing here writes or
 * blocks on its own — a governance rule that silently changed state the first
 * time someone opened a page would be indistinguishable from a bug.
 */
export async function evaluatePolicies(projectId: string): Promise<{
  context: Record<string, unknown>;
  decisions: PolicyDecision[];
  blocking: PolicyDecision[];
}> {
  const policies = await listPolicies(projectId);
  const enabled = policies.filter((p) => p.enabled);
  const context = await buildContext(projectId);

  const headers: Record<string, string> = { "content-type": "application/json" };
  if (config.detectionApiKey) headers.authorization = `Bearer ${config.detectionApiKey}`;

  const decisions: PolicyDecision[] = [];
  for (const p of enabled) {
    const res = await fetch(`${config.detectionUrl}/v1/assess/policy`, {
      method: "POST",
      headers,
      body: JSON.stringify({
        project_id: safeProjectId(projectId),
        policy: {
          conditions: p.conditions,
          action: p.action,
          result_severity: p.result_severity,
          message: p.message,
        },
        context,
      }),
    });
    if (!res.ok) throw new Error(`detection /v1/assess/policy ${res.status}`);
    const d = (await res.json()) as { matched: boolean; action: string; severity: string; message: string | null };
    decisions.push({
      id: p.id, policyKey: p.policy_key, name: p.name,
      matched: d.matched, action: d.action, severity: d.severity, message: d.message,
    });
  }

  return {
    context,
    decisions,
    blocking: decisions.filter((d) => d.matched && BLOCKING_ACTIONS.has(d.action)),
  };
}
