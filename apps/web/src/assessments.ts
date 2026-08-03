/**
 * Static assessments: run, store, list (Phase 2 of the InjectGuard merge).
 *
 * The engines live in the detection service (/v1/assess/*, pure functions);
 * this module owns everything they deliberately don't: tenancy, storage, and
 * the analyst's disposition on a finding. Two invariants carried over from the
 * rest of the dashboard:
 *
 *  - Every query names the project in its WHERE clause. Detail lookups are
 *    scoped by (id AND project_id), never id alone — the ACL check validates
 *    the *claimed* project, so an unscoped id lookup crosses tenants.
 *  - Prompt contents are never stored. The assessment row keeps document
 *    names/kinds and the deterministic context; findings keep the engine's
 *    already-redacted evidence excerpt. Prompts are customer IP that often
 *    contains exactly the secrets the scanner exists to flag — retaining them
 *    would make Argus the disclosure.
 */
import { config } from "@argus/shared";
import { pool } from "./db.js";
import { safeProjectId } from "./ids.js";
import { observedCategories } from "./assessmentSynthesis.js";

// ---------------- detection-service client ----------------
// Mirrors apps/worker/src/detectionClient.ts: same env, same auth posture
// (header omitted entirely when no key is configured).

function detectionHeaders(): Record<string, string> {
  const h: Record<string, string> = { "content-type": "application/json" };
  if (config.detectionApiKey) h.authorization = `Bearer ${config.detectionApiKey}`;
  return h;
}

async function callDetection<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(`${config.detectionUrl}${path}`, {
    method: "POST",
    headers: detectionHeaders(),
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`detection ${path} ${res.status}`);
  return (await res.json()) as T;
}

// ---------------- wire shapes (detection service contract) ----------------

export interface PromptDocIn {
  kind?: string;
  content: string;
  name?: string;
}

export interface AssessContextIn {
  has_write_capable_tools?: boolean;
  human_approval_enabled?: boolean;
  has_retrieval?: boolean;
  is_public?: boolean;
  tool_names_user_controlled?: boolean;
  has_compensating_controls?: boolean;
  has_sensitive_data?: boolean;
  business_criticality?: string;
  /** Filled in by the server from telemetry, never accepted from the client. */
  observed_categories?: string[];
}

interface AssessFindingWire {
  document_index: number;
  document_name: string;
  rule_id: string;
  title: string;
  category: string;
  severity: string;
  confidence: string;
  explanation: string;
  affected_lines: number[];
  evidence: string;
  recommendation: string;
  frameworks: Record<string, string>[];
  argus_category: string | null;
  argus_severity: string;
  observed_in_production: boolean;
  risk: Record<string, unknown>;
  mitigations: Record<string, unknown>[];
}

interface AssessPromptWire {
  finding_count: number;
  max_severity: string | null;
  overall_risk: number;
  scoring_version: string;
  findings: AssessFindingWire[];
}

export interface GraphNodeIn {
  id: string;
  label?: string;
  node_type?: string;
  trust_level?: string;
  can_write?: boolean;
  requires_approval?: boolean;
  attributes?: Record<string, unknown>;
}

export interface GraphEdgeIn {
  source?: string | null;
  target?: string | null;
  edge_type?: string;
  tenant_boundary?: boolean;
  name?: string;
}

interface GraphInsightWire {
  rule: string;
  severity: string;
  message: string;
  component_ids: string[];
  argus_category: string | null;
  argus_severity: string;
}

interface AssessGraphWire {
  insight_count: number;
  max_severity: string | null;
  insights: GraphInsightWire[];
}

interface BlastRadiusHopWire {
  node_id: string;
  label: string;
  sink_kinds: string[];
  hops: number;
  gated: boolean;
}

interface AssessBlastRadiusWire {
  from_node_id: string;
  from_label: string;
  sink_count: number;
  reachable_sinks: BlastRadiusHopWire[];
}

// ---------------- run + store ----------------

export interface RunResult {
  id: string;
  kind: string;
  findingCount: number;
  maxSeverity: string | null;
  overallRisk: number;
  scoringVersion: string;
  findings: unknown[];
}

/** Cap request size well below anything legitimate: the engine reads prompt
 *  templates, not corpora, and an unbounded body is a free CPU oracle. */
const MAX_DOCUMENTS = 50;
const MAX_DOC_CHARS = 100_000;

export function validateDocuments(docs: PromptDocIn[] | undefined): string | null {
  if (!Array.isArray(docs) || docs.length === 0) return "documents required";
  if (docs.length > MAX_DOCUMENTS) return `at most ${MAX_DOCUMENTS} documents`;
  for (const d of docs) {
    if (typeof d?.content !== "string" || !d.content.trim()) return "each document needs content";
    if (d.content.length > MAX_DOC_CHARS) return `document exceeds ${MAX_DOC_CHARS} chars`;
  }
  return null;
}

export async function runPromptAssessment(
  projectId: string,
  documents: PromptDocIn[],
  context: AssessContextIn,
  createdBy: string | null,
): Promise<RunResult | null> {
  const safe = safeProjectId(projectId);
  if (!safe) return null;

  // Phase-4 synthesis: tell the engine which attack classes this application
  // has actually seen, so a demonstrated weakness outranks a theoretical one.
  // Derived server-side from telemetry and NOT taken from the request — a
  // client-supplied value here would let a caller inflate its own risk scores,
  // and worse, quietly launder someone else's telemetry into its assessment.
  // Best-effort: a ClickHouse blip must not block an assessment, it just means
  // this run scores on inference alone.
  let observed: string[] = [];
  try {
    observed = await observedCategories(safe);
  } catch { /* score without runtime evidence rather than failing the run */ }

  const wire = await callDetection<AssessPromptWire>("/v1/assess/prompt", {
    project_id: safe,
    documents: documents.map((d) => ({
      kind: d.kind ?? "system",
      content: d.content,
      name: d.name ?? "",
    })),
    context: { ...context, observed_categories: observed },
  });

  // Names/kinds only — see the module header for why contents never persist.
  const docMeta = documents.map((d) => ({ kind: d.kind ?? "system", name: d.name ?? "" }));

  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const { rows } = await client.query<{ id: string }>(
      `INSERT INTO assessments
         (project_id, kind, context, documents, finding_count, max_severity,
          overall_risk, scoring_version, created_by)
       VALUES ($1, 'prompt', $2, $3, $4, $5, $6, $7, $8)
       RETURNING id`,
      [
        safe,
        JSON.stringify(context ?? {}),
        JSON.stringify(docMeta),
        wire.finding_count,
        wire.max_severity,
        wire.overall_risk,
        wire.scoring_version,
        createdBy,
      ],
    );
    const assessmentId = rows[0].id;
    for (const f of wire.findings) {
      await client.query(
        `INSERT INTO assessment_findings
           (assessment_id, project_id, document_index, document_name, rule_id, title,
            category, severity, confidence, explanation, affected_lines, evidence,
            recommendation, frameworks, argus_category, argus_severity, risk, mitigations,
            observed_in_production)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)`,
        [
          assessmentId, safe, f.document_index, f.document_name, f.rule_id, f.title,
          f.category, f.severity, f.confidence, f.explanation, f.affected_lines, f.evidence,
          f.recommendation, JSON.stringify(f.frameworks), f.argus_category, f.argus_severity,
          JSON.stringify(f.risk), JSON.stringify(f.mitigations), !!f.observed_in_production,
        ],
      );
    }
    await client.query("COMMIT");
    return {
      id: assessmentId,
      kind: "prompt",
      findingCount: wire.finding_count,
      maxSeverity: wire.max_severity,
      overallRisk: wire.overall_risk,
      scoringVersion: wire.scoring_version,
      findings: wire.findings,
    };
  } catch (err) {
    await client.query("ROLLBACK").catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}

/** Analyze the project's stored graph and record the run. Returns null when the
 *  project id is unusable or no graph has been saved yet. */
export async function runGraphAssessment(
  projectId: string,
  createdBy: string | null,
): Promise<RunResult | null> {
  const safe = safeProjectId(projectId);
  if (!safe) return null;
  const graph = await getGraph(safe);
  if (!graph || (graph.nodes as unknown[]).length === 0) return null;

  const wire = await callDetection<AssessGraphWire>("/v1/assess/graph", {
    project_id: safe,
    nodes: graph.nodes,
    edges: graph.edges,
  });

  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const { rows } = await client.query<{ id: string }>(
      `INSERT INTO assessments
         (project_id, kind, context, finding_count, max_severity, overall_risk,
          scoring_version, created_by)
       VALUES ($1, 'graph', $2, $3, $4, 0, '', $5)
       RETURNING id`,
      [
        safe,
        JSON.stringify({ nodes: graph.nodes, edges: graph.edges }),
        wire.insight_count,
        wire.max_severity,
        createdBy,
      ],
    );
    const assessmentId = rows[0].id;
    for (const i of wire.insights) {
      await client.query(
        `INSERT INTO assessment_findings
           (assessment_id, project_id, rule_id, title, category, severity, confidence,
            explanation, evidence, recommendation, argus_category, argus_severity)
         VALUES ($1,$2,$3,$4,'architecture',$5,'medium',$6,'','',$7,$8)`,
        [assessmentId, safe, i.rule, i.rule.replace(/_/g, " "), i.severity, i.message,
         i.argus_category, i.argus_severity],
      );
    }
    await client.query("COMMIT");
    return {
      id: assessmentId,
      kind: "graph",
      findingCount: wire.insight_count,
      maxSeverity: wire.max_severity,
      overallRisk: 0,
      scoringVersion: "",
      findings: wire.insights,
    };
  } catch (err) {
    await client.query("ROLLBACK").catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}

// ---------------- graph storage ----------------

const MAX_GRAPH_ITEMS = 200;

export function validateGraph(
  nodes: GraphNodeIn[] | undefined,
  edges: GraphEdgeIn[] | undefined,
): string | null {
  if (!Array.isArray(nodes)) return "nodes required";
  if (!Array.isArray(edges ?? [])) return "edges must be a list";
  if (nodes.length > MAX_GRAPH_ITEMS || (edges ?? []).length > MAX_GRAPH_ITEMS) {
    return `at most ${MAX_GRAPH_ITEMS} nodes/edges`;
  }
  for (const n of nodes) {
    if (typeof n?.id !== "string" || !n.id.trim()) return "each node needs an id";
  }
  return null;
}

export async function saveGraph(
  projectId: string,
  nodes: GraphNodeIn[],
  edges: GraphEdgeIn[],
  updatedBy: string | null,
): Promise<boolean> {
  const safe = safeProjectId(projectId);
  if (!safe) return false;
  await pool.query(
    `INSERT INTO assessment_graphs (project_id, nodes, edges, updated_by, updated_at)
     VALUES ($1, $2, $3, $4, now())
     ON CONFLICT (project_id)
     DO UPDATE SET nodes = $2, edges = $3, updated_by = $4, updated_at = now()`,
    [safe, JSON.stringify(nodes), JSON.stringify(edges ?? []), updatedBy],
  );
  return true;
}

export async function getGraph(
  projectId: string,
): Promise<{ nodes: unknown[]; edges: unknown[]; updatedAt: string | null } | null> {
  const safe = safeProjectId(projectId);
  if (!safe) return null;
  const { rows } = await pool.query<{ nodes: unknown[]; edges: unknown[]; updated_at: Date }>(
    `SELECT nodes, edges, updated_at FROM assessment_graphs WHERE project_id = $1`,
    [safe],
  );
  if (rows.length === 0) return { nodes: [], edges: [], updatedAt: null };
  return { nodes: rows[0].nodes, edges: rows[0].edges, updatedAt: rows[0].updated_at.toISOString() };
}

// ---------------- reads ----------------

export async function listAssessments(projectId: string, limit = 50): Promise<unknown[]> {
  const safe = safeProjectId(projectId);
  if (!safe) return [];
  const { rows } = await pool.query(
    `SELECT id, kind, finding_count, max_severity, overall_risk, scoring_version,
            created_by, created_at
     FROM assessments WHERE project_id = $1
     ORDER BY created_at DESC LIMIT $2`,
    [safe, Math.min(Math.max(limit, 1), 200)],
  );
  return rows;
}

export async function getAssessment(projectId: string, id: string): Promise<unknown | null> {
  const safe = safeProjectId(projectId);
  const safeId = safeProjectId(id); // assessment ids are UUIDs too — same sanitizer
  if (!safe || !safeId) return null;
  const { rows } = await pool.query(
    `SELECT id, kind, context, documents, finding_count, max_severity, overall_risk,
            scoring_version, created_by, created_at
     FROM assessments WHERE id = $1 AND project_id = $2`,
    [safeId, safe],
  );
  if (rows.length === 0) return null;
  const { rows: findings } = await pool.query(
    `SELECT id, document_index, document_name, rule_id, title, category, severity,
            confidence, explanation, affected_lines, evidence, recommendation,
            frameworks, argus_category, argus_severity, observed_in_production,
            risk, mitigations, analyst_status, created_at
     FROM assessment_findings WHERE assessment_id = $1 AND project_id = $2
     ORDER BY created_at, id`,
    [safeId, safe],
  );
  return { ...rows[0], findings };
}

export async function listFindings(projectId: string, limit = 200): Promise<unknown[]> {
  const safe = safeProjectId(projectId);
  if (!safe) return [];
  const { rows } = await pool.query(
    // Observed-in-production first: a weakness someone is already probing is
    // the one to work on, regardless of when it was found.
    `SELECT id, assessment_id, document_name, rule_id, title, category, severity,
            confidence, argus_category, argus_severity, observed_in_production,
            risk, analyst_status, created_at
     FROM assessment_findings WHERE project_id = $1
     ORDER BY observed_in_production DESC, created_at DESC LIMIT $2`,
    [safe, Math.min(Math.max(limit, 1), 500)],
  );
  return rows;
}

// ---------------- reports ----------------

export const REPORT_KINDS = new Set(["executive", "technical", "governance"]);
export const REPORT_FORMATS = new Set(["md", "json", "csv", "pdf"]);

const MAX_BLAST_RADIUS_INSIGHTS = 5;
const BLAST_RADIUS_SEVERITY_RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };

/**
 * docs/15 §5, phase 2. Best-effort enrichment for the report: walks the
 * stored graph's highest-severity insights and asks the engine what's
 * reachable from each. Never throws — a report's actual reason for existing
 * (findings, controls) must render even if there's no stored graph, the
 * graph is empty, or the detection service hiccups on this specific call;
 * losing the blast-radius section is a degraded report, not a failed one.
 * Capped to the top few insights by severity so a large graph can't turn one
 * report generation into an unbounded number of detection-service calls.
 */
async function computeBlastRadiusEntries(
  projectId: string,
): Promise<{ from_node_id: string; from_label: string; reachable_sinks: BlastRadiusHopWire[] }[]> {
  try {
    const graph = await getGraph(projectId);
    if (!graph || (graph.nodes as unknown[]).length === 0) return [];

    const graphWire = await callDetection<AssessGraphWire>("/v1/assess/graph", {
      project_id: projectId,
      nodes: graph.nodes,
      edges: graph.edges,
    });
    if (!graphWire.insights.length) return [];

    const byId = new Map(
      (graph.nodes as { id: string; trust_level?: string }[]).map((n) => [n.id, n]),
    );
    const ranked = [...graphWire.insights].sort(
      (a, b) => (BLAST_RADIUS_SEVERITY_RANK[a.severity] ?? 9) - (BLAST_RADIUS_SEVERITY_RANK[b.severity] ?? 9),
    );
    const starts = new Set<string>();
    for (const insight of ranked) {
      if (starts.size >= MAX_BLAST_RADIUS_INSIGHTS) break;
      const untrusted = insight.component_ids.filter((id) => byId.get(id)?.trust_level === "untrusted");
      for (const id of untrusted.length ? untrusted : insight.component_ids) {
        if (starts.size >= MAX_BLAST_RADIUS_INSIGHTS) break;
        starts.add(id);
      }
    }
    if (!starts.size) return [];

    const results = await Promise.all(
      [...starts].map((fromNodeId) =>
        callDetection<AssessBlastRadiusWire>("/v1/assess/blast-radius", {
          project_id: projectId,
          nodes: graph.nodes,
          edges: graph.edges,
          from_node_id: fromNodeId,
        }),
      ),
    );
    return results
      .filter((r) => r.reachable_sinks.length > 0)
      .map((r) => ({
        from_node_id: r.from_node_id,
        from_label: r.from_label,
        reachable_sinks: r.reachable_sinks,
      }));
  } catch {
    return [];
  }
}

/**
 * Gather this project's open findings and controls, hand them to the engine's
 * renderer, and return the finished file.
 *
 * The rendering lives in the detection service so all four formats share one
 * definition of what a report says (and one redaction backstop); this side owns
 * only the data-gathering, which is where the tenancy is. Findings are limited
 * to `open` on purpose — a report is a statement about outstanding risk, and
 * padding it with things the team already resolved makes it useless for the
 * conversation it exists to support.
 */
export async function renderReport(
  projectId: string,
  projectName: string,
  kind: string,
  format: string,
): Promise<{ body: Buffer; contentType: string } | null> {
  const safe = safeProjectId(projectId);
  if (!safe || !REPORT_KINDS.has(kind) || !REPORT_FORMATS.has(format)) return null;

  const [findings, controls] = await Promise.all([
    pool.query(
      `SELECT rule_id, title, category, severity, confidence, document_name,
              explanation, evidence, recommendation, frameworks, mitigations,
              observed_in_production, (risk->>'final_score')::int AS risk_score
       FROM assessment_findings
       WHERE project_id = $1 AND analyst_status = 'open'
       ORDER BY created_at DESC LIMIT 500`,
      [safe],
    ),
    pool.query(
      `SELECT control_key, domain, objective, description, status, owner,
              evidence, frameworks
       FROM governance_controls WHERE project_id = $1 ORDER BY control_key`,
      [safe],
    ),
  ]);

  const coverage: Record<string, number> = {};
  for (const c of controls.rows as { status: string }[]) {
    coverage[c.status] = (coverage[c.status] ?? 0) + 1;
  }
  const overallRisk = (findings.rows as { risk_score: number | null }[])
    .reduce((m, f) => Math.max(m, Number(f.risk_score ?? 0)), 0);

  // Governance reports don't render blast radius (report.py's own scope
  // decision — it's about controls and outstanding-risk counts, not
  // reachability), so skip the extra detection-service calls entirely rather
  // than compute something that would just be dropped on the floor.
  const blastRadius = kind === "governance" ? [] : await computeBlastRadiusEntries(safe);

  const headers: Record<string, string> = { "content-type": "application/json" };
  if (config.detectionApiKey) headers.authorization = `Bearer ${config.detectionApiKey}`;

  const res = await fetch(`${config.detectionUrl}/v1/report`, {
    method: "POST",
    headers,
    body: JSON.stringify({
      kind,
      format,
      data: {
        project_name: projectName,
        generated_at: new Date().toISOString(),
        overall_risk: overallRisk,
        coverage,
        findings: findings.rows,
        controls: controls.rows,
        blast_radius: blastRadius,
      },
    }),
  });
  if (!res.ok) throw new Error(`detection /v1/report ${res.status}`);
  return {
    body: Buffer.from(await res.arrayBuffer()),
    contentType: res.headers.get("content-type") || "application/octet-stream",
  };
}

const FINDING_STATUSES = new Set(["open", "resolved", "accepted"]);

/** Scoped by (id AND project_id): the ACL validated the claimed project, so the
 *  row must be looked up under that same project or not at all. */
export async function setFindingStatus(
  projectId: string,
  findingId: string,
  status: string,
): Promise<{ error: string } | { ok: true }> {
  const safe = safeProjectId(projectId);
  const safeId = safeProjectId(findingId);
  if (!safe || !safeId) return { error: "invalid id" };
  if (!FINDING_STATUSES.has(status)) return { error: "status must be open|resolved|accepted" };
  const r = await pool.query(
    `UPDATE assessment_findings SET analyst_status = $1
     WHERE id = $2 AND project_id = $3`,
    [status, safeId, safe],
  );
  if (r.rowCount === 0) return { error: "finding not found" };
  return { ok: true };
}
