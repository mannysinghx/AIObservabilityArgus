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

// ---------------- artifact assessments (L0 — docs/18) ----------------

/** One model-file manifest, extracted at the edge by `argus-modelscan`.
 *  Kilobytes: the weights never travel, only what a pickle stream would call. */
export interface ArtifactManifestIn {
  path?: string;
  sha256?: string;
  size_bytes?: number;
  format?: string;
  source_uri?: string;
  revision?: string;
  globals?: { module?: string; name?: string; opcode?: string; offset?: number; member?: string }[];
  opcode_summary?: Record<string, number>;
  archive_members?: {
    name?: string; size?: number; compress_type?: number; is_pickle?: boolean; raw_name?: string;
  }[];
  tensor_keys?: string[];
  declared_arch?: string;
  onnx_custom_ops?: string[];
  onnx_external_data?: string[];
  keras_layer_types?: string[];
  parse_errors?: string[];
}

interface AssessArtifactWire extends AssessPromptWire {
  allowlist_version: string;
}

/** A manifest is machine-generated and small, but it arrives from a CI runner
 *  we do not control, so it gets the same treatment as any other request body.
 *  The caps are generous against real artifacts and cheap against a body built
 *  to make the engine do work: a torch state_dict resolves a few dozen globals,
 *  not a hundred thousand. */
const MAX_ARTIFACTS = 100;
const MAX_GLOBALS_PER_ARTIFACT = 20_000;
const MAX_MEMBERS_PER_ARTIFACT = 20_000;

export function validateArtifacts(artifacts: ArtifactManifestIn[] | undefined): string | null {
  if (!Array.isArray(artifacts) || artifacts.length === 0) return "artifacts required";
  if (artifacts.length > MAX_ARTIFACTS) return `at most ${MAX_ARTIFACTS} artifacts`;
  for (const a of artifacts) {
    if (a === null || typeof a !== "object") return "each artifact must be an object";
    // The digest is the artifact's identity — it is what a finding is about and
    // what the Phase-2 ledger will key on. A manifest without one is not
    // something we can file a finding against.
    if (typeof a.sha256 !== "string" || !/^[0-9a-f]{64}$/.test(a.sha256)) {
      return "each artifact needs a sha256 (64 hex chars)";
    }
    if ((a.globals?.length ?? 0) > MAX_GLOBALS_PER_ARTIFACT) {
      return `at most ${MAX_GLOBALS_PER_ARTIFACT} globals per artifact`;
    }
    if ((a.archive_members?.length ?? 0) > MAX_MEMBERS_PER_ARTIFACT) {
      return `at most ${MAX_MEMBERS_PER_ARTIFACT} archive members per artifact`;
    }
  }
  return null;
}

/**
 * Scan model artifacts and record the run.
 *
 * Stored as `kind='artifact'` in the same tables as prompt assessments. That is
 * not a shortcut: an artifact finding has a rule id, a severity, framework
 * refs, a risk breakdown and an analyst disposition — the same shape, about a
 * different subject — so it belongs in the Findings view alongside everything
 * else rather than in a parallel screen nobody opens.
 *
 * What is NOT stored is the manifest's `globals` list. The already-redacted
 * evidence excerpt on each finding names the references that mattered; keeping
 * the full list would mean retaining a map of the customer's proprietary model
 * internals to no end.
 */
export async function runArtifactAssessment(
  projectId: string,
  artifacts: ArtifactManifestIn[],
  firstPartyPrefixes: string[],
  createdBy: string | null,
): Promise<(RunResult & { allowlistVersion: string }) | null> {
  const safe = safeProjectId(projectId);
  if (!safe) return null;

  let observed: string[] = [];
  try {
    observed = await observedCategories(safe);
  } catch { /* score without runtime evidence rather than failing the run */ }

  const wire = await callDetection<AssessArtifactWire>("/v1/assess/artifact", {
    project_id: safe,
    artifacts,
    first_party_prefixes: firstPartyPrefixes,
    context: { observed_categories: observed },
  });

  // Identity only — path, digest, format, size. See the doc comment above.
  const docMeta = artifacts.map((a) => ({
    kind: a.format ?? "unknown",
    name: a.path ?? (a.sha256 ?? "").slice(0, 16),
    sha256: a.sha256 ?? "",
    size_bytes: a.size_bytes ?? 0,
    source_uri: a.source_uri ?? "",
    revision: a.revision ?? "",
  }));

  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const { rows } = await client.query<{ id: string }>(
      `INSERT INTO assessments
         (project_id, kind, context, documents, finding_count, max_severity,
          overall_risk, scoring_version, created_by)
       VALUES ($1, 'artifact', $2, $3, $4, $5, $6, $7, $8)
       RETURNING id`,
      [
        safe,
        // The allowlist decides every verdict here, so it is stored beside the
        // scoring version: a finding nobody can reproduce is a finding nobody
        // can argue with.
        JSON.stringify({ first_party_prefixes: firstPartyPrefixes, allowlist_version: wire.allowlist_version }),
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
      kind: "artifact",
      findingCount: wire.finding_count,
      maxSeverity: wire.max_severity,
      overallRisk: wire.overall_risk,
      scoringVersion: wire.scoring_version,
      allowlistVersion: wire.allowlist_version,
      findings: wire.findings,
    };
  } catch (err) {
    await client.query("ROLLBACK").catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}

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
