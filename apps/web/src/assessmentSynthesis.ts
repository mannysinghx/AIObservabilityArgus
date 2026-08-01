/**
 * Phase 4 — synthesis: the runtime half informing the static half.
 *
 * Assessment has so far judged an application from what a human declared about
 * it. But Argus already *watches* the application run, and that record is a
 * better witness than a form: it knows which components actually exist, which
 * of them read untrusted content, and which attack classes have genuinely been
 * attempted in production. Two functions here close that loop:
 *
 *   deriveGraph()        — build a proposed architecture graph from observed spans
 *   observedCategories() — which attack classes this project has actually seen
 *
 * Both read ClickHouse through query_params rather than string interpolation.
 * The dashboard's own queries build SQL by concatenation and are safe because
 * their inputs are sanitized identifiers — but that safety is a property of the
 * callers. These are new, so they get the stronger form (the same reasoning
 * publicApi.ts records).
 */
import { ch } from "@argus/shared";
import { safeProjectId } from "./ids.js";
import type { GraphEdgeIn, GraphNodeIn } from "./assessments.js";

async function q<T>(sql: string, params: Record<string, unknown>): Promise<T[]> {
  const rs = await ch().query({ query: sql, query_params: params, format: "JSONEachRow" });
  return rs.json<T>();
}

// Observation type → architecture node type. `span` and `event` carry no
// architectural meaning on their own, so they are skipped rather than guessed
// at: a graph full of "other" nodes is noise a user then has to delete.
const TYPE_TO_NODE: Record<string, string> = {
  generation: "model",
  retrieval: "document_source",
  tool: "tool",
};

/**
 * Tools whose names suggest they change something outside the app. Used only to
 * PRE-TICK "can write" on a proposed graph the user reviews before saving —
 * never to decide anything on its own. A false positive here costs one unticked
 * box; a false negative costs a rule that should have fired.
 */
const WRITE_HINT = /\b(send|email|post|write|delete|remove|create|update|insert|pay|charge|refund|transfer|wire|purchase|order|execute|run|deploy|revoke|grant)\b|_(send|write|delete|update|create)/i;

interface SpanRow { type: string; name: string; untrusted: number; n: string }
interface EdgeRow { ptype: string; pname: string; ctype: string; cname: string; n: string }

/**
 * A proposed architecture graph derived from this project's traces.
 *
 * Deliberately a PROPOSAL: the caller hands it to the editor unsaved so a human
 * confirms it. Traces can prove a component exists and that it read untrusted
 * content; they cannot prove whether a human approves a write, which is exactly
 * the fact the highest-severity architecture rules turn on. Silently overwriting
 * a curated graph with an inferred one would quietly answer that question wrong.
 */
export async function deriveGraph(
  projectId: string,
  limit = 40,
): Promise<{ nodes: GraphNodeIn[]; edges: GraphEdgeIn[]; observations: number }> {
  const safe = safeProjectId(projectId);
  if (!safe) return { nodes: [], edges: [], observations: 0 };

  // Distinct components. `untrusted` is max() rather than any(): if a component
  // EVER handled untrusted content, that is the trust level to carry into the
  // analysis — the risky case is the one that matters.
  const spans = await q<SpanRow>(
    `SELECT toString(type) AS type,
            name,
            max(taint = 'untrusted_external') AS untrusted,
            count() AS n
     FROM observations FINAL
     WHERE project_id = {project:String} AND name != ''
     GROUP BY type, name
     ORDER BY n DESC
     LIMIT {lim:UInt32}`,
    { project: safe, lim: limit },
  );

  const nodes: GraphNodeIn[] = [];
  const idFor = new Map<string, string>(); // "type|name" → node id
  for (const s of spans) {
    const nodeType = TYPE_TO_NODE[s.type];
    if (!nodeType) continue;
    const id = "d" + (nodes.length + 1);
    idFor.set(`${s.type}|${s.name}`, id);
    nodes.push({
      id,
      label: s.name,
      node_type: nodeType,
      // A retrieval span is untrusted by definition of the taint model; a tool
      // or model span is untrusted only if it was actually observed handling
      // untrusted content.
      trust_level: nodeType === "document_source" || Number(s.untrusted) === 1 ? "untrusted" : "trusted",
      can_write: nodeType === "tool" && WRITE_HINT.test(s.name),
      // Never inferred — see the doc comment. The user ticks this.
      requires_approval: false,
      attributes: {},
    });
  }

  // Parent → child relationships become connections. BOTH sides of the join are
  // scoped to the project: trace and observation ids are caller-supplied at
  // ingest and are not unique across tenants, so a join scoped on one side only
  // is a cross-tenant read. (Same trap as tracesList/sessions in queries.ts.)
  const edgeRows = nodes.length
    ? await q<EdgeRow>(
        `SELECT toString(p.type) AS ptype, p.name AS pname,
                toString(c.type) AS ctype, c.name AS cname,
                count() AS n
         FROM observations AS c
         INNER JOIN observations AS p
           ON c.parent_id = p.observation_id AND c.project_id = p.project_id
         WHERE c.project_id = {project:String}
           AND p.project_id = {project:String}
           AND c.parent_id != '' AND c.name != '' AND p.name != ''
         GROUP BY ptype, pname, ctype, cname
         ORDER BY n DESC
         LIMIT {lim:UInt32}`,
        { project: safe, lim: limit * 2 },
      )
    : [];

  const edges: GraphEdgeIn[] = [];
  const seen = new Set<string>();
  for (const e of edgeRows) {
    const src = idFor.get(`${e.ptype}|${e.pname}`);
    const dst = idFor.get(`${e.ctype}|${e.cname}`);
    if (!src || !dst || src === dst) continue;
    const key = `${src}>${dst}`;
    if (seen.has(key)) continue;
    seen.add(key);
    edges.push({
      source: src,
      target: dst,
      // What flows is read off the destination: a model invoked under a span is
      // being prompted; a tool being called is an invocation; a retrieval is a
      // data read.
      edge_type: e.ctype === "generation" ? "sends_prompt" : e.ctype === "tool" ? "invokes" : "retrieves_data",
      tenant_boundary: false, // not observable from a trace — the user decides
      name: "",
    });
  }

  const observations = spans.reduce((t, s) => t + Number(s.n || 0), 0);
  return { nodes, edges, observations };
}

/**
 * Argus security-event categories this project has actually seen.
 *
 * This is the evidence that turns a theoretical weakness into a demonstrated
 * one. A prompt that mixes instructions with untrusted data is a medium concern
 * in the abstract; it is a different conversation when the same application has
 * logged indirect-injection attempts all week. Only categories with a real
 * attempt count are returned — `unknown`-outcome noise is excluded so a single
 * low-confidence blip can't inflate every future score.
 */
export async function observedCategories(projectId: string, days = 30): Promise<string[]> {
  const safe = safeProjectId(projectId);
  if (!safe) return [];
  const rows = await q<{ category: string }>(
    `SELECT toString(category) AS category
     FROM security_events FINAL
     WHERE project_id = {project:String}
       AND detected_at >= now() - INTERVAL {days:UInt32} DAY
       AND outcome IN ('attempted', 'succeeded')
     GROUP BY category
     HAVING count() > 0`,
    { project: safe, days },
  );
  return rows.map((r) => r.category).filter(Boolean);
}
