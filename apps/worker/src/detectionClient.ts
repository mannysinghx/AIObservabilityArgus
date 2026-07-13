import { config, type Finding, type ObservationInput } from "@argus/shared";

/** Thin client for the Python detection service (services/detection). */

interface ScanObsBody {
  project_id: string;
  observation: {
    observation_id: string;
    trace_id: string;
    parent_id: string;
    type: string;
    name: string;
    content: string;
    role: string;
    taint?: string;
    taint_source: string;
    model: string;
    attributes: Record<string, string>;
  };
  tool_overrides: Record<string, string>;
  enable_l2: boolean;
}

function contentOf(o: ObservationInput): string {
  // The security-relevant text depends on span type:
  //  - generation/retrieval: the produced text (completion / retrieved chunk)
  //  - tool: BOTH arguments (input) and result (output) — exfiltration lives in
  //    the arguments (recipient, body, URL), which a result-only view misses
  //  - span/event/user: whatever text is present
  if (o.type === "generation" || o.type === "retrieval") {
    return o.output || o.input;
  }
  return [o.input, o.output].filter(Boolean).join("\n");
}

export function toScanObs(projectId: string, o: ObservationInput): ScanObsBody {
  return {
    project_id: projectId,
    observation: {
      observation_id: o.observationId,
      trace_id: o.traceId,
      parent_id: o.parentId ?? "",
      type: o.type,
      name: o.name ?? "",
      content: contentOf(o),
      role: o.role ?? "",
      taint: o.taint,
      taint_source: o.taintSource ?? "",
      model: o.model ?? "",
      attributes: o.attributes ?? {},
    },
    tool_overrides: {},
    enable_l2: config.detectionEnableL2,
  };
}

export async function scanObservation(
  projectId: string,
  o: ObservationInput,
): Promise<Finding[]> {
  const res = await fetch(`${config.detectionUrl}/v1/scan`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(toScanObs(projectId, o)),
  });
  if (!res.ok) throw new Error(`detection /v1/scan ${res.status}`);
  const data = (await res.json()) as { findings: Finding[] };
  return data.findings ?? [];
}

export async function scanTrace(
  projectId: string,
  traceId: string,
  observations: ObservationInput[],
  canaries: string[] = [],
): Promise<Finding[]> {
  const body = {
    project_id: projectId,
    trace_id: traceId,
    observations: observations.map((o) => ({
      observation_id: o.observationId,
      trace_id: o.traceId,
      parent_id: o.parentId ?? "",
      type: o.type,
      name: o.name ?? "",
      content: contentOf(o),
      role: o.role ?? "",
      taint: o.taint,
      taint_source: o.taintSource ?? "",
      model: o.model ?? "",
      attributes: o.attributes ?? {},
    })),
    tool_overrides: {},
    canaries,
  };
  const res = await fetch(`${config.detectionUrl}/v1/scan/trace`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`detection /v1/scan/trace ${res.status}`);
  const data = (await res.json()) as { findings: Finding[] };
  return data.findings ?? [];
}
