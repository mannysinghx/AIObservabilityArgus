import { config, contentOf, type CanaryRef, type Finding, type ObservationInput } from "@argus/shared";

/** Thin client for the Python detection service (services/detection). */

/** Auth header for detection calls. Omitted entirely when no key is configured,
 *  so this stays compatible with a detection service that has none. */
function detectionHeaders(): Record<string, string> {
  const h: Record<string, string> = { "content-type": "application/json" };
  if (config.detectionApiKey) h.authorization = `Bearer ${config.detectionApiKey}`;
  return h;
}

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

export function toScanObs(projectId: string, o: ObservationInput, enableL2: boolean): ScanObsBody {
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
    enable_l2: enableL2,
  };
}

export async function scanObservation(
  projectId: string,
  o: ObservationInput,
  // Per-project L2 toggle from the app's Settings; falls back to the global env
  // default when a caller doesn't supply one.
  enableL2: boolean = config.detectionEnableL2,
): Promise<Finding[]> {
  const res = await fetch(`${config.detectionUrl}/v1/scan`, {
    method: "POST",
    headers: detectionHeaders(),
    body: JSON.stringify(toScanObs(projectId, o, enableL2)),
  });
  if (!res.ok) throw new Error(`detection /v1/scan ${res.status}`);
  const data = (await res.json()) as { findings: Finding[] };
  return data.findings ?? [];
}

export async function scanTrace(
  projectId: string,
  traceId: string,
  observations: ObservationInput[],
  canaryRefs: CanaryRef[] = [],
): Promise<Finding[]> {
  const body = {
    project_id: projectId,
    trace_id: traceId,
    // Generated canaries travel as hashes only. The detection service handles
    // hostile text all day; anything it doesn't hold, it can't leak.
    canary_refs: canaryRefs.map((c) => ({
      id: c.id,
      label: c.label,
      kind: c.kind,
      token_hash: c.tokenHash,
      value: c.value,
    })),
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
  };
  const res = await fetch(`${config.detectionUrl}/v1/scan/trace`, {
    method: "POST",
    headers: detectionHeaders(),
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`detection /v1/scan/trace ${res.status}`);
  const data = (await res.json()) as { findings: Finding[] };
  return data.findings ?? [];
}
