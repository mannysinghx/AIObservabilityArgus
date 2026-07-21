import { createHash } from "node:crypto";
import Fastify from "fastify";
import {
  config,
  redis,
  STREAM_KEY,
  IngestBatch,
  otlpToObservations,
  loadProjectConfig,
  redactObservation,
  type OtlpTracePayload,
  type StreamEvent,
  type ObservationInput,
  type TraceInput,
} from "@argus/shared";
import { authenticate, authenticateToken, parseBasicAuth, parseBearer } from "./auth.js";

// Deterministic head sampling: the same traceId always resolves to the same
// keep/drop decision, so every event of a trace — spans and the trace summary,
// even across separate batches — is kept or dropped together. Stateless: a hash
// of the id mapped into [0,1), compared to the rate.
function keepTrace(traceId: string, rate: number): boolean {
  if (rate >= 1) return true;
  if (rate <= 0) return false;
  const v = createHash("sha1").update(traceId).digest().readUInt32BE(0) / 0xffffffff;
  return v < rate;
}

const app = Fastify({
  logger: { level: process.env.LOG_LEVEL ?? "info" },
  bodyLimit: 16 * 1024 * 1024,
});

async function pushEvents(projectId: string, batch: IngestBatch): Promise<number> {
  // Per-application config decides sampling + redaction. Cached (~30s) and fails
  // open to permissive defaults, so this adds negligible latency and a config
  // problem can never drop a customer's telemetry on the floor.
  const cfg = await loadProjectConfig(projectId);
  const rate = cfg.sampling.trace_sample_rate;
  const redactMode = cfg.redaction.mode;

  const r = redis();
  const pipeline = r.pipeline();
  let n = 0;
  for (const trace of batch.traces) {
    if (!keepTrace((trace as TraceInput).traceId, rate)) continue;
    const ev: StreamEvent = { projectId, kind: "trace", payload: trace as TraceInput };
    pipeline.xadd(STREAM_KEY, "*", "event", JSON.stringify(ev));
    n++;
  }
  for (const obs of batch.observations) {
    if (!keepTrace((obs as ObservationInput).traceId, rate)) continue;
    // Redact BEFORE it leaves the ingress — the raw text is never stored, and
    // (for mask_pii) injection payloads survive so detection still works.
    const payload = redactObservation(obs as ObservationInput, redactMode);
    const ev: StreamEvent = { projectId, kind: "observation", payload };
    pipeline.xadd(STREAM_KEY, "*", "event", JSON.stringify(ev));
    n++;
  }
  await pipeline.exec();
  return n;
}

// ---- auth guard ----
app.decorateRequest("projectId", "");
app.addHook("preHandler", async (req, reply) => {
  if (req.url === "/health") return;
  const header = req.headers.authorization;

  // Preferred: a single write-only ingest key — `Authorization: Bearer ak_live_…`.
  // Fallback: the original publicKey:secret Basic auth, so existing
  // integrations keep working unchanged.
  let project = null;
  const token = parseBearer(header);
  if (token) {
    project = await authenticateToken(token);
  } else {
    const basic = parseBasicAuth(header);
    if (basic) project = await authenticate(basic.user, basic.pass);
  }

  if (!project) {
    reply.code(401).send({ error: "invalid or missing credentials — send 'Authorization: Bearer <ingest key>'" });
    return;
  }
  (req as unknown as { projectId: string }).projectId = project.projectId;
});

app.get("/health", async () => ({ status: "ok", service: "argus-ingest" }));

/**
 * Native / Langfuse-style batch endpoint. Body: { traces[], observations[] }.
 * Returns 202 immediately after enqueuing.
 */
app.post("/api/public/ingestion", async (req, reply) => {
  const projectId = (req as unknown as { projectId: string }).projectId;
  const parsed = IngestBatch.safeParse(req.body);
  if (!parsed.success) {
    reply.code(400).send({ error: "invalid batch", details: parsed.error.issues });
    return;
  }
  const n = await pushEvents(projectId, parsed.data);
  reply.code(202).send({ accepted: n });
});

/**
 * OTLP/HTTP JSON traces endpoint. Accepts OpenTelemetry GenAI spans and
 * normalizes them into observations before enqueuing.
 */
app.post("/v1/traces", async (req, reply) => {
  const projectId = (req as unknown as { projectId: string }).projectId;
  let observations: ObservationInput[];
  try {
    observations = otlpToObservations(req.body as OtlpTracePayload);
  } catch (err) {
    reply.code(400).send({ error: "invalid OTLP payload", detail: String(err) });
    return;
  }
  const n = await pushEvents(projectId, {
    traces: [],
    observations,
  } as unknown as IngestBatch);
  reply.code(202).send({ partialSuccess: {}, accepted: n });
});

const start = async () => {
  try {
    await app.listen({ port: config.ingestPort, host: "0.0.0.0" });
    app.log.info(`argus-ingest listening on :${config.ingestPort}`);
  } catch (err) {
    app.log.error(err);
    process.exit(1);
  }
};
start();
