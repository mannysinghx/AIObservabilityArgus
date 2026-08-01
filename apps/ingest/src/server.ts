import { createHash } from "node:crypto";
import Fastify from "fastify";
import {
  config,
  redis,
  STREAM_KEY,
  IngestBatch,
  PromptEventBatch,
  mapPromptEvent,
  otlpToObservations,
  loadProjectConfig,
  redactObservation,
  rateLimit,
  LIMITS,
  metrics,
  refreshQueueMetrics,
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
  if (req.url === "/health" || req.url === "/metrics") return;
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
    // Unauthenticated attempts are limited by IP so a stolen-key hunt or a
    // credential-stuffing sweep can't run at line rate against Postgres.
    await rateLimit(`ingest-auth:${req.ip}`, 60, 60_000);
    reply.code(401).send({ error: "invalid or missing credentials — send 'Authorization: Bearer <ingest key>'" });
    return;
  }

  // Per-project quota. Telemetry ingest is the one endpoint a customer's own
  // code calls in a loop, so a runaway retry in *their* app is the realistic
  // failure — it fills ClickHouse and the Redis stream for every other tenant
  // sharing the deployment. Limiting by project (not IP) is what makes this a
  // noisy-neighbour control rather than an anti-abuse one.
  const quota = await rateLimit(`ingest:${project.projectId}`, LIMITS.ingest.limit, LIMITS.ingest.windowMs);
  if (!quota.allowed) {
    reply
      .code(429)
      .header("retry-after", String(Math.ceil(quota.resetMs / 1000)))
      .send({ error: "ingest rate limit exceeded for this project", retryAfterMs: quota.resetMs });
    metrics.inc("argus_ingest_rate_limited_total", { project: project.projectId });
    return;
  }

  (req as unknown as { projectId: string }).projectId = project.projectId;
});

app.get("/health", async () => ({ status: "ok", service: "argus-ingest" }));

/**
 * Prometheus scrape target. Deliberately outside the auth hook (which skips
 * /health and now /metrics): a scraper has no API key, and the numbers here are
 * counts and latencies, never customer content. Put it behind your network
 * policy the same way you would any other /metrics.
 */
app.get("/metrics", async (_req, reply) => {
  await refreshQueueMetrics().catch(() => {});
  reply.header("content-type", "text/plain; version=0.0.4").send(metrics.render());
});

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
  metrics.inc("argus_ingest_events_total", { endpoint: "native" }, n, "Telemetry events accepted");
  reply.code(202).send({ accepted: n });
});

/**
 * Browser Guard reports.
 *
 * The extension scans a prompt locally and posts the verdict — never the text.
 * Authentication is the same `ak_live_` key as every other ingestion route (the
 * preHandler above already resolved it to a project), so an extension install is
 * scoped to exactly one application and can write nowhere else.
 *
 * Sampling is deliberately NOT applied. These arrive one per risky prompt rather
 * than one per span, so the volume is a rounding error next to normal telemetry,
 * and dropping a "someone pasted an API key into ChatGPT" report to honour a
 * trace sample rate would be losing the signal to save nothing.
 */
app.post("/api/public/prompt-events", async (req, reply) => {
  const projectId = (req as unknown as { projectId: string }).projectId;
  const parsed = PromptEventBatch.safeParse(req.body);
  if (!parsed.success) {
    reply.code(400).send({ error: "invalid batch", details: parsed.error.issues });
    return;
  }

  const r = redis();
  const pipeline = r.pipeline();
  let accepted = 0;
  let stored = 0;
  for (const ev of parsed.data.events) {
    accepted++;
    const mapped = mapPromptEvent(ev);
    if (!mapped) continue; // clean prompt, or no rule we recognise — see mapPromptEvent
    const push = (e: StreamEvent) => pipeline.xadd(STREAM_KEY, "*", "event", JSON.stringify(e));
    push({ projectId, kind: "trace", payload: mapped.trace });
    push({ projectId, kind: "observation", payload: mapped.observation });
    push({ projectId, kind: "finding", payload: mapped.findings });
    stored++;
  }
  await pipeline.exec();

  metrics.inc("argus_ingest_events_total", { endpoint: "prompt-events" }, stored, "Telemetry events accepted");
  // `accepted` is what the caller sent, `stored` what was worth keeping. The
  // extension uses neither, but the difference is the first thing to look at
  // when someone reports "my reports aren't showing up".
  reply.code(202).send({ accepted, stored });
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
  metrics.inc("argus_ingest_events_total", { endpoint: "otlp" }, n, "Telemetry events accepted");
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
