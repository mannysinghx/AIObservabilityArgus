/**
 * Argus gateway — an OpenAI-compatible inline proxy.
 *
 * Point your SDK's base URL here instead of at the provider and Argus can
 * *refuse* a prompt-injection attempt rather than merely report it afterwards.
 * It also emits a trace for every call, so pointing at the gateway gives you
 * observability with no SDK change at all.
 *
 *   client = OpenAI(base_url="https://argus-gateway.you.com/v1",
 *                   api_key=YOUR_OPENAI_KEY,
 *                   default_headers={"x-argus-key": "ak_live_…"})
 *
 * Two credentials, deliberately: the provider key is the customer's and is
 * forwarded untouched (Argus never stores it), and the Argus key identifies the
 * project. Mixing them would mean holding someone's OpenAI billing credential.
 *
 * THE OPERATING PRINCIPLE: this is the only part of Argus on a customer's
 * critical path. Every ambiguous case resolves toward "let the request
 * through". A security proxy that takes production down is uninstalled within
 * the week, and then it protects nothing at all.
 */
import Fastify from "fastify";
import {
  evaluate,
  gatewayPolicyFromEnv,
  loadProjectConfig,
  metrics,
  redis,
  STREAM_KEY,
  withProjectSettings,
  type StreamEvent,
  type ObservationInput,
  type TraceInput,
} from "@argus/shared";
import { randomUUID } from "node:crypto";
import { authenticateKey, hasScope, parseBearer } from "@argus/shared";

const app = Fastify({
  logger: { level: process.env.LOG_LEVEL ?? "info" },
  bodyLimit: 16 * 1024 * 1024,
});

const policy = gatewayPolicyFromEnv();
const UPSTREAM = (process.env.GATEWAY_UPSTREAM ?? "https://api.openai.com").replace(/\/$/, "");
const PORT = Number(process.env.PORT ?? process.env.GATEWAY_PORT ?? 3004);

app.log.info(
  { mode: policy.mode, blockThreshold: policy.blockThreshold, latencyBudgetMs: policy.latencyBudgetMs, onFailure: policy.onFailure, upstream: UPSTREAM },
  "gateway policy",
);

app.get("/health", async () => ({ status: "ok", service: "argus-gateway", mode: policy.mode, upstream: UPSTREAM }));
app.get("/metrics", async (_req, reply) => {
  reply.header("content-type", "text/plain; version=0.0.4").send(metrics.render());
});

// ---------------------------------------------------------------- auth
interface Keyed { projectId: string }
const projectOf = (req: unknown): string => (req as Keyed).projectId;

app.decorateRequest("projectId", "");
app.addHook("preHandler", async (req, reply) => {
  const path = req.url.split("?")[0];
  if (path === "/health" || path === "/metrics") return;

  // The Argus key travels in its own header so the Authorization header stays
  // exactly as the provider SDK set it — that one is the customer's provider
  // credential and is forwarded verbatim.
  const raw = req.headers["x-argus-key"];
  const token = (Array.isArray(raw) ? raw[0] : raw)?.trim() || parseBearer(req.headers["x-argus-authorization"] as string);
  if (!token) {
    reply.code(401).send({ error: { message: "Missing x-argus-key header.", type: "argus_auth" } });
    return;
  }
  const key = await authenticateKey(token);
  if (!key || !hasScope(key, "ingest")) {
    reply.code(401).send({ error: { message: "Invalid Argus key, or it lacks the 'ingest' scope.", type: "argus_auth" } });
    return;
  }
  (req as unknown as Keyed).projectId = key.projectId;
});

// ---------------------------------------------------------------- helpers

interface ChatMessage { role?: string; content?: unknown }
interface ChatBody { messages?: ChatMessage[]; model?: string; stream?: boolean }

/**
 * The text to scan: the user's turn(s) only.
 *
 * Never the system prompt. A system prompt is by nature a list of imperative
 * instructions, so scanning it would match injection heuristics on every single
 * request — the detector would be perfectly correct and completely useless.
 * Assistant turns are excluded too: those are our own model's prior output, and
 * anything wrong with them is L4's job, with the trace context to judge it.
 */
function userText(body: ChatBody): string {
  const parts: string[] = [];
  for (const m of body.messages ?? []) {
    if (m.role !== "user") continue;
    if (typeof m.content === "string") parts.push(m.content);
    else if (Array.isArray(m.content)) {
      // The multimodal shape: [{type:"text", text:"..."}, {type:"image_url",…}]
      for (const part of m.content as Array<{ type?: string; text?: string }>) {
        if (part?.type === "text" && typeof part.text === "string") parts.push(part.text);
      }
    }
  }
  return parts.join("\n");
}

/** Emit a trace for this call. Fire-and-forget: telemetry must never delay or
 *  fail a proxied request. */
function emitTrace(projectId: string, opts: {
  model: string; input: string; output: string; blocked: boolean;
  startedAt: number; inputTokens?: number; outputTokens?: number;
}): void {
  const traceId = `gw-${randomUUID()}`;
  const now = new Date().toISOString();
  const trace: TraceInput = {
    traceId, name: "gateway.chat", sessionId: "", userId: "",
    timestamp: new Date(opts.startedAt).toISOString(),
    environment: process.env.GATEWAY_ENVIRONMENT ?? "gateway",
    release: "", metadata: { blocked: String(opts.blocked) }, tags: ["gateway"],
  };
  const obs: ObservationInput = {
    observationId: `gw-obs-${randomUUID()}`, traceId, parentId: "",
    type: "generation", name: opts.model || "chat.completions",
    startTime: new Date(opts.startedAt).toISOString(), endTime: now,
    model: opts.model, provider: "gateway", role: "user",
    input: opts.input, output: opts.output,
    inputTokens: opts.inputTokens ?? 0, outputTokens: opts.outputTokens ?? 0,
    costUsd: 0, finishReason: opts.blocked ? "argus_blocked" : "stop",
    taint: "user", taintSource: "", attributes: {},
  };
  const r = redis();
  const push = (ev: StreamEvent) => r.xadd(STREAM_KEY, "*", "event", JSON.stringify(ev));
  Promise.all([
    push({ projectId, kind: "observation", payload: obs }),
    push({ projectId, kind: "trace", payload: trace }),
  ]).catch((err) => app.log.warn({ err }, "gateway trace emit failed"));
}

// ---------------------------------------------------------------- proxy

app.post("/v1/chat/completions", async (req, reply) => {
  const projectId = projectOf(req);
  const body = (req.body ?? {}) as ChatBody;
  const startedAt = Date.now();
  const model = String(body.model ?? "");
  const input = userText(body);

  // Per-project overrides on top of the deployment default. loadProjectConfig
  // is cached ~30s and already fails open to defaults, but it is wrapped again
  // here: a settings lookup is not a reason to fail a customer's request, and
  // this file's whole contract is that every ambiguous case lets traffic
  // through. Falling back to `policy` keeps the deployment-wide behaviour,
  // which is exactly what happened before per-project settings existed.
  let effective = policy;
  try {
    const cfg = await loadProjectConfig(projectId);
    effective = withProjectSettings(policy, cfg.gateway);
  } catch (err) {
    app.log.warn({ err }, "gateway project settings unavailable, using deployment policy");
  }

  const verdict = await evaluate(projectId, input, effective);
  metrics.observe("gateway_scan_duration_ms", verdict.latencyMs, { mode: effective.mode });
  if (verdict.degraded) metrics.inc("gateway_scan_degraded_total", { failure: effective.onFailure });

  if (verdict.blocked) {
    metrics.inc("gateway_blocked_total", { category: verdict.category || "unavailable" });
    emitTrace(projectId, {
      model, input, output: `[argus blocked: ${verdict.reason}]`,
      blocked: true, startedAt,
    });
    app.log.warn({ projectId, category: verdict.category, score: verdict.score }, "gateway blocked a request");
    // 403 in the provider's error shape, so an OpenAI SDK surfaces it as a
    // normal API error the caller can catch rather than a parse failure.
    reply.code(403).send({
      error: {
        message: `Blocked by Argus: ${verdict.category || "policy"}. ${verdict.reason}`,
        type: "argus_blocked",
        code: "prompt_injection_detected",
        param: null,
      },
    });
    return;
  }

  // `effective`, not `policy`: with per-project settings the mode that actually
  // decided this request may differ from the deployment default, and a metric
  // that reports the wrong one makes "why wasn't this blocked?" unanswerable.
  metrics.inc("gateway_allowed_total", { mode: effective.mode });

  // Forward upstream with the caller's own Authorization header untouched.
  let upstreamRes: Response;
  try {
    const headers: Record<string, string> = { "content-type": "application/json" };
    const auth = req.headers.authorization;
    if (auth) headers.authorization = auth;
    const org = req.headers["openai-organization"];
    if (typeof org === "string") headers["openai-organization"] = org;

    upstreamRes = await fetch(`${UPSTREAM}/v1/chat/completions`, {
      method: "POST",
      headers,
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(Number(process.env.GATEWAY_UPSTREAM_TIMEOUT_MS ?? 120_000)),
    });
  } catch (err) {
    metrics.inc("gateway_upstream_errors_total");
    app.log.error({ err }, "gateway upstream request failed");
    reply.code(502).send({ error: { message: `Upstream request failed: ${String(err)}`, type: "argus_upstream" } });
    return;
  }

  const text = await upstreamRes.text();

  // Streaming is passed through untouched. Argus does not currently scan model
  // output on this path — a streamed response would have to be buffered to do
  // it, which would remove the only reason anyone streams. The async pipeline
  // still scans the completion moments later.
  if (body.stream) {
    metrics.inc("gateway_streamed_total");
    reply.code(upstreamRes.status)
      .header("content-type", upstreamRes.headers.get("content-type") ?? "text/event-stream")
      .send(text);
    emitTrace(projectId, { model, input, output: "[streamed]", blocked: false, startedAt });
    return;
  }

  let completion = "";
  let usage: { prompt_tokens?: number; completion_tokens?: number } | undefined;
  try {
    const parsed = JSON.parse(text) as {
      choices?: Array<{ message?: { content?: string } }>;
      usage?: { prompt_tokens?: number; completion_tokens?: number };
    };
    completion = parsed.choices?.[0]?.message?.content ?? "";
    usage = parsed.usage;
  } catch {
    /* non-JSON upstream error body — pass it through as-is */
  }

  emitTrace(projectId, {
    model, input, output: completion, blocked: false, startedAt,
    inputTokens: usage?.prompt_tokens, outputTokens: usage?.completion_tokens,
  });

  reply.code(upstreamRes.status)
    .header("content-type", upstreamRes.headers.get("content-type") ?? "application/json")
    .send(text);
});

/** Everything else on /v1 is proxied unscanned (models, embeddings, …). */
app.all("/v1/*", async (req, reply) => {
  try {
    const headers: Record<string, string> = { "content-type": "application/json" };
    const auth = req.headers.authorization;
    if (auth) headers.authorization = auth;
    const res = await fetch(`${UPSTREAM}${req.url}`, {
      method: req.method,
      headers,
      body: req.method === "GET" || req.method === "HEAD" ? undefined : JSON.stringify(req.body ?? {}),
      signal: AbortSignal.timeout(60_000),
    });
    const text = await res.text();
    reply.code(res.status).header("content-type", res.headers.get("content-type") ?? "application/json").send(text);
  } catch (err) {
    reply.code(502).send({ error: { message: `Upstream request failed: ${String(err)}`, type: "argus_upstream" } });
  }
});

try {
  await app.listen({ port: PORT, host: "0.0.0.0" });
  app.log.info(`argus-gateway on :${PORT} → ${UPSTREAM} (mode: ${policy.mode})`);
} catch (err) {
  app.log.error(err);
  process.exit(1);
}
