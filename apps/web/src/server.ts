import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import Fastify from "fastify";
import fastifyStatic from "@fastify/static";
import { config } from "@argus/shared";
import * as Q from "./queries.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const PUBLIC_DIR = join(__dirname, "..", "public");
const port = Number(process.env.PORT ?? process.env.WEB_PORT ?? 3002);

const app = Fastify({ logger: { level: process.env.LOG_LEVEL ?? "info" } });
await app.register(fastifyStatic, { root: PUBLIC_DIR, prefix: "/" });

app.get("/health", async () => ({ status: (await Q.health()) ? "ok" : "degraded", service: "argus-web" }));

// Wrap a query so a ClickHouse hiccup returns 503 instead of crashing.
function guard<T>(name: string, fn: (range?: string) => Promise<T>) {
  app.get(`/api/${name}`, async (req, reply) => {
    try {
      const range = (req.query as { range?: string } | undefined)?.range;
      return await fn(range);
    } catch (err) {
      app.log.error({ err }, `${name} failed`);
      reply.code(503).send({ error: "query failed", detail: String(err) });
    }
  });
}

guard("overview", Q.overview);
guard("threat", Q.threat);
guard("attacks", (r) => Q.attackFeed(r));
guard("incidents", Q.incidents);
guard("review", Q.reviewQueue);
guard("sessions", Q.sessions);
guard("traces", (r) => Q.tracesList(r));
guard("analytics", Q.analytics);
guard("prompts", () => Q.prompts());

app.get<{ Params: { id: string } }>("/api/trace/:id", async (req, reply) => {
  try { return await Q.traceDetail(req.params.id); }
  catch (err) { app.log.error({ err }, "trace failed"); reply.code(503).send({ error: String(err) }); }
});

// Analyst action: set a verdict on a security event.
app.post<{ Body: { eventId?: string; verdict?: string } }>("/api/verdict", async (req, reply) => {
  const { eventId, verdict } = req.body || {};
  if (!eventId || !verdict) { reply.code(400).send({ error: "eventId and verdict required" }); return; }
  try {
    const ok = await Q.setVerdict(eventId, verdict);
    if (!ok) { reply.code(404).send({ error: "event not found" }); return; }
    return { ok: true, eventId, verdict };
  } catch (err) {
    app.log.error({ err }, "verdict failed");
    reply.code(500).send({ error: String(err) });
  }
});

try {
  await app.listen({ port, host: "0.0.0.0" });
  app.log.info(`argus-web on :${port} (clickhouse: ${config.clickhouseUrl})`);
} catch (err) {
  app.log.error(err);
  process.exit(1);
}
