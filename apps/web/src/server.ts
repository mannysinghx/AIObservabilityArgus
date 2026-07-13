import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import Fastify from "fastify";
import fastifyStatic from "@fastify/static";
import { config } from "@argus/shared";
import {
  analytics,
  attackFeed,
  health,
  overview,
  traceDetail,
  tracesList,
} from "./queries.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const PUBLIC_DIR = join(__dirname, "..", "public");

// PORT (Railway) or WEB_PORT locally, default 3002.
const port = Number(process.env.PORT ?? process.env.WEB_PORT ?? 3002);

const app = Fastify({ logger: { level: process.env.LOG_LEVEL ?? "info" } });

await app.register(fastifyStatic, { root: PUBLIC_DIR, prefix: "/" });

app.get("/health", async () => ({ status: (await health()) ? "ok" : "degraded", service: "argus-web" }));

// Wrap query handlers so a ClickHouse hiccup returns a clean 503, not a crash.
function route(name: string, fn: () => Promise<unknown>) {
  app.get(`/api/${name}`, async (_req, reply) => {
    try {
      return await fn();
    } catch (err) {
      app.log.error({ err }, `query ${name} failed`);
      reply.code(503).send({ error: "query failed", detail: String(err) });
    }
  });
}

route("overview", overview);
route("attacks", () => attackFeed(80));
route("traces", () => tracesList(80));
route("analytics", analytics);

app.get<{ Params: { id: string } }>("/api/trace/:id", async (req, reply) => {
  try {
    return await traceDetail(req.params.id);
  } catch (err) {
    app.log.error({ err }, "trace detail failed");
    reply.code(503).send({ error: "query failed", detail: String(err) });
  }
});

// Public-facing service: bind 0.0.0.0 (matches the proven ingest service). It
// only calls ClickHouse outbound, so it needs no inbound IPv6 private network.
try {
  await app.listen({ port, host: "0.0.0.0" });
  app.log.info(`argus-web on :${port} (clickhouse: ${config.clickhouseUrl})`);
} catch (err) {
  app.log.error(err);
  process.exit(1);
}
