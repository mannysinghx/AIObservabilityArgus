import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import Fastify from "fastify";
import fastifyStatic from "@fastify/static";
import { config } from "@argus/shared";
import * as Q from "./queries.js";
import * as Onboarding from "./onboarding.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const PUBLIC_DIR = join(__dirname, "..", "public");
const port = Number(process.env.PORT ?? process.env.WEB_PORT ?? 3002);

const app = Fastify({ logger: { level: process.env.LOG_LEVEL ?? "info" } });
await app.register(fastifyStatic, { root: PUBLIC_DIR, prefix: "/" });

app.get("/health", async () => ({ status: (await Q.health()) ? "ok" : "degraded", service: "argus-web" }));

type ScopedQuery = { range?: string; project?: string };

// Wrap a query so a ClickHouse hiccup returns 503 instead of crashing.
// `project` (from ?project=<uuid>) narrows every query to one client's data —
// present on a self-onboarded client's personalized dashboard link, absent
// for the default "all projects" view.
function guard<T>(name: string, fn: (range: string | undefined, projectId: string | undefined) => Promise<T>) {
  app.get(`/api/${name}`, async (req, reply) => {
    try {
      const { range, project } = (req.query as ScopedQuery | undefined) || {};
      return await fn(range, project);
    } catch (err) {
      app.log.error({ err }, `${name} failed`);
      reply.code(503).send({ error: "query failed", detail: String(err) });
    }
  });
}

guard("overview", (r, p) => Q.overview(r, p));
guard("threat", (r, p) => Q.threat(r, p));
guard("attacks", (r, p) => Q.attackFeed(r, 100, p));
guard("incidents", (r, p) => Q.incidents(r, p));
guard("review", (r, p) => Q.reviewQueue(r, p));
guard("sessions", (r, p) => Q.sessions(r, p));
guard("traces", (r, p) => Q.tracesList(r, 100, p));
guard("analytics", (r, p) => Q.analytics(r, p));
guard("prompts", () => Q.prompts());

app.get<{ Params: { id: string }; Querystring: ScopedQuery }>("/api/trace/:id", async (req, reply) => {
  try { return await Q.traceDetail(req.params.id, req.query.project); }
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

// ---------------- Self-service onboarding ----------------

app.post<{ Body: { orgName?: string; projectName?: string } }>("/api/onboarding/projects", async (req, reply) => {
  const orgName = (req.body?.orgName || "").trim();
  const projectName = (req.body?.projectName || "").trim();
  if (!orgName || !projectName) {
    reply.code(400).send({ error: "orgName and projectName are required" });
    return;
  }
  if (orgName.length > 200 || projectName.length > 200) {
    reply.code(400).send({ error: "orgName/projectName must be 200 characters or fewer" });
    return;
  }
  try {
    const project = await Onboarding.createProject(orgName, projectName);
    const ingestUrl =
      process.env.ARGUS_PUBLIC_INGEST_URL || "http://localhost:3001/api/public/ingestion";
    return { ...project, ingestUrl };
  } catch (err) {
    app.log.error({ err }, "onboarding: project creation failed");
    reply.code(500).send({ error: "failed to create project" });
  }
});

app.get<{ Params: { id: string } }>("/api/onboarding/status/:id", async (req, reply) => {
  try {
    return await Onboarding.checkConnectionStatus(req.params.id);
  } catch (err) {
    app.log.error({ err }, "onboarding: status check failed");
    reply.code(503).send({ error: "status check failed" });
  }
});

try {
  await app.listen({ port, host: "0.0.0.0" });
  app.log.info(`argus-web on :${port} (clickhouse: ${config.clickhouseUrl})`);
} catch (err) {
  app.log.error(err);
  process.exit(1);
}
