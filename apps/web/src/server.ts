import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import Fastify from "fastify";
import fastifyStatic from "@fastify/static";
import { config } from "@argus/shared";
import * as Q from "./queries.js";
import * as Onboarding from "./onboarding.js";
import * as Auth from "./auth.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const PUBLIC_DIR = join(__dirname, "..", "public");
const port = Number(process.env.PORT ?? process.env.WEB_PORT ?? 3002);

const app = Fastify({ logger: { level: process.env.LOG_LEVEL ?? "info" } });
await app.register(fastifyStatic, { root: PUBLIC_DIR, prefix: "/" });

type ScopedQuery = { range?: string; project?: string };
type WithUser = { user: Auth.SessionUser | null };
const asUser = (req: unknown): WithUser => req as unknown as WithUser;
const userOf = (req: unknown): Auth.SessionUser | null => asUser(req).user;

app.get("/health", async () => ({ status: (await Q.health()) ? "ok" : "degraded", service: "argus-web" }));

// ---------------- auth gate ----------------
// Resolve the signed-in user for every /api/* request from the session cookie,
// and require one for everything except the auth endpoints themselves. Static
// assets (login.html, the dashboard shell, JS/CSS) stay public — all *data*
// lives behind /api and is gated here.
app.decorateRequest("user", null);
app.addHook("preHandler", async (req, reply) => {
  const path = req.url.split("?")[0];
  if (!path.startsWith("/api/")) return;
  const token = Auth.parseSessionCookie(req.headers.cookie);
  asUser(req).user = await Auth.sessionUser(token);
  if (path.startsWith("/api/auth/")) return; // these manage their own session
  if (!asUser(req).user) {
    reply.code(401).send({ error: "authentication required" });
  }
});

// ---------------- auth routes ----------------
app.post<{ Body: { email?: string; password?: string; name?: string; company?: string } }>(
  "/api/auth/signup",
  async (req, reply) => {
    const { email, password, name, company } = req.body || {};
    const r = await Auth.signup(email || "", password || "", name || "", company || "");
    if ("error" in r) { reply.code(400).send(r); return; }
    reply.header("set-cookie", Auth.sessionCookie(r.token));
    return { user: r.user };
  },
);

app.post<{ Body: { email?: string; password?: string } }>("/api/auth/login", async (req, reply) => {
  const { email, password } = req.body || {};
  const r = await Auth.login(email || "", password || "");
  if ("error" in r) { reply.code(401).send(r); return; }
  reply.header("set-cookie", Auth.sessionCookie(r.token));
  return { user: r.user };
});

app.post("/api/auth/logout", async (req, reply) => {
  await Auth.logout(Auth.parseSessionCookie(req.headers.cookie));
  reply.header("set-cookie", Auth.clearCookie());
  return { ok: true };
});

app.get("/api/auth/me", async (req, reply) => {
  const user = userOf(req);
  if (!user) { reply.code(401).send({ error: "not authenticated" }); return; }
  return { user };
});

// ---------------- scoped data queries ----------------
// Every data view requires a ?project= the caller is a member of. The catalog
// (/api/projects) is the only cross-project endpoint, and it's filtered to the
// user's own organizations.
function guard<T>(name: string, fn: (range: string | undefined, projectId: string) => Promise<T>) {
  app.get(`/api/${name}`, async (req, reply) => {
    const user = userOf(req)!; // preHandler guarantees a user here
    const { range, project } = (req.query as ScopedQuery | undefined) || {};
    if (!project) { reply.code(400).send({ error: "project required" }); return; }
    if (!(await Auth.userCanAccessProject(user.id, project))) {
      reply.code(403).send({ error: "forbidden" });
      return;
    }
    try {
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

// Catalog: only the customers (orgs) this user belongs to, and their apps.
app.get("/api/projects", async (req, reply) => {
  const user = userOf(req)!;
  try { return await Onboarding.listProjectsWithStats(await Auth.userOrgIds(user.id)); }
  catch (err) { app.log.error({ err }, "projects failed"); reply.code(503).send({ error: "query failed", detail: String(err) }); }
});

app.get<{ Params: { id: string } }>("/api/project/:id", async (req, reply) => {
  const user = userOf(req)!;
  if (!(await Auth.userCanAccessProject(user.id, req.params.id))) { reply.code(403).send({ error: "forbidden" }); return; }
  try {
    const meta = await Onboarding.getProjectMeta(req.params.id);
    if (!meta) { reply.code(404).send({ error: "project not found" }); return; }
    return meta;
  } catch (err) { app.log.error({ err }, "project meta failed"); reply.code(503).send({ error: String(err) }); }
});

app.get<{ Params: { id: string }; Querystring: ScopedQuery }>("/api/trace/:id", async (req, reply) => {
  const user = userOf(req)!;
  const project = req.query.project;
  if (!project || !(await Auth.userCanAccessProject(user.id, project))) { reply.code(403).send({ error: "forbidden" }); return; }
  try { return await Q.traceDetail(req.params.id, project); }
  catch (err) { app.log.error({ err }, "trace failed"); reply.code(503).send({ error: String(err) }); }
});

// Analyst action: set a verdict on a security event (scoped to the event's project).
app.post<{ Body: { eventId?: string; verdict?: string; project?: string } }>("/api/verdict", async (req, reply) => {
  const user = userOf(req)!;
  const { eventId, verdict, project } = req.body || {};
  if (!eventId || !verdict) { reply.code(400).send({ error: "eventId and verdict required" }); return; }
  if (!project || !(await Auth.userCanAccessProject(user.id, project))) { reply.code(403).send({ error: "forbidden" }); return; }
  try {
    const ok = await Q.setVerdict(eventId, verdict);
    if (!ok) { reply.code(404).send({ error: "event not found" }); return; }
    return { ok: true, eventId, verdict };
  } catch (err) {
    app.log.error({ err }, "verdict failed");
    reply.code(500).send({ error: String(err) });
  }
});

// ---------------- onboarding (add an app to your org) ----------------
app.post<{ Body: { projectName?: string; orgId?: string } }>("/api/onboarding/projects", async (req, reply) => {
  const user = userOf(req)!;
  const projectName = (req.body?.projectName || "").trim();
  if (!projectName) { reply.code(400).send({ error: "projectName is required" }); return; }
  if (projectName.length > 200) { reply.code(400).send({ error: "projectName must be 200 characters or fewer" }); return; }
  try {
    const project = await Onboarding.createProject(user.id, projectName, req.body?.orgId);
    const ingestUrl =
      process.env.ARGUS_PUBLIC_INGEST_URL || "http://localhost:3001/api/public/ingestion";
    return { ...project, ingestUrl };
  } catch (err) {
    app.log.error({ err }, "onboarding: project creation failed");
    reply.code(500).send({ error: "failed to create project" });
  }
});

app.get<{ Params: { id: string } }>("/api/onboarding/status/:id", async (req, reply) => {
  const user = userOf(req)!;
  if (!(await Auth.userCanAccessProject(user.id, req.params.id))) { reply.code(403).send({ error: "forbidden" }); return; }
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
