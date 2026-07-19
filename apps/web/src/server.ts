import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import Fastify from "fastify";
import fastifyStatic from "@fastify/static";
import { config } from "@argus/shared";
import * as Q from "./queries.js";
import * as Onboarding from "./onboarding.js";
import * as Auth from "./auth.js";
import * as Admin from "./admin.js";
import * as Audit from "./audit.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const PUBLIC_DIR = join(__dirname, "..", "public");
const port = Number(process.env.PORT ?? process.env.WEB_PORT ?? 3002);

const app = Fastify({ logger: { level: process.env.LOG_LEVEL ?? "info" } });
await app.register(fastifyStatic, { root: PUBLIC_DIR, prefix: "/" });

type ScopedQuery = { range?: string; project?: string };
type WithUser = { user: Auth.SessionUser | null };
const asUser = (req: unknown): WithUser => req as unknown as WithUser;
const userOf = (req: unknown): Auth.SessionUser | null => asUser(req).user;

// Fire-and-forget audit record with the acting user + client IP attached.
function audit(req: unknown, action: string, opts: Partial<Audit.RecordOpts> = {}): void {
  const u = userOf(req);
  const ip = (req as { ip?: string }).ip;
  void Audit.record(action, { actor: u?.id, actorEmail: u?.email, ip, ...opts });
}

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
  const u = asUser(req).user;
  if (!u) {
    reply.code(401).send({ error: "authentication required" });
    return;
  }
  // Optional hard gate: block data access until the email is verified. Off by
  // default (verification is a nudge); set REQUIRE_EMAIL_VERIFICATION=1 to enforce.
  if (process.env.REQUIRE_EMAIL_VERIFICATION === "1" && !u.emailVerified) {
    reply.code(403).send({ error: "email not verified" });
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
    void Audit.record("user.signup", { actor: r.user.id, actorEmail: r.user.email, ip: (req as { ip?: string }).ip });
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
  return { user, emailConfigured: Auth.emailConfigured() };
});

// Verification link target (from the email). Public — the token is the credential.
app.get<{ Querystring: { token?: string } }>("/api/auth/verify", async (req, reply) => {
  const r = await Auth.verifyEmailToken(req.query.token || "");
  reply.redirect("error" in r ? "/login.html?verify_error=1" : "/login.html?verified=1");
});

// Password reset (public). Request always returns ok (no account enumeration).
app.post<{ Body: { email?: string } }>("/api/auth/forgot", async (req, reply) => {
  try { await Auth.requestPasswordReset(req.body?.email || ""); } catch (err) { app.log.error({ err }, "forgot failed"); }
  return { ok: true };
});

app.post<{ Body: { token?: string; password?: string } }>("/api/auth/reset", async (req, reply) => {
  const r = await Auth.resetPassword(req.body?.token || "", req.body?.password || "");
  if ("error" in r) { reply.code(400).send(r); return; }
  return r;
});

// Re-send the verification email for the signed-in user.
app.post("/api/auth/resend", async (req, reply) => {
  const user = userOf(req);
  if (!user) { reply.code(401).send({ error: "not authenticated" }); return; }
  try { return await Auth.resendVerification(user.id, user.email, user.name); }
  catch (err) { app.log.error({ err }, "resend failed"); reply.code(500).send({ error: "could not resend" }); }
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
    if (!user.isPlatformAdmin && !(await Auth.userCanAccessProject(user.id, project))) {
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
guard("prompts", (_r, p) => Q.prompts(p));

// Catalog: by default, ONLY the companies this user belongs to — for everyone,
// platform admins included. This is the landing view, so defaulting a platform
// admin to every customer's applications made the product open on what looks
// like an operator console instead of their own company.
//
// Cross-tenant listing is still available to platform admins, but only when
// asked for explicitly (?all=1) from the admin area — never implicitly.
app.get("/api/projects", async (req, reply) => {
  const user = userOf(req)!;
  const wantsAll = (req.query as { all?: string } | undefined)?.all === "1";
  const crossTenant = wantsAll && user.isPlatformAdmin;
  try {
    const orgIds = crossTenant ? await Auth.allOrgIds() : await Auth.userOrgIds(user.id);
    return await Onboarding.listProjectsWithStats(orgIds);
  } catch (err) { app.log.error({ err }, "projects failed"); reply.code(503).send({ error: "query failed", detail: String(err) }); }
});

app.get<{ Params: { id: string } }>("/api/project/:id", async (req, reply) => {
  const user = userOf(req)!;
  const role = user.isPlatformAdmin ? "owner" : await Auth.userRoleForProject(user.id, req.params.id);
  if (!role) { reply.code(403).send({ error: "forbidden" }); return; }
  try {
    const meta = await Onboarding.getProjectMeta(req.params.id);
    if (!meta) { reply.code(404).send({ error: "project not found" }); return; }
    return { ...meta, role };
  } catch (err) { app.log.error({ err }, "project meta failed"); reply.code(503).send({ error: String(err) }); }
});

// Gate an action on the caller's role in the project's org. Returns the org id
// (and the caller's role) when allowed; sends the appropriate 4xx and returns
// null otherwise.
async function roleGate(
  req: unknown,
  reply: import("fastify").FastifyReply,
  project: string | undefined,
  min: string,
): Promise<{ orgId: string; role: string } | null> {
  const user = userOf(req)!;
  if (!project) { reply.code(400).send({ error: "project required" }); return null; }
  const role = user.isPlatformAdmin ? "owner" : await Auth.userRoleForProject(user.id, project);
  if (!role) { reply.code(403).send({ error: "forbidden" }); return null; }
  if (!Auth.atLeast(role, min)) { reply.code(403).send({ error: `requires ${min} role` }); return null; }
  const orgId = await Auth.orgIdForProject(project);
  if (!orgId) { reply.code(404).send({ error: "project not found" }); return null; }
  return { orgId, role };
}

// ---------------- API keys (admin+) ----------------
app.get("/api/keys", async (req, reply) => {
  const project = (req.query as ScopedQuery).project;
  if (!(await roleGate(req, reply, project, "admin"))) return;
  try { return { keys: await Onboarding.listKeys(project!) }; }
  catch (err) { app.log.error({ err }, "keys list failed"); reply.code(503).send({ error: String(err) }); }
});

app.post<{ Body: { project?: string } }>("/api/keys", async (req, reply) => {
  const project = req.body?.project;
  const g = await roleGate(req, reply, project, "admin");
  if (!g) return;
  try {
    const key = await Onboarding.createKey(project!);
    audit(req, "apikey.created", { orgId: g.orgId, targetType: "apikey", target: key.id, metadata: { publicKey: key.publicKey, project } });
    return key;
  } catch (err) { app.log.error({ err }, "key create failed"); reply.code(500).send({ error: String(err) }); }
});

app.delete<{ Params: { id: string }; Querystring: ScopedQuery }>("/api/keys/:id", async (req, reply) => {
  const project = req.query.project;
  const g = await roleGate(req, reply, project, "admin");
  if (!g) return;
  const r = await Onboarding.revokeKey(project!, req.params.id);
  if ("error" in r) { reply.code(400).send(r); return; }
  audit(req, "apikey.revoked", { orgId: g.orgId, targetType: "apikey", target: req.params.id, metadata: { project } });
  return r;
});

// ---------------- team members (view: member+, manage: admin+) ----------------
app.get("/api/members", async (req, reply) => {
  const project = (req.query as ScopedQuery).project;
  const g = await roleGate(req, reply, project, "member");
  if (!g) return;
  const user = userOf(req)!;
  try { return { members: await Auth.listMembers(g.orgId), myRole: g.role, myUserId: user.id }; }
  catch (err) { app.log.error({ err }, "members list failed"); reply.code(503).send({ error: String(err) }); }
});

app.post<{ Body: { project?: string; email?: string; role?: string } }>("/api/members/invite", async (req, reply) => {
  const g = await roleGate(req, reply, req.body?.project, "admin");
  if (!g) return;
  const user = userOf(req)!;
  const r = await Auth.inviteMember(g.orgId, req.body?.email || "", req.body?.role || "member", user.id);
  if ("error" in r) { reply.code(400).send(r); return; }
  audit(req, "member.invited", { orgId: g.orgId, targetType: "member", target: req.body?.email, metadata: { role: req.body?.role || "member" } });
  return r;
});

app.patch<{ Body: { project?: string; userId?: string; role?: string } }>("/api/members/role", async (req, reply) => {
  const g = await roleGate(req, reply, req.body?.project, "admin");
  if (!g) return;
  const r = await Auth.updateMemberRole(g.orgId, req.body?.userId || "", req.body?.role || "");
  if ("error" in r) { reply.code(400).send(r); return; }
  audit(req, "member.role_changed", { orgId: g.orgId, targetType: "member", target: req.body?.userId, metadata: { role: req.body?.role } });
  return r;
});

app.post<{ Body: { project?: string; userId?: string; email?: string } }>("/api/members/remove", async (req, reply) => {
  const g = await roleGate(req, reply, req.body?.project, "admin");
  if (!g) return;
  if (req.body?.userId) {
    const r = await Auth.removeMember(g.orgId, req.body.userId);
    if ("error" in r) { reply.code(400).send(r); return; }
    audit(req, "member.removed", { orgId: g.orgId, targetType: "member", target: req.body.userId });
    return r;
  }
  if (req.body?.email) {
    await Auth.revokeInvite(g.orgId, req.body.email);
    audit(req, "member.invite_revoked", { orgId: g.orgId, targetType: "member", target: req.body.email });
    return { ok: true };
  }
  reply.code(400).send({ error: "userId or email required" });
});

app.get<{ Params: { id: string }; Querystring: ScopedQuery }>("/api/trace/:id", async (req, reply) => {
  const user = userOf(req)!;
  const project = req.query.project;
  if (!project || (!user.isPlatformAdmin && !(await Auth.userCanAccessProject(user.id, project)))) { reply.code(403).send({ error: "forbidden" }); return; }
  try { return await Q.traceDetail(req.params.id, project); }
  catch (err) { app.log.error({ err }, "trace failed"); reply.code(503).send({ error: String(err) }); }
});

// Analyst action: set a verdict on a security event (scoped to the event's project).
app.post<{ Body: { eventId?: string; verdict?: string; project?: string } }>("/api/verdict", async (req, reply) => {
  const user = userOf(req)!;
  const { eventId, verdict, project } = req.body || {};
  if (!eventId || !verdict) { reply.code(400).send({ error: "eventId and verdict required" }); return; }
  if (!project || (!user.isPlatformAdmin && !(await Auth.userCanAccessProject(user.id, project)))) { reply.code(403).send({ error: "forbidden" }); return; }
  try {
    // Pass the project so the write is scoped to the tenant whose access we just
    // verified — otherwise the id lookup crosses tenants.
    const ok = await Q.setVerdict(eventId, verdict, project);
    if (!ok) { reply.code(404).send({ error: "event not found" }); return; }
    audit(req, "event.verdict_set", { orgId: (await Auth.orgIdForProject(project!)) || undefined, targetType: "event", target: eventId, metadata: { verdict, project } });
    return { ok: true, eventId, verdict };
  } catch (err) {
    app.log.error({ err }, "verdict failed");
    reply.code(500).send({ error: String(err) });
  }
});

// ---------------- platform admin (super-admin) ----------------
// Every route here requires the platform-admin flag. This is the operator layer
// above tenant roles: full visibility and control over all users and companies.
function requireAdmin(req: unknown, reply: import("fastify").FastifyReply): boolean {
  if (userOf(req)?.isPlatformAdmin) return true;
  reply.code(403).send({ error: "platform admin only" });
  return false;
}

app.get("/api/admin/overview", async (req, reply) => {
  if (!requireAdmin(req, reply)) return;
  try { return await Admin.platformOverview(); }
  catch (err) { app.log.error({ err }, "admin overview failed"); reply.code(503).send({ error: "query failed", detail: String(err) }); }
});

app.get("/api/admin/users", async (req, reply) => {
  if (!requireAdmin(req, reply)) return;
  try { return { users: await Admin.listUsers() }; }
  catch (err) { app.log.error({ err }, "admin users failed"); reply.code(503).send({ error: String(err) }); }
});

app.get("/api/admin/orgs", async (req, reply) => {
  if (!requireAdmin(req, reply)) return;
  try { return { orgs: await Admin.listOrgs() }; }
  catch (err) { app.log.error({ err }, "admin orgs failed"); reply.code(503).send({ error: String(err) }); }
});

app.post<{ Params: { id: string }; Body: { value?: boolean } }>("/api/admin/users/:id/platform-admin", async (req, reply) => {
  if (!requireAdmin(req, reply)) return;
  const value = req.body?.value === true;
  const r = await Admin.setPlatformAdmin(req.params.id, value);
  if ("error" in r) { reply.code(400).send(r); return; }
  audit(req, "admin.platform_admin_changed", { targetType: "user", target: req.params.id, metadata: { value } });
  return r;
});

app.delete<{ Params: { id: string } }>("/api/admin/users/:id", async (req, reply) => {
  if (!requireAdmin(req, reply)) return;
  if (req.params.id === userOf(req)!.id) { reply.code(400).send({ error: "You can't delete your own account here." }); return; }
  const r = await Admin.deleteUser(req.params.id);
  if ("error" in r) { reply.code(400).send(r); return; }
  audit(req, "admin.user_deleted", { targetType: "user", target: req.params.id });
  return r;
});

app.post<{ Body: { name?: string } }>("/api/admin/orgs", async (req, reply) => {
  if (!requireAdmin(req, reply)) return;
  const r = await Admin.createOrg(req.body?.name || "");
  if ("error" in r) { reply.code(400).send(r); return; }
  audit(req, "admin.company_created", { orgId: r.id, targetType: "company", target: r.id, metadata: { name: req.body?.name } });
  return r;
});

app.patch<{ Params: { id: string }; Body: { name?: string } }>("/api/admin/orgs/:id", async (req, reply) => {
  if (!requireAdmin(req, reply)) return;
  const r = await Admin.renameOrg(req.params.id, req.body?.name || "");
  if ("error" in r) { reply.code(400).send(r); return; }
  audit(req, "admin.company_renamed", { orgId: req.params.id, targetType: "company", target: req.params.id, metadata: { name: req.body?.name } });
  return r;
});

app.delete<{ Params: { id: string } }>("/api/admin/orgs/:id", async (req, reply) => {
  if (!requireAdmin(req, reply)) return;
  try {
    const r = await Admin.deleteOrg(req.params.id);
    audit(req, "admin.company_deleted", { targetType: "company", target: req.params.id, metadata: { projectsPurged: r.projectsPurged } });
    return r;
  } catch (err) { app.log.error({ err }, "admin org delete failed"); reply.code(500).send({ error: String(err) }); }
});

// Audit viewers: org-scoped (admin+ of that company) and platform-wide (admin).
app.get("/api/audit", async (req, reply) => {
  const project = (req.query as ScopedQuery).project;
  const g = await roleGate(req, reply, project, "admin");
  if (!g) return;
  try { return { entries: await Audit.listByOrg(g.orgId) }; }
  catch (err) { app.log.error({ err }, "audit failed"); reply.code(503).send({ error: String(err) }); }
});

app.get("/api/admin/audit", async (req, reply) => {
  if (!requireAdmin(req, reply)) return;
  try { return { entries: await Audit.listAll() }; }
  catch (err) { app.log.error({ err }, "admin audit failed"); reply.code(503).send({ error: String(err) }); }
});

// ---------------- onboarding (add an app to your org) ----------------
app.post<{ Body: { projectName?: string; orgId?: string } }>("/api/onboarding/projects", async (req, reply) => {
  const user = userOf(req)!;
  const projectName = (req.body?.projectName || "").trim();
  if (!projectName) { reply.code(400).send({ error: "projectName is required" }); return; }
  if (projectName.length > 200) { reply.code(400).send({ error: "projectName must be 200 characters or fewer" }); return; }
  try {
    const project = await Onboarding.createProject(user.id, projectName, req.body?.orgId);
    audit(req, "project.created", { orgId: project.orgId, targetType: "project", target: project.projectId, metadata: { name: project.projectName } });
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
