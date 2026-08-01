import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import Fastify from "fastify";
import type { FastifyReply, FastifyRequest } from "fastify";
import fastifyStatic from "@fastify/static";
import { config, rateLimit, LIMITS, metrics, refreshQueueMetrics } from "@argus/shared";
import * as Q from "./queries.js";
import * as Onboarding from "./onboarding.js";
import * as Auth from "./auth.js";
import * as Admin from "./admin.js";
import * as Audit from "./audit.js";
import * as Settings from "./settings.js";
import * as Canaries from "./canaryAdmin.js";
import * as Governance from "./dataGovernance.js";
import { registerPublicApi } from "./publicRoutes.js";
import * as Alerts from "./alertAdmin.js";
import * as Assessments from "./assessments.js";
import * as Synthesis from "./assessmentSynthesis.js";
import * as Policies from "./policies.js";
import * as Controls from "./controls.js";
import { applySecurityHeaders } from "./headers.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const PUBLIC_DIR = join(__dirname, "..", "public");

/**
 * Builds the dashboard's Fastify instance with every route registered, and
 * returns it without listening.
 *
 * Split out of server.ts so the app can be exercised by `app.inject()` in tests.
 * That matters more here than it usually does: nearly every cross-tenant leak
 * this codebase has had was a route-level authorization mistake, invisible to
 * unit tests of the query layer and only catchable by driving the real HTTP
 * surface as a real signed-in user of the wrong tenant.
 */
export async function buildApp() {
  const app = Fastify({ logger: { level: process.env.LOG_LEVEL ?? "info" }, trustProxy: true });

  // Security headers on every response. Registered first so it also covers static
  // assets, 404s, and error replies — a header set only on the happy path is a
  // header set on the responses that were never the problem. The /demo route
  // re-applies it with its own script hash.
  app.addHook("onRequest", async (req, reply) => {
    applySecurityHeaders(req, reply);
    (req as unknown as { startedAt: number }).startedAt = Date.now();
  });

  // One counter and one histogram per route. The route pattern is used as the
  // label rather than the URL, so /api/trace/:id is one series instead of one
  // series per trace id — an unbounded label set is how a metrics endpoint
  // becomes the outage.
  app.addHook("onResponse", async (req, reply) => {
    const route = (req as unknown as { routeOptions?: { url?: string } }).routeOptions?.url ?? "unknown";
    const labels = { route, method: req.method, status: String(reply.statusCode) };
    metrics.inc("argus_http_requests_total", labels, 1, "HTTP requests served");
    const started = (req as unknown as { startedAt?: number }).startedAt;
    if (started) metrics.observe("argus_http_duration_ms", Date.now() - started, { route }, "HTTP request duration");
  });

  // Nothing internal reaches a client. Individual routes already catch their own
  // failures and send a curated message; this is the backstop for the ones that
  // don't, and it exists because a malformed ?project= used to reach Postgres as
  // a uuid parameter and come back as a 500 carrying the driver's error text
  // ("invalid input syntax for type uuid: ..."). Error bodies are a real
  // information-disclosure channel: they name the database, the column types,
  // and sometimes the query. The detail goes to the log, where it belongs.
  app.setErrorHandler((err, req, reply) => {
    const status = err.statusCode && err.statusCode < 500 ? err.statusCode : 500;
    if (status >= 500) {
      req.log.error({ err, url: req.url }, "unhandled error");
      reply.code(500).send({ error: "internal error" });
      return;
    }
    // 4xx from Fastify itself (bad JSON, unsupported media type) is about the
    // caller's own request, so echoing it back tells them nothing they didn't send.
    reply.code(status).send({ error: err.message });
  });

  // ---------------------------------------------------------------- asset versioning
  // The dashboard is several cooperating files (app.js needs glossary.js; both
  // need app.css). If a browser or CDN caches one and revalidates another, it can
  // serve a mismatched pair — which used to mean a broken page. So: hash the
  // asset bundle once at boot, stamp that version into every HTML asset URL, and
  // serve the HTML itself as no-cache. The HTML is always fresh and cheap; the
  // assets are immutable per version and can be cached hard. A deploy changes the
  // hash, so every client picks up the whole new set atomically.
  const VERSIONED_ASSETS = ["app.js", "app.css", "appearance.js", "glossary.js", "login.js", "onboard.js", "reset.js"];
  const HTML_PAGES = ["index.html", "login.html", "onboard.html", "reset.html"];

  // Hash names and raw bytes in a plain loop. Buffers go in as Buffers (no utf8
  // round-trip) and the filename is folded in, so a rename or a missing file
  // changes the version too. Deliberately boring: this value decides whether a
  // browser picks up a deploy, so it should be obvious rather than clever.
  function computeAssetVersion(): string {
    const h = createHash("sha1");
    for (const f of VERSIONED_ASSETS) {
      h.update(f);
      try { h.update(readFileSync(join(PUBLIC_DIR, f))); } catch { h.update("<missing>"); }
    }
    return h.digest("hex").slice(0, 10);
  }
  const ASSET_VERSION = computeAssetVersion();

  // Rendered once at boot — these files never change while the process is alive.
  const renderedHtml = new Map<string, string>();
  for (const page of HTML_PAGES) {
    try {
      renderedHtml.set(page, readFileSync(join(PUBLIC_DIR, page), "utf8").replaceAll("__ASSETV__", ASSET_VERSION));
    } catch { /* page absent in this build — fall through to static */ }
  }
  function sendHtml(page: string, reply: FastifyReply): FastifyReply | undefined {
    const body = renderedHtml.get(page);
    if (body === undefined) return undefined; // let @fastify/static handle it
    return reply
      .header("content-type", "text/html; charset=utf-8")
      // Must revalidate: this is what guarantees a redeploy is picked up.
      .header("cache-control", "no-cache")
      .send(body);
  }

  // Explicit HTML routes are registered before the static wildcard so they win.
  app.get("/", async (_req, reply) => sendHtml("index.html", reply) ?? reply.callNotFound());
  for (const page of HTML_PAGES) {
    app.get(`/${page}`, async (_req, reply) => sendHtml(page, reply) ?? reply.callNotFound());
  }

  // ---------------- public demo (removable, flag-gated) ----------------
  // A completely separate, login-free marketing demo. It lives OUTSIDE the static
  // public dir and is served only through this route, so setting DEMO_ENABLED=0
  // makes it fully unreachable, and deleting apps/web/demo/ + this block removes
  // it with no other impact. The file is self-contained synthetic data — it never
  // reads live customer data.
  const DEMO_ENABLED = process.env.DEMO_ENABLED !== "0";
  let demoHtml: string | null = null;
  try { demoHtml = readFileSync(join(__dirname, "..", "demo", "index.html"), "utf8"); } catch { /* absent — /demo 404s */ }

  // The demo page carries one inline <script> (a cosmetic count-up). Rather than
  // relax script-src to 'unsafe-inline' — which would apply to every page that
  // renders customer trace content — hash it at boot and allow exactly that
  // script, on exactly this route.
  const demoScriptHashes: string[] = (() => {
    if (!demoHtml) return [];
    const hashes: string[] = [];
    for (const m of demoHtml.matchAll(/<script(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/gi)) {
      hashes.push("sha256-" + createHash("sha256").update(m[1], "utf8").digest("base64"));
    }
    return hashes;
  })();

  app.get("/demo", async (req, reply) => {
    if (!DEMO_ENABLED || demoHtml === null) return reply.callNotFound();
    applySecurityHeaders(req, reply, { scriptHashes: demoScriptHashes });
    return reply.header("content-type", "text/html; charset=utf-8").header("cache-control", "no-cache").send(demoHtml);
  });

  // The API-key-authenticated public surface. Registered as an encapsulated
  // plugin so its auth hook applies only to its own routes and can't be
  // confused with the session gate below.
  await app.register(async (scope) => { await registerPublicApi(scope); });

  // `index: false` — "/" is served by the route above, not by static's own index.
  await app.register(fastifyStatic, { root: PUBLIC_DIR, prefix: "/", index: false });
  app.log.info({ assetVersion: ASSET_VERSION }, "static assets versioned");

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

  // `assetVersion` is the deploy fingerprint: curl /health and compare it against
  // the ?v= in the page source to tell "my browser is stale" apart from "the
  // server never picked up my deploy".
  app.get("/health", async () => ({ status: (await Q.health()) ? "ok" : "degraded", service: "argus-web", assetVersion: ASSET_VERSION }));

  // Prometheus scrape target. Not behind the session gate (which only guards
  // /api/*): a scraper has no session. Counts and latencies only — no customer
  // content ever reaches this endpoint.
  app.get("/metrics", async (_req, reply) => {
    await refreshQueueMetrics().catch(() => {});
    reply.header("content-type", "text/plain; version=0.0.4").send(metrics.render());
  });

  // ---------------- auth gate ----------------
  // Resolve the signed-in user for every /api/* request from the session cookie,
  // and require one for everything except the auth endpoints themselves. Static
  // assets (login.html, the dashboard shell, JS/CSS) stay public — all *data*
  // lives behind /api and is gated here.
  // ---------------- rate limiting ----------------
  // Unauthenticated auth endpoints are the ones an attacker can hammer for free:
  // login is credential stuffing, forgot/resend are an outbound-email cannon paid
  // for by us, and reset is token guessing. Limits are keyed by client IP, and
  // login is *additionally* keyed by the email being tried so that rotating IPs
  // still can't grind a single account.
  //
  // Returning 429 before the handler means we never touch Postgres or the mailer
  // for a request we've already decided to refuse.
  async function limited(
    req: FastifyRequest,
    reply: FastifyReply,
    scope: string,
    policy: { limit: number; windowMs: number },
    extra?: string,
  ): Promise<boolean> {
    const id = extra ? `${scope}:${extra}` : `${scope}:${req.ip}`;
    const r = await rateLimit(id, policy.limit, policy.windowMs);
    if (r.allowed) return false;
    reply
      .code(429)
      .header("retry-after", String(Math.ceil(r.resetMs / 1000)))
      .send({ error: "Too many requests. Please wait and try again." });
    return true;
  }

  /** Per-path limit policy for the public auth endpoints. */
  async function authRateLimited(req: FastifyRequest, reply: FastifyReply, path: string): Promise<boolean> {
    if (path === "/api/auth/login") {
      const email = String((req.body as { email?: string } | undefined)?.email ?? "").trim().toLowerCase();
      if (await limited(req, reply, "login-ip", LIMITS.login)) return true;
      if (email && (await limited(req, reply, "login-email", LIMITS.login, email))) return true;
      return false;
    }
    if (path === "/api/auth/signup") return limited(req, reply, "signup", LIMITS.signup);
    if (path === "/api/auth/forgot" || path === "/api/auth/resend")
      return limited(req, reply, "email-trigger", LIMITS.emailTrigger);
    if (path === "/api/auth/reset" || path === "/api/auth/verify")
      return limited(req, reply, "reset-submit", LIMITS.resetSubmit);
    return false;
  }

  app.decorateRequest("user", null);
  app.addHook("preHandler", async (req, reply) => {
    const path = req.url.split("?")[0];
    if (!path.startsWith("/api/")) return;
    const token = Auth.parseSessionCookie(req.headers.cookie);
    asUser(req).user = await Auth.sessionUser(token);
    if (path.startsWith("/api/auth/")) {
      if (await authRateLimited(req, reply, path)) return;
      return; // these manage their own session
    }
    const u = asUser(req).user;
    if (!u) {
      reply.code(401).send({ error: "authentication required" });
      return;
    }
    // Optional hard gate: block data access until the email is verified. Off by
    // default (verification is a nudge); set REQUIRE_EMAIL_VERIFICATION=1 to enforce.
    if (process.env.REQUIRE_EMAIL_VERIFICATION === "1" && !u.emailVerified) {
      reply.code(403).send({ error: "email not verified" });
      return;
    }
    // Signed-in traffic is limited per user, not per IP: an office behind one NAT
    // is many users, and a stolen session is one user across many IPs.
    await limited(req, reply, "api-user", LIMITS.api, u.id);
  });

  // ---------------- auth routes ----------------
  // Was this request delivered over TLS? Decides the cookie's Secure flag —
  // setting it on a plain-HTTP connection makes the browser drop the cookie and
  // the user can never stay signed in.
  function secureReq(req: FastifyRequest): boolean {
    if (req.protocol === "https") return true;
    const xf = req.headers["x-forwarded-proto"];
    const proto = Array.isArray(xf) ? xf[0] : xf;
    return (proto ?? "").split(",")[0].trim() === "https";
  }

  // What the login page needs to render itself correctly (whether to show the
  // signup form, and whether to ask for a setup token). Public by necessity, and
  // it reveals only configuration the operator chose, never account existence.
  app.get("/api/auth/policy", async () => Auth.signupPolicy());

  app.post<{ Body: { email?: string; password?: string; name?: string; company?: string; bootstrapToken?: string } }>(
    "/api/auth/signup",
    async (req, reply) => {
      const { email, password, name, company, bootstrapToken } = req.body || {};
      const r = await Auth.signup(email || "", password || "", name || "", company || "", bootstrapToken || "");
      if ("error" in r) {
        void Audit.record("user.signup_rejected", { actorEmail: email, ip: req.ip, metadata: { reason: r.error } });
        reply.code(400).send(r);
        return;
      }
      reply.header("set-cookie", Auth.sessionCookie(r.token, secureReq(req)));
      void Audit.record("user.signup", { actor: r.user.id, actorEmail: r.user.email, ip: req.ip });
      return { user: r.user };
    },
  );

  app.post<{ Body: { email?: string; password?: string } }>("/api/auth/login", async (req, reply) => {
    const { email, password } = req.body || {};
    const r = await Auth.login(email || "", password || "");
    if ("error" in r) {
      // Failed logins are the signal that matters in an audit trail — a
      // successful-only log tells you nothing about the attempt that preceded it.
      void Audit.record("user.login_failed", { actorEmail: String(email || "").toLowerCase(), ip: req.ip });
      reply.code(401).send(r);
      return;
    }
    reply.header("set-cookie", Auth.sessionCookie(r.token, secureReq(req)));
    void Audit.record("user.login", { actor: r.user.id, actorEmail: r.user.email, ip: req.ip });
    return { user: r.user };
  });

  app.post("/api/auth/logout", async (req, reply) => {
    const u = userOf(req);
    await Auth.logout(Auth.parseSessionCookie(req.headers.cookie));
    reply.header("set-cookie", Auth.clearCookie(secureReq(req)));
    if (u) void Audit.record("user.logout", { actor: u.id, actorEmail: u.email, ip: req.ip });
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

  app.post<{ Body: { project?: string; scopes?: string[]; label?: string } }>("/api/keys", async (req, reply) => {
    const project = req.body?.project;
    const g = await roleGate(req, reply, project, "admin");
    if (!g) return;
    try {
      const key = await Onboarding.createKey(project!, { scopes: req.body?.scopes, label: req.body?.label });
      audit(req, "apikey.created", {
        orgId: g.orgId, targetType: "apikey", target: key.id,
        metadata: { publicKey: key.publicKey, project, scopes: key.scopes, label: key.label },
      });
      return key;
    } catch (err) { app.log.error({ err }, "key create failed"); reply.code(500).send({ error: "could not create key" }); }
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

  // ---------------- application settings (view: member+, change: admin+) ----------------
  // The per-application detection config lives here and is read by ingest + worker
  // at request time — so a customer tunes sampling, redaction, detection layers and
  // alerting from this UI, and never from their own app's code.
  app.get("/api/settings", async (req, reply) => {
    const project = (req.query as ScopedQuery).project;
    const g = await roleGate(req, reply, project, "member");
    if (!g) return;
    try { return await Settings.getSettings(project!); }
    catch (err) { app.log.error({ err }, "settings read failed"); reply.code(503).send({ error: String(err) }); }
  });

  app.put<{ Body: { project?: string; config?: unknown } }>("/api/settings", async (req, reply) => {
    const project = req.body?.project;
    const g = await roleGate(req, reply, project, "admin");
    if (!g) return;
    try {
      const r = await Settings.updateSettings(project!, req.body?.config, userOf(req)!.email);
      audit(req, "settings.updated", { orgId: g.orgId, targetType: "project", target: project, metadata: { version: r.version } });
      return r;
    } catch (err) { app.log.error({ err }, "settings write failed"); reply.code(500).send({ error: String(err) }); }
  });

  // ---------------- alert channels (view: member+, manage: admin+) ----------------
  app.get("/api/alerts/channels", async (req, reply) => {
    const g = await roleGate(req, reply, (req.query as ScopedQuery).project, "member");
    if (!g) return;
    try { return { channels: await Alerts.listChannels((req.query as ScopedQuery).project!) }; }
    catch (err) { app.log.error({ err }, "channels list failed"); reply.code(503).send({ error: "query failed" }); }
  });

  app.post<{ Body: { project?: string; kind?: string; label?: string; target?: string; minSeverity?: string; sign?: boolean } }>(
    "/api/alerts/channels",
    async (req, reply) => {
      const g = await roleGate(req, reply, req.body?.project, "admin");
      if (!g) return;
      try {
        const r = await Alerts.createChannel(req.body!.project!, req.body!, userOf(req)!.email);
        if ("error" in r) { reply.code(400).send(r); return; }
        // The target is a credential — audit that a channel was added, never
        // where to. An audit log that records the webhook URL leaks it.
        audit(req, "alertchannel.created", {
          orgId: g.orgId, targetType: "alertchannel", target: r.id,
          metadata: { kind: req.body?.kind, label: req.body?.label, minSeverity: req.body?.minSeverity },
        });
        return r;
      } catch (err) { app.log.error({ err }, "channel create failed"); reply.code(500).send({ error: "could not create channel" }); }
    },
  );

  app.delete<{ Params: { id: string }; Querystring: ScopedQuery }>("/api/alerts/channels/:id", async (req, reply) => {
    const g = await roleGate(req, reply, req.query.project, "admin");
    if (!g) return;
    const r = await Alerts.deleteChannel(req.query.project!, req.params.id);
    if ("error" in r) { reply.code(400).send(r); return; }
    audit(req, "alertchannel.deleted", { orgId: g.orgId, targetType: "alertchannel", target: req.params.id });
    return r;
  });

  app.post<{ Body: { project?: string; id?: string } }>("/api/alerts/channels/test", async (req, reply) => {
    const g = await roleGate(req, reply, req.body?.project, "admin");
    if (!g) return;
    try { return await Alerts.testChannel(req.body!.project!, req.body?.id || ""); }
    catch (err) { app.log.error({ err }, "channel test failed"); reply.code(500).send({ ok: false, error: "test failed" }); }
  });

  // ---------------- suppression rules (view: member+, manage: admin+) ----------------
  app.get("/api/alerts/suppressions", async (req, reply) => {
    const g = await roleGate(req, reply, (req.query as ScopedQuery).project, "member");
    if (!g) return;
    try { return { rules: await Alerts.listSuppressions((req.query as ScopedQuery).project!) }; }
    catch (err) { app.log.error({ err }, "suppressions failed"); reply.code(503).send({ error: "query failed" }); }
  });

  app.post<{ Body: { project?: string; ruleId?: string; category?: string; scopeType?: string; scopeValue?: string; reason?: string; expiresInDays?: number } }>(
    "/api/alerts/suppressions",
    async (req, reply) => {
      const g = await roleGate(req, reply, req.body?.project, "admin");
      if (!g) return;
      try {
        const r = await Alerts.createSuppression(req.body!.project!, req.body!, userOf(req)!.email);
        if ("error" in r) { reply.code(400).send(r); return; }
        // Suppression is a deliberate blind spot, so who created it and why is
        // exactly what an incident review will want.
        audit(req, "suppression.created", {
          orgId: g.orgId, targetType: "suppression", target: r.id,
          metadata: { ruleId: req.body?.ruleId, category: req.body?.category, reason: req.body?.reason },
        });
        return r;
      } catch (err) { app.log.error({ err }, "suppression create failed"); reply.code(500).send({ error: "could not create rule" }); }
    },
  );

  app.delete<{ Params: { id: string }; Querystring: ScopedQuery }>("/api/alerts/suppressions/:id", async (req, reply) => {
    const g = await roleGate(req, reply, req.query.project, "admin");
    if (!g) return;
    const r = await Alerts.deleteSuppression(req.query.project!, req.params.id);
    if ("error" in r) { reply.code(400).send(r); return; }
    audit(req, "suppression.deleted", { orgId: g.orgId, targetType: "suppression", target: req.params.id });
    return r;
  });

  // ---------------- data governance (view: member+, change: owner) ----------------
  // Retention and erasure are destructive and irreversible, so they sit above
  // the detection settings in required role: an admin can tune sampling, only an
  // owner can shorten how long a customer's data is kept or erase a person.
  app.get("/api/retention", async (req, reply) => {
    const project = (req.query as ScopedQuery).project;
    const g = await roleGate(req, reply, project, "member");
    if (!g) return;
    try { return await Governance.getRetention(project!); }
    catch (err) { app.log.error({ err }, "retention read failed"); reply.code(503).send({ error: "query failed" }); }
  });

  app.put<{ Body: { project?: string; retentionDays?: number } }>("/api/retention", async (req, reply) => {
    const project = req.body?.project;
    const g = await roleGate(req, reply, project, "owner");
    if (!g) return;
    try {
      const r = await Governance.setRetention(project!, Number(req.body?.retentionDays));
      if ("error" in r) { reply.code(400).send(r); return; }
      audit(req, "retention.changed", {
        orgId: g.orgId, targetType: "project", target: project,
        metadata: { retentionDays: r.retentionDays },
      });
      // Apply immediately: shortening a window is something people do because
      // they want data gone now, not within the hour.
      const swept = await Governance.applyRetentionNow(project!);
      return { ...r, swept: swept.tables };
    } catch (err) { app.log.error({ err }, "retention write failed"); reply.code(500).send({ error: "could not update retention" }); }
  });

  // Right to erasure. GET previews the blast radius, POST performs it.
  app.get<{ Querystring: ScopedQuery & { userId?: string } }>("/api/erasure/preview", async (req, reply) => {
    const g = await roleGate(req, reply, req.query.project, "owner");
    if (!g) return;
    try { return await Governance.previewErasure(req.query.project!, req.query.userId || ""); }
    catch (err) { app.log.error({ err }, "erasure preview failed"); reply.code(503).send({ error: "query failed" }); }
  });

  app.post<{ Body: { project?: string; userId?: string } }>("/api/erasure", async (req, reply) => {
    const project = req.body?.project;
    const g = await roleGate(req, reply, project, "owner");
    if (!g) return;
    try {
      const r = await Governance.eraseUser(project!, req.body?.userId || "");
      if ("error" in r) { reply.code(400).send(r); return; }
      // The audit entry is the evidence that the request was honoured, and it
      // deliberately records the subject id: the whole point is to be able to
      // show an auditor what was erased and when.
      audit(req, "data.erased", {
        orgId: g.orgId, targetType: "project", target: project,
        metadata: { subject: r.subject, tracesMatched: r.tracesMatched },
      });
      return r;
    } catch (err) { app.log.error({ err }, "erasure failed"); reply.code(500).send({ error: "erasure failed" }); }
  });

  // ---------------- canaries (view: member+, manage: admin+) ----------------
  // Planted markers that should never travel. A hit here is the one finding in
  // the product that is asserted rather than inferred.
  app.get("/api/canaries", async (req, reply) => {
    const project = (req.query as ScopedQuery).project;
    const g = await roleGate(req, reply, project, "member");
    if (!g) return;
    try { return { canaries: await Canaries.listCanaries(project!) }; }
    catch (err) { app.log.error({ err }, "canary list failed"); reply.code(503).send({ error: "query failed" }); }
  });

  app.post<{ Body: { project?: string; label?: string; value?: string } }>("/api/canaries", async (req, reply) => {
    const project = req.body?.project;
    const g = await roleGate(req, reply, project, "admin");
    if (!g) return;
    try {
      const r = await Canaries.createCanary(project!, req.body?.label || "", userOf(req)!.email, req.body?.value);
      if ("error" in r) { reply.code(400).send(r); return; }
      // The label is audited, never the value — an audit log that records the
      // canary is an audit log that leaks it.
      audit(req, "canary.created", {
        orgId: g.orgId, targetType: "canary", target: r.id,
        metadata: { label: r.label, kind: r.kind, project },
      });
      return r;
    } catch (err) { app.log.error({ err }, "canary create failed"); reply.code(500).send({ error: "could not create canary" }); }
  });

  app.delete<{ Params: { id: string }; Querystring: ScopedQuery }>("/api/canaries/:id", async (req, reply) => {
    const project = req.query.project;
    const g = await roleGate(req, reply, project, "admin");
    if (!g) return;
    const r = await Canaries.revokeCanary(project!, req.params.id);
    if ("error" in r) { reply.code(400).send(r); return; }
    audit(req, "canary.revoked", { orgId: g.orgId, targetType: "canary", target: req.params.id, metadata: { project } });
    return r;
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

  // ---------------- static assessments (view: member+, run/edit: member+) ----------------
  // Phase 2 of the InjectGuard merge. The engines are pure functions in the
  // detection service; these routes own tenancy and storage. Reads go through
  // guard() like every other data view; writes verify access and then pass the
  // project into the module, whose queries key on it directly.

  guard("assessments", (_r, p) => Assessments.listAssessments(p).then((assessments) => ({ assessments })));
  guard("assessment-findings", (_r, p) => Assessments.listFindings(p).then((findings) => ({ findings })));
  guard("assessment-graph", (_r, p) => Assessments.getGraph(p));

  app.get<{ Params: { id: string }; Querystring: ScopedQuery }>("/api/assessment/:id", async (req, reply) => {
    const user = userOf(req)!;
    const project = req.query.project;
    if (!project || (!user.isPlatformAdmin && !(await Auth.userCanAccessProject(user.id, project)))) { reply.code(403).send({ error: "forbidden" }); return; }
    try {
      const a = await Assessments.getAssessment(project, req.params.id);
      if (!a) { reply.code(404).send({ error: "assessment not found" }); return; }
      return a;
    } catch (err) { app.log.error({ err }, "assessment detail failed"); reply.code(503).send({ error: String(err) }); }
  });

  app.post<{ Body: { project?: string; documents?: Assessments.PromptDocIn[]; context?: Assessments.AssessContextIn } }>(
    "/api/assess/prompt",
    async (req, reply) => {
      const g = await roleGate(req, reply, req.body?.project, "member");
      if (!g) return;
      const invalid = Assessments.validateDocuments(req.body?.documents);
      if (invalid) { reply.code(400).send({ error: invalid }); return; }
      try {
        const r = await Assessments.runPromptAssessment(
          req.body!.project!, req.body!.documents!, req.body?.context ?? {}, userOf(req)!.id,
        );
        if (!r) { reply.code(400).send({ error: "invalid project" }); return; }
        audit(req, "assessment.run", {
          orgId: g.orgId, targetType: "assessment", target: r.id,
          metadata: { project: req.body?.project, kind: "prompt", findings: r.findingCount, maxSeverity: r.maxSeverity },
        });
        return r;
      } catch (err) {
        // The engine being down is an operational condition, not a caller error.
        app.log.error({ err }, "assess prompt failed");
        reply.code(503).send({ error: "assessment engine unavailable" });
      }
    },
  );

  app.post<{ Body: { project?: string; nodes?: Assessments.GraphNodeIn[]; edges?: Assessments.GraphEdgeIn[] } }>(
    "/api/assessment/graph",
    async (req, reply) => {
      const g = await roleGate(req, reply, req.body?.project, "member");
      if (!g) return;
      const invalid = Assessments.validateGraph(req.body?.nodes, req.body?.edges);
      if (invalid) { reply.code(400).send({ error: invalid }); return; }
      try {
        const ok = await Assessments.saveGraph(req.body!.project!, req.body!.nodes!, req.body?.edges ?? [], userOf(req)!.id);
        if (!ok) { reply.code(400).send({ error: "invalid project" }); return; }
        audit(req, "assessment.graph_saved", {
          orgId: g.orgId, targetType: "assessment_graph", target: req.body!.project!,
          metadata: { project: req.body?.project, nodes: req.body!.nodes!.length, edges: (req.body?.edges ?? []).length },
        });
        return { ok: true };
      } catch (err) { app.log.error({ err }, "graph save failed"); reply.code(500).send({ error: String(err) }); }
    },
  );

  // Phase 4: propose a graph from observed traces. A PROPOSAL — it is returned
  // for review and never written, because traces can prove a component exists
  // but cannot prove whether a human approves its writes, and that is the fact
  // the highest-severity architecture rules turn on.
  app.post<{ Body: { project?: string } }>("/api/assessment/graph/derive", async (req, reply) => {
    const g = await roleGate(req, reply, req.body?.project, "member");
    if (!g) return;
    try {
      const derived = await Synthesis.deriveGraph(req.body!.project!);
      audit(req, "assessment.graph_derived", {
        orgId: g.orgId, targetType: "assessment_graph", target: req.body!.project!,
        metadata: { project: req.body?.project, nodes: derived.nodes.length, edges: derived.edges.length },
      });
      return derived;
    } catch (err) { app.log.error({ err }, "graph derive failed"); reply.code(503).send({ error: "could not read traces" }); }
  });

  app.post<{ Body: { project?: string } }>("/api/assessment/graph/analyze", async (req, reply) => {
    const g = await roleGate(req, reply, req.body?.project, "member");
    if (!g) return;
    try {
      const r = await Assessments.runGraphAssessment(req.body!.project!, userOf(req)!.id);
      if (!r) { reply.code(400).send({ error: "no graph saved for this project" }); return; }
      audit(req, "assessment.run", {
        orgId: g.orgId, targetType: "assessment", target: r.id,
        metadata: { project: req.body?.project, kind: "graph", findings: r.findingCount, maxSeverity: r.maxSeverity },
      });
      return r;
    } catch (err) { app.log.error({ err }, "assess graph failed"); reply.code(503).send({ error: "assessment engine unavailable" }); }
  });

  // Analyst action, mirroring /api/verdict: scoped by (id AND project).
  app.post<{ Body: { project?: string; findingId?: string; status?: string } }>(
    "/api/assessment/finding/status",
    async (req, reply) => {
      const g = await roleGate(req, reply, req.body?.project, "member");
      if (!g) return;
      const { findingId, status } = req.body || {};
      if (!findingId || !status) { reply.code(400).send({ error: "findingId and status required" }); return; }
      try {
        const r = await Assessments.setFindingStatus(req.body!.project!, findingId, status);
        if ("error" in r) { reply.code(r.error === "finding not found" ? 404 : 400).send(r); return; }
        audit(req, "assessment.finding_status", {
          orgId: g.orgId, targetType: "assessment_finding", target: findingId,
          metadata: { project: req.body?.project, status },
        });
        return r;
      } catch (err) { app.log.error({ err }, "finding status failed"); reply.code(500).send({ error: String(err) }); }
    },
  );

  // ---------------- governance policies (view: member+, manage: member+) ----------------

  guard("policies", (_r, p) => Policies.listPolicies(p).then((policies) => ({ policies })));

  app.post<{ Body: { project?: string } & Policies.PolicyInput }>("/api/policies", async (req, reply) => {
    const g = await roleGate(req, reply, req.body?.project, "member");
    if (!g) return;
    const invalid = Policies.validatePolicy(req.body!);
    if (invalid) { reply.code(400).send({ error: invalid }); return; }
    try {
      const r = await Policies.createPolicy(req.body!.project!, req.body!, userOf(req)!.id);
      if ("error" in r) { reply.code(400).send(r); return; }
      audit(req, "policy.created", {
        orgId: g.orgId, targetType: "policy", target: r.id,
        metadata: { project: req.body?.project, policyKey: r.policy_key, action: r.action },
      });
      return r;
    } catch (err) { app.log.error({ err }, "policy create failed"); reply.code(500).send({ error: String(err) }); }
  });

  app.post<{ Params: { id: string }; Body: { project?: string; enabled?: boolean } }>(
    "/api/policies/:id/enabled",
    async (req, reply) => {
      const g = await roleGate(req, reply, req.body?.project, "member");
      if (!g) return;
      const ok = await Policies.setPolicyEnabled(req.body!.project!, req.params.id, !!req.body?.enabled);
      if (!ok) { reply.code(404).send({ error: "policy not found" }); return; }
      audit(req, "policy.toggled", {
        orgId: g.orgId, targetType: "policy", target: req.params.id,
        metadata: { project: req.body?.project, enabled: !!req.body?.enabled },
      });
      return { ok: true };
    },
  );

  app.delete<{ Params: { id: string }; Querystring: ScopedQuery }>("/api/policies/:id", async (req, reply) => {
    const g = await roleGate(req, reply, req.query.project, "member");
    if (!g) return;
    const ok = await Policies.deletePolicy(req.query.project!, req.params.id);
    if (!ok) { reply.code(404).send({ error: "policy not found" }); return; }
    audit(req, "policy.deleted", {
      orgId: g.orgId, targetType: "policy", target: req.params.id,
      metadata: { project: req.query.project },
    });
    return { ok: true };
  });

  // Read-only: reports what the rules say about the application right now.
  // Never writes and never blocks on its own — the caller decides.
  app.get("/api/policies/evaluate", async (req, reply) => {
    const user = userOf(req)!;
    const project = (req.query as ScopedQuery).project;
    if (!project || (!user.isPlatformAdmin && !(await Auth.userCanAccessProject(user.id, project)))) { reply.code(403).send({ error: "forbidden" }); return; }
    try { return await Policies.evaluatePolicies(project); }
    catch (err) { app.log.error({ err }, "policy evaluate failed"); reply.code(503).send({ error: "policy engine unavailable" }); }
  });

  // Reports. A GET so it can be a plain link/bookmark, and it streams the file
  // itself rather than JSON — the point is something you can attach to an email
  // or an audit response.
  app.get<{ Params: { kind: string }; Querystring: ScopedQuery & { format?: string } }>(
    "/api/reports/:kind",
    async (req, reply) => {
      const user = userOf(req)!;
      const project = req.query.project;
      if (!project || (!user.isPlatformAdmin && !(await Auth.userCanAccessProject(user.id, project)))) { reply.code(403).send({ error: "forbidden" }); return; }
      const format = req.query.format || "md";
      if (!Assessments.REPORT_KINDS.has(req.params.kind) || !Assessments.REPORT_FORMATS.has(format)) {
        reply.code(400).send({ error: "unknown report kind or format" }); return;
      }
      try {
        const meta = await Onboarding.getProjectMeta(project);
        const out = await Assessments.renderReport(project, meta?.projectName || "Application", req.params.kind, format);
        if (!out) { reply.code(400).send({ error: "could not render the report" }); return; }
        audit(req, "report.generated", {
          orgId: (await Auth.orgIdForProject(project)) || undefined,
          targetType: "report", target: req.params.kind,
          metadata: { project, kind: req.params.kind, format },
        });
        const ext = format === "md" ? "md" : format;
        reply
          .header("content-type", out.contentType)
          .header("content-disposition", `attachment; filename="argus-${req.params.kind}-report.${ext}"`)
          .send(out.body);
      } catch (err) {
        app.log.error({ err }, "report failed");
        reply.code(503).send({ error: "report engine unavailable" });
      }
    },
  );

  // ---------------- governance controls (view: any role, manage: member+) ----------------

  guard("controls", async (_r, p) => ({
    controls: await Controls.listControls(p),
    coverage: await Controls.coverage(p),
    catalogSize: Controls.CONTROL_CATALOG.length,
  }));

  // Adopting the baseline is an explicit action, not a side effect of reading.
  app.post<{ Body: { project?: string } }>("/api/controls/adopt", async (req, reply) => {
    const g = await roleGate(req, reply, req.body?.project, "member");
    if (!g) return;
    try {
      const added = await Controls.adoptCatalog(req.body!.project!, userOf(req)!.id);
      audit(req, "controls.adopted", {
        orgId: g.orgId, targetType: "controls", target: req.body!.project!,
        metadata: { project: req.body?.project, added },
      });
      return { ok: true, added };
    } catch (err) { app.log.error({ err }, "control adopt failed"); reply.code(500).send({ error: String(err) }); }
  });

  app.post<{ Params: { id: string }; Body: { project?: string } & Controls.ControlUpdate }>(
    "/api/controls/:id",
    async (req, reply) => {
      const g = await roleGate(req, reply, req.body?.project, "member");
      if (!g) return;
      try {
        const r = await Controls.updateControl(req.body!.project!, req.params.id, req.body!, userOf(req)!.id);
        if ("error" in r) { reply.code(r.error === "control not found" ? 404 : 400).send(r); return; }
        audit(req, "control.updated", {
          orgId: g.orgId, targetType: "control", target: req.params.id,
          metadata: { project: req.body?.project, status: req.body?.status },
        });
        return r;
      } catch (err) { app.log.error({ err }, "control update failed"); reply.code(500).send({ error: String(err) }); }
    },
  );

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


  return app;
}
