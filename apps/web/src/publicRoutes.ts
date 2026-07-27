/**
 * /v1/* — the API-key-authenticated public surface.
 *
 * Registered as its own Fastify plugin so it gets its own auth hook. It has to
 * be separate from the dashboard's /api/*: those routes authenticate a *person*
 * via a session cookie and derive the project from a query parameter the person
 * is checked against. Here the credential names the project directly, so there
 * is no project parameter at all — and therefore no way to ask for someone
 * else's, which is a stronger position than checking one.
 */
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { authenticateKey, hasScope, parseBearer, rateLimit, type AuthedKey } from "@argus/shared";
import * as Api from "./publicApi.js";

interface KeyedRequest {
  apiKey: AuthedKey;
}

const keyOf = (req: unknown): AuthedKey => (req as unknown as KeyedRequest).apiKey;

/** Per-key read quota. Separate from the ingest quota: a runaway export loop
 *  and a runaway telemetry loop are different problems with different limits. */
const READ_LIMIT = Number(process.env.READ_RATE_LIMIT ?? 600);

export async function registerPublicApi(app: FastifyInstance): Promise<void> {
  app.decorateRequest("apiKey", null);

  app.addHook("preHandler", async (req: FastifyRequest, reply: FastifyReply) => {
    const path = req.url.split("?")[0];
    if (!path.startsWith("/v1/")) return;

    const token = parseBearer(req.headers.authorization);
    if (!token) {
      await rateLimit(`v1-noauth:${req.ip}`, 60, 60_000);
      reply.code(401).send({
        error: "unauthorized",
        message: "Send 'Authorization: Bearer <api key>'. Create a read key under API Keys.",
      });
      return;
    }

    const key = await authenticateKey(token);
    if (!key) {
      await rateLimit(`v1-badkey:${req.ip}`, 60, 60_000);
      reply.code(401).send({ error: "unauthorized", message: "Unknown or revoked API key." });
      return;
    }

    // Scope check. An ingest key is deployed into application code on every
    // host that runs the customer's app — by deployment count it is the most
    // exposed credential they have. It must not also be able to read back
    // everything it ever sent.
    if (!hasScope(key, "read")) {
      reply.code(403).send({
        error: "forbidden",
        message: "This key does not have the 'read' scope. Create a read key under API Keys.",
      });
      return;
    }

    const quota = await rateLimit(`v1-read:${key.keyId}`, READ_LIMIT, 60_000);
    if (!quota.allowed) {
      reply
        .code(429)
        .header("retry-after", String(Math.ceil(quota.resetMs / 1000)))
        .send({ error: "rate_limited", message: "Too many requests for this key." });
      return;
    }

    (req as unknown as KeyedRequest).apiKey = key;
  });

  interface ListQuery {
    limit?: string; cursor?: string; since?: string; until?: string;
    traceId?: string; type?: string;
    severity?: string; category?: string; outcome?: string; verdict?: string;
  }

  const listOpts = (q: ListQuery) => ({
    limit: q.limit ? Number(q.limit) : undefined,
    cursor: q.cursor,
    since: q.since,
    until: q.until,
  });

  // Self-description, so a caller can confirm which project and scopes a key
  // has without guessing from a 403.
  app.get("/v1/me", async (req) => {
    const key = keyOf(req);
    return { projectId: key.projectId, scopes: key.scopes };
  });

  app.get<{ Querystring: ListQuery }>("/v1/traces", async (req, reply) => {
    try { return await Api.listTraces(keyOf(req).projectId, listOpts(req.query)); }
    catch (err) { req.log.error({ err }, "v1 traces failed"); reply.code(503).send({ error: "query_failed" }); }
  });

  app.get<{ Params: { id: string } }>("/v1/traces/:id", async (req, reply) => {
    try {
      const r = await Api.getTrace(keyOf(req).projectId, req.params.id);
      if (!r) { reply.code(404).send({ error: "not_found" }); return; }
      return r;
    } catch (err) { req.log.error({ err }, "v1 trace failed"); reply.code(503).send({ error: "query_failed" }); }
  });

  app.get<{ Querystring: ListQuery }>("/v1/observations", async (req, reply) => {
    try {
      return await Api.listObservations(keyOf(req).projectId, {
        ...listOpts(req.query), traceId: req.query.traceId, type: req.query.type,
      });
    } catch (err) { req.log.error({ err }, "v1 observations failed"); reply.code(503).send({ error: "query_failed" }); }
  });

  app.get<{ Querystring: ListQuery }>("/v1/security-events", async (req, reply) => {
    // A filter value we don't recognise is a 400, not a silent empty page. A
    // monitoring query filtered on a typo'd severity would otherwise report "no
    // critical events" indefinitely and look like good news.
    const bad = Api.invalidFilters(req.query);
    if (bad.length) {
      reply.code(400).send({ error: "invalid_filter", message: `Unrecognised filter value(s): ${bad.join(", ")}` });
      return;
    }
    try {
      return await Api.listSecurityEvents(keyOf(req).projectId, {
        ...listOpts(req.query),
        severity: req.query.severity, category: req.query.category,
        outcome: req.query.outcome, verdict: req.query.verdict,
      });
    } catch (err) { req.log.error({ err }, "v1 security events failed"); reply.code(503).send({ error: "query_failed" }); }
  });

  app.get<{ Querystring: ListQuery }>("/v1/summary", async (req, reply) => {
    try { return await Api.summary(keyOf(req).projectId, listOpts(req.query)); }
    catch (err) { req.log.error({ err }, "v1 summary failed"); reply.code(503).send({ error: "query_failed" }); }
  });
}
