"use strict";
// @argus/node — drop-in auto-instrumenting tracer for Argus.
//
//   const argus = require('@argus/node').init();   // reads ARGUS_* env vars
//   app.use(argus.middleware());                    // Express: one trace / request
//
// After init(), every OpenAI / Anthropic / OpenAI-compatible LLM call is
// captured automatically. Retrieval and tool spans are optional one-liners.

const {
  resolveConfig,
  setConfig,
  isEnabled,
  warnOnce,
  log,
} = require("./config");
const { runWithTrace, getActiveTrace } = require("./context");
const { Trace } = require("./trace");
const transport = require("./transport");
const fetchInstr = require("./instrument/fetch");
const openaiInstr = require("./instrument/openai");
const anthropicInstr = require("./instrument/anthropic");

const VERSION = "0.1.0";
let initialized = false;

/**
 * Initialize the SDK. Idempotent — safe to call more than once. Options fall
 * back to ARGUS_PUBLIC_KEY / ARGUS_SECRET_KEY / ARGUS_INGEST_URL, so in most
 * deployments this needs no arguments. Returns the API for one-line chaining.
 */
function init(opts = {}) {
  const cfg = resolveConfig(opts);
  setConfig(cfg);

  if (!cfg.enabled) {
    warnOnce(
      "no-keys",
      "ARGUS_PUBLIC_KEY / ARGUS_SECRET_KEY not set — tracing is disabled, no data will be sent. " +
        "Set both to start capturing.",
    );
  }

  if (!initialized) {
    // Install patches once. They short-circuit while disabled, so it's safe to
    // install even before keys are present (e.g. keys set by a later config load).
    if (cfg.instrumentFetch) safe(() => fetchInstr.install(), "fetch");
    if (cfg.instrumentOpenAI) safe(() => openaiInstr.install(), "openai");
    if (cfg.instrumentAnthropic) safe(() => anthropicInstr.install(), "anthropic");
    initialized = true;
    log("initialized", { ingestUrl: cfg.ingestUrl, enabled: cfg.enabled });
  }
  return api;
}

function safe(fn, label) {
  try {
    fn();
  } catch (err) {
    log(label + " install failed (continuing)", err);
  }
}

// ---------- Express middleware ----------

/**
 * Express/Connect middleware: opens a trace for each request so every LLM call
 * during that request is grouped into one trace, and closes it when the
 * response finishes. Options:
 *   name(req)         -> custom trace name       (default: "METHOD /path")
 *   getSessionId(req) -> session id              (default: common session fields)
 *   getUserId(req)    -> user id                 (default: req.user.id / req.userId)
 *   tags(req)         -> string[]
 */
function middleware(opts = {}) {
  return function argusMiddleware(req, res, next) {
    if (!isEnabled()) return next();
    let t;
    try {
      const meta = {
        sessionId: str(opts.getSessionId ? opts.getSessionId(req) : defaultSession(req)),
        userId: str(opts.getUserId ? opts.getUserId(req) : defaultUser(req)),
        tags: opts.tags ? opts.tags(req) : undefined,
      };
      const name = (opts.name && opts.name(req)) || defaultName(req);
      t = new Trace(name, meta);
    } catch (err) {
      log("middleware setup failed", err);
      return next();
    }

    runWithTrace(t, () => {
      let done = false;
      const finish = () => {
        if (done) return;
        done = true;
        try {
          t.finish();
        } catch (err) {
          log("trace finish failed", err);
        }
      };
      res.on("finish", finish);
      res.on("close", finish);
      next();
    });
  };
}

function defaultName(req) {
  const path = req.path || req.originalUrl || req.url || "/";
  return `${req.method || "REQ"} ${String(path).split("?")[0]}`;
}
function defaultSession(req) {
  return (
    req.sessionID ||
    (req.session && (req.session.id || req.session.sessionID)) ||
    req.headers?.["x-session-id"] ||
    ""
  );
}
function defaultUser(req) {
  return (req.user && (req.user.id || req.user._id || req.user.userId)) || req.userId || "";
}
function str(v) {
  return v == null ? "" : String(v);
}

// ---------- manual spans (optional one-liners) ----------
// Each reads the active request trace; outside a request they emit a standalone
// single-span trace so nothing is silently lost.

function onTrace(fn, name, meta) {
  const active = getActiveTrace();
  if (active) {
    fn(active);
    active.flushObservations();
    return;
  }
  if (!isEnabled()) return;
  const t = new Trace(name, meta || {});
  fn(t);
  t.finish();
}

function retrieval(name, text, opts = {}) {
  if (!isEnabled()) return;
  onTrace((t) => t.retrieval(name, text, opts), name || "retrieval");
}
function tool(name, opts = {}) {
  if (!isEnabled()) return;
  onTrace((t) => t.tool(name, opts), name || "tool");
}
function generation(name, opts = {}) {
  if (!isEnabled()) return;
  onTrace((t) => t.generation(name, opts), name || opts.model || "generation");
}

/** Merge metadata (sessionId, userId, tags, ...) onto the active trace. */
function annotate(meta = {}) {
  const active = getActiveTrace();
  if (active) Object.assign(active.meta, meta);
}

/**
 * Wrap an async function in a fresh trace context — the non-Express way to group
 * calls (workers, queues, scripts). Returns whatever fn returns; the trace is
 * finished when fn settles.
 */
function trace(name, metaOrFn, maybeFn) {
  let meta = {};
  let fn = maybeFn;
  if (typeof metaOrFn === "function") fn = metaOrFn;
  else meta = metaOrFn || {};
  const t = new Trace(name, meta);
  return runWithTrace(t, async () => {
    try {
      return await fn(t);
    } finally {
      try {
        t.finish();
      } catch (err) {
        log("trace() finish failed", err);
      }
    }
  });
}

/** The trace bound to the current async context, or null. Advanced use. */
function activeTrace() {
  return getActiveTrace();
}

module.exports = {
  init,
  middleware,
  retrieval,
  tool,
  generation,
  annotate,
  trace,
  activeTrace,
  flush: transport.flush,
  shutdown: transport.shutdown,
  version: VERSION,
};

const api = module.exports;
