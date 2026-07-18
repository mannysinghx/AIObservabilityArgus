"use strict";
// Batched, fire-and-forget delivery to the Argus ingestion endpoint. The single
// hard rule of this file: nothing here may ever throw into, or block, the host
// app's request path. An Argus outage must be invisible to the client's users.
//
// Traces and observations are buffered and flushed on a timer (or when the
// buffer is full). On process exit we make a best-effort final flush so the last
// request's spans aren't lost.

const { getConfig, isEnabled, log, warnOnce } = require("./config");

let traceBuf = [];
let obsBuf = [];
let timer = null;
let exitHooked = false;

function authHeader(cfg) {
  const raw = `${cfg.publicKey}:${cfg.secretKey}`;
  return "Basic " + Buffer.from(raw).toString("base64");
}

function ensureTimer() {
  const cfg = getConfig();
  if (timer || !cfg) return;
  timer = setInterval(() => {
    flush().catch(() => {});
  }, cfg.flushIntervalMs);
  // Don't keep the event loop alive just for the flush timer — a short-lived
  // script should still be free to exit.
  if (timer.unref) timer.unref();

  if (!exitHooked) {
    exitHooked = true;
    // Best-effort final flush. beforeExit fires when the loop would otherwise
    // drain, giving async flush a chance; it won't fire on process.exit()/fatal
    // errors, which is why shutdown() exists as an explicit escape hatch.
    process.once("beforeExit", () => {
      flush().catch(() => {});
    });
  }
}

/** Queue a trace summary for delivery. */
function enqueueTrace(trace) {
  if (!isEnabled()) return;
  traceBuf.push(trace);
  ensureTimer();
  maybeFlushBySize();
}

/** Queue one or more observations for delivery. */
function enqueueObservations(observations) {
  if (!isEnabled() || !observations.length) return;
  for (const o of observations) obsBuf.push(o);
  ensureTimer();
  maybeFlushBySize();
}

function maybeFlushBySize() {
  const cfg = getConfig();
  if (!cfg) return;
  if (obsBuf.length + traceBuf.length >= cfg.maxBatchSize) {
    flush().catch(() => {});
  }
}

/**
 * Send whatever is buffered. Observations are sent before trace summaries: the
 * trace-summary event is what tells Argus's security worker "this trace is
 * complete, run L4", so its observations must already be in flight.
 */
async function flush() {
  const cfg = getConfig();
  if (!cfg || !cfg.enabled) {
    traceBuf = [];
    obsBuf = [];
    return;
  }
  if (!traceBuf.length && !obsBuf.length) return;

  const traces = traceBuf;
  const observations = obsBuf;
  traceBuf = [];
  obsBuf = [];

  try {
    if (observations.length) {
      await post(cfg, { traces: [], observations });
    }
    if (traces.length) {
      await post(cfg, { traces, observations: [] });
    }
  } catch (err) {
    // Never rethrow. One warning per session so a persistent outage doesn't
    // spam logs, but a genuine misconfiguration still surfaces once.
    warnOnce(
      "flush-failed",
      "ingestion request failed (non-fatal, tracing degraded): " +
        (err && err.message ? err.message : String(err)),
    );
    log("flush error", err);
  }
}

async function post(cfg, body) {
  if (typeof fetch !== "function") {
    warnOnce(
      "no-fetch",
      "global fetch is unavailable (Node < 18?) — traces cannot be sent.",
    );
    return;
  }
  // Use the ORIGINAL fetch, never the instrumented one, so delivering a trace
  // can never itself be captured as a trace (infinite loop). instrument/fetch.js
  // stashes the pristine reference here at patch time.
  const send = post._rawFetch || fetch;
  const res = await send(cfg.ingestUrl, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      authorization: authHeader(cfg),
    },
    body: JSON.stringify(body),
  });
  // We ignore the body; we only care that it didn't reject. A non-2xx is
  // logged once for visibility but never thrown.
  if (res && res.ok === false) {
    warnOnce(
      "http-" + res.status,
      "ingestion returned HTTP " + res.status + " — check your API keys.",
    );
  }
}

/** Called by instrument/fetch.js so transport always uses the pristine fetch. */
function setRawFetch(fn) {
  post._rawFetch = fn;
}

/**
 * Flush everything and stop the timer. Call before a deliberate process.exit()
 * (e.g. a serverless handler that can't rely on beforeExit) to guarantee the
 * final batch lands.
 */
async function shutdown() {
  await flush();
  if (timer) {
    clearInterval(timer);
    timer = null;
  }
}

module.exports = {
  enqueueTrace,
  enqueueObservations,
  flush,
  shutdown,
  setRawFetch,
};
