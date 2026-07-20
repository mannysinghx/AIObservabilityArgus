"use strict";
// Central configuration + singleton client state for the SDK. init() populates
// this once; every other module reads from getConfig(). Kept deliberately tiny
// and dependency-free.

// Hosted Argus ingest endpoint. Baked in so a customer never has to configure a
// URL — self-hosters override with ingestUrl / ARGUS_INGEST_URL.
const HOSTED_INGEST = "https://argusingest-production.up.railway.app/api/public/ingestion";

const DEFAULTS = {
  ingestUrl: HOSTED_INGEST,
  // How long to buffer observations before flushing, and the max batch size.
  flushIntervalMs: 2000,
  maxBatchSize: 100,
  // Default environment tag on traces when the caller doesn't set one.
  environment: "production",
  // Auto-instrumentation toggles. All on by default — that's the "drop-in" promise.
  instrumentOpenAI: true,
  instrumentAnthropic: true,
  instrumentFetch: true,
  // When true, log a one-line notice for each captured LLM call (handy while
  // wiring things up; noisy in production, so it's off by default).
  debug: false,
};

let state = null; // set by init(); null means "not initialized / disabled"

/**
 * Resolve options, falling back to ARGUS_* environment variables so that in
 * most deployments init() needs no arguments at all.
 */
function resolveConfig(opts = {}) {
  // init("ak_live_…") — the zero-config path: one key, nothing else.
  if (typeof opts === "string") opts = { key: opts };
  const env = process.env;
  const key = opts.key || env.ARGUS_KEY || "";
  const publicKey = opts.publicKey || env.ARGUS_PUBLIC_KEY || "";
  const secretKey = opts.secretKey || env.ARGUS_SECRET_KEY || "";
  const ingestUrl =
    opts.ingestUrl || env.ARGUS_INGEST_URL || DEFAULTS.ingestUrl;

  return {
    key,
    publicKey,
    secretKey,
    ingestUrl,
    // Auto-detect the environment tag so it isn't one more thing to configure.
    environment: opts.environment || env.ARGUS_ENV || env.NODE_ENV || DEFAULTS.environment,
    flushIntervalMs: opts.flushIntervalMs ?? DEFAULTS.flushIntervalMs,
    maxBatchSize: opts.maxBatchSize ?? DEFAULTS.maxBatchSize,
    instrumentOpenAI: opts.instrumentOpenAI ?? DEFAULTS.instrumentOpenAI,
    instrumentAnthropic: opts.instrumentAnthropic ?? DEFAULTS.instrumentAnthropic,
    instrumentFetch: opts.instrumentFetch ?? DEFAULTS.instrumentFetch,
    debug: opts.debug ?? (env.ARGUS_DEBUG === "1" || DEFAULTS.debug),
    // Enabled with either the single ingest key or the legacy public/secret pair.
    enabled: Boolean(key || (publicKey && secretKey)),
  };
}

function setConfig(cfg) {
  state = cfg;
}

function getConfig() {
  return state;
}

function isEnabled() {
  return Boolean(state && state.enabled);
}

function log(...args) {
  if (state && state.debug) console.log("[argus]", ...args);
}

/** Never throw out of the SDK — a warning is the loudest we ever get. */
function warnOnce(key, msg) {
  if (!warnOnce._seen) warnOnce._seen = new Set();
  if (warnOnce._seen.has(key)) return;
  warnOnce._seen.add(key);
  console.warn("[argus] " + msg);
}

module.exports = {
  DEFAULTS,
  resolveConfig,
  setConfig,
  getConfig,
  isEnabled,
  log,
  warnOnce,
};
