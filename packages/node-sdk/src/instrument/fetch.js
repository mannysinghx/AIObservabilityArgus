"use strict";
// Global-fetch instrumentation — the primary, provider-agnostic capture point.
// On Node 18+ the OpenAI and Anthropic SDKs both dispatch through global fetch,
// and autogovern.io's multi-provider chain calls OpenAI-compatible endpoints
// with raw fetch, so patching fetch once captures essentially everything.
//
// Absolute constraints:
//   * the caller's Response is returned untouched and unconsumed
//   * capture runs off to the side (clone / tee); never on the caller's path
//   * any error in here is swallowed — the request proceeds as if unpatched

const { isGuarded } = require("../guard");
const { isEnabled, log } = require("../config");
const { setRawFetch } = require("../transport");
const { captureGeneration } = require("../capture");
const shapes = require("../shapes");

let patched = false;

function install() {
  if (patched) return;
  if (typeof globalThis.fetch !== "function") {
    // Node < 18 or a runtime without global fetch — nothing to patch. The
    // transport layer surfaces the "can't send" warning separately.
    return;
  }
  const raw = globalThis.fetch;
  setRawFetch(raw); // ensure trace delivery always uses the pristine fetch

  globalThis.fetch = function argusFetch(input, init) {
    // Fast path: disabled, already handled at an SDK layer, or clearly not a
    // POST we care about — do nothing but forward.
    if (!isEnabled() || isGuarded()) return raw.call(this, input, init);

    let meta;
    try {
      meta = describe(input, init);
    } catch {
      meta = null;
    }
    if (!meta || !meta.kind) return raw.call(this, input, init);

    const startedAt = new Date();
    const p = raw.call(this, input, init);
    // Attach capture to the promise without altering what the caller receives.
    return p.then((res) => {
      let isStream = false;
      try {
        isStream = decideStream(meta, res);
      } catch (err) {
        log("stream decision failed", err);
      }
      // Capture strictly OFF the caller's path — for both streaming and JSON.
      // We read a clone in the background and hand the untouched response back
      // immediately. Blocking on the clone before the caller reads the original
      // can deadlock/abort undici's shared-body backpressure (the caller can't
      // read until we finish, and our clone can't finish until the caller
      // reads), which silently loses the response body. Recording a beat later
      // is fine: it still lands well before the request ends and the trace
      // closes.
      try {
        if (isStream) captureStreaming(meta, startedAt, res);
        else captureJson(meta, startedAt, res);
      } catch (err) {
        log("fetch capture error", err);
      }
      return res;
    });
  };
  globalThis.fetch.__argus = true;
  patched = true;
}

/** Extract url + method + parsed JSON body from the fetch arguments. */
function describe(input, init) {
  let url = "";
  let method = "GET";
  let bodyRaw;

  if (typeof input === "string") url = input;
  else if (input && typeof input.url === "string") {
    url = input.url; // Request object
    method = input.method || method;
  } else if (input) url = String(input);

  if (init) {
    if (init.method) method = init.method;
    if (init.body != null) bodyRaw = init.body;
  }
  if (String(method).toUpperCase() !== "POST") return null;

  let body = null;
  if (typeof bodyRaw === "string") {
    try {
      body = JSON.parse(bodyRaw);
    } catch {
      body = null;
    }
  }
  // If we couldn't read a body (e.g. a Request with a stream body), we can still
  // classify by URL alone for the well-known endpoints.
  const kind = shapes.classify(url, body);
  if (!kind) return null;
  const req = shapes.parseRequest(kind, body || {});
  return {
    kind,
    url,
    provider: shapes.providerFromUrl(url),
    model: req.model,
    input: req.input,
    stream: req.stream,
  };
}

function decideStream(meta, res) {
  if (meta.stream) return true;
  const ct = (res && res.headers && res.headers.get && res.headers.get("content-type")) || "";
  return /event-stream/i.test(ct);
}

function captureJson(meta, startedAt, res) {
  // Read a CLONE so the caller's res is left fully intact.
  let clone;
  try {
    clone = res && typeof res.clone === "function" ? res.clone() : null;
  } catch {
    clone = null;
  }
  if (!clone) {
    record(meta, startedAt, { output: "", inputTokens: 0, outputTokens: 0, finishReason: "" });
    return Promise.resolve();
  }
  return clone
    .json()
    .then((json) => record(meta, startedAt, shapes.parseResponse(meta.kind, json)))
    .catch((err) => {
      log("json capture failed", err);
      // Still record the request side so the call isn't invisible.
      record(meta, startedAt, { output: "", inputTokens: 0, outputTokens: 0, finishReason: "" });
    });
}

function captureStreaming(meta, startedAt, res) {
  // Read a clone's stream so the caller's original body is never touched.
  let clone;
  try {
    clone = res.clone();
  } catch {
    return record(meta, startedAt, { output: "[streamed]", inputTokens: 0, outputTokens: 0, finishReason: "" });
  }
  clone
    .text()
    .then((sseText) => record(meta, startedAt, shapes.parseStream(meta.kind, sseText)))
    .catch((err) => {
      log("stream capture failed", err);
      record(meta, startedAt, { output: "[streamed]", inputTokens: 0, outputTokens: 0, finishReason: "" });
    });
}

function record(meta, startedAt, resp) {
  captureGeneration(meta.model || meta.provider || "generation", {
    model: meta.model,
    provider: meta.provider,
    input: meta.input,
    output: resp.output,
    inputTokens: resp.inputTokens,
    outputTokens: resp.outputTokens,
    finishReason: resp.finishReason,
    startTime: startedAt,
    endTime: new Date(),
  });
}

module.exports = { install };
