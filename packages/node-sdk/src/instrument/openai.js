"use strict";
// Best-effort SDK-level patch for the `openai` package. The fetch patch already
// captures OpenAI SDK traffic on Node 18+ (the SDK uses global fetch), so this
// exists mainly for the edge case of a client configured with a custom fetch/
// transport, and as belt-and-suspenders. It is fully defensive: if the SDK
// isn't installed or its internals don't match, it silently does nothing.
//
// Non-streaming calls are recorded here and wrapped in runGuarded() so the fetch
// layer skips them (no double count). Streaming calls are passed straight
// through — unguarded — so the fetch layer captures them instead.

const { runGuarded } = require("../guard");
const { isEnabled, log } = require("../config");
const { captureGeneration } = require("../capture");
const shapes = require("../shapes");

function install() {
  let mod;
  try {
    mod = require("openai");
  } catch {
    return; // not a dependency of the host app — nothing to do
  }
  const Client = mod.OpenAI || mod.default || (typeof mod === "function" ? mod : null);
  if (!Client || Client.__argusPatched) return;

  class ArgusOpenAI extends Client {
    constructor(...args) {
      super(...args);
      try {
        patchInstance(this);
      } catch (err) {
        log("openai patchInstance failed", err);
      }
    }
  }
  ArgusOpenAI.__argusPatched = true;

  try {
    mod.OpenAI = ArgusOpenAI;
    if (mod.default === Client) mod.default = ArgusOpenAI;
  } catch (err) {
    log("openai module reassign failed", err);
  }
}

function patchInstance(client) {
  const comps = client && client.chat && client.chat.completions;
  if (!comps || typeof comps.create !== "function" || comps.__argus) return;
  const orig = comps.create.bind(comps);
  const provider = shapes.providerFromUrl(client.baseURL || "") || "openai";

  comps.create = function (params, opts) {
    // Disabled, or a streaming call → let it run unguarded; fetch layer handles
    // streaming capture.
    if (!isEnabled() || (params && params.stream)) return orig(params, opts);

    const startedAt = new Date();
    const ret = runGuarded(() => orig(params, opts));
    try {
      // Tap the result without changing what the caller receives (the SDK's
      // APIPromise is returned untouched, preserving .withResponse() etc.).
      Promise.resolve(ret).then(
        (completion) => {
          try {
            recordChat(provider, params, completion, startedAt);
          } catch (err) {
            log("openai record failed", err);
          }
        },
        () => {}, // request errors are the caller's to handle; we stay silent
      );
    } catch (err) {
      log("openai tap failed", err);
    }
    return ret;
  };
  comps.__argus = true;
}

function recordChat(provider, params, completion, startedAt) {
  const req = shapes.parseRequest("openai-chat", params || {});
  const resp = shapes.parseResponse("openai-chat", completion || {});
  captureGeneration(req.model || provider, {
    model: req.model,
    provider,
    input: req.input,
    output: resp.output,
    inputTokens: resp.inputTokens,
    outputTokens: resp.outputTokens,
    finishReason: resp.finishReason,
    startTime: startedAt,
    endTime: new Date(),
  });
}

module.exports = { install };
