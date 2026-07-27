"use strict";
// Best-effort SDK-level patch for `@anthropic-ai/sdk`, mirroring instrument/
// openai.js. The fetch patch captures Anthropic traffic on Node 18+ already
// (the SDK uses global fetch and its /v1/messages shape is recognized), so this
// covers the custom-transport edge case and acts as belt-and-suspenders.

const { runGuarded } = require("../guard");
const { isEnabled, log } = require("../config");
const { captureGeneration } = require("../capture");
const { redefine } = require("./redefine");
const shapes = require("../shapes");

function install() {
  let mod;
  try {
    mod = require("@anthropic-ai/sdk");
  } catch {
    return;
  }
  const Client = mod.Anthropic || mod.default || (typeof mod === "function" ? mod : null);
  if (!Client || Client.__argusPatched) return;

  class ArgusAnthropic extends Client {
    constructor(...args) {
      super(...args);
      try {
        patchInstance(this);
      } catch (err) {
        log("anthropic patchInstance failed", err);
      }
    }
  }
  ArgusAnthropic.__argusPatched = true;

  // Read `default` before swapping `Anthropic`, so we know whether the two
  // exports pointed at the same class to begin with.
  const defaultWasClient = mod.default === Client;
  const named = redefine(mod, "Anthropic", ArgusAnthropic);
  const dflt = defaultWasClient ? redefine(mod, "default", ArgusAnthropic) : false;
  if (!named && !dflt) {
    log("anthropic module reassign failed — exports are not configurable");
  }
}

function patchInstance(client) {
  const messages = client && client.messages;
  if (!messages || typeof messages.create !== "function" || messages.__argus) return;
  const orig = messages.create.bind(messages);
  const provider = shapes.providerFromUrl(client.baseURL || "") || "anthropic";

  messages.create = function (params, opts) {
    if (!isEnabled() || (params && params.stream)) return orig(params, opts);

    const startedAt = new Date();
    const ret = runGuarded(() => orig(params, opts));
    try {
      Promise.resolve(ret).then(
        (message) => {
          try {
            recordMessage(provider, params, message, startedAt);
          } catch (err) {
            log("anthropic record failed", err);
          }
        },
        () => {},
      );
    } catch (err) {
      log("anthropic tap failed", err);
    }
    return ret;
  };
  messages.__argus = true;
}

function recordMessage(provider, params, message, startedAt) {
  const req = shapes.parseRequest("anthropic-messages", params || {});
  const resp = shapes.parseResponse("anthropic-messages", message || {});
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
