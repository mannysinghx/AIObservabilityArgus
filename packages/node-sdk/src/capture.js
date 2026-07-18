"use strict";
// The bridge auto-instrumentation uses to record a captured LLM call. It hides
// the "is there an active trace?" decision from every patch module:
//   - inside a request scope (middleware ran)  -> attach to that trace
//   - outside any scope (a script, a worker)   -> emit a standalone one-span
//     trace so the call still shows up on its own.

const { getActiveTrace } = require("./context");
const { Trace } = require("./trace");
const { isEnabled, log } = require("./config");

/**
 * Record an auto-captured generation. `gen` is the same opts object Trace
 * .generation() accepts ({ model, provider, input, output, inputTokens,
 * outputTokens, ... }). `name` labels the span (defaults to the model).
 */
function captureGeneration(name, gen) {
  if (!isEnabled()) return;
  const label = name || gen.model || "generation";
  const active = getActiveTrace();
  if (active) {
    active.generation(label, gen);
    active.flushObservations();
    log("captured generation on active trace", active.traceId, label);
    return;
  }
  // No surrounding request context — stand up a throwaway trace for this one
  // call so it isn't silently dropped. finish() emits it immediately.
  const t = new Trace(label, {});
  t.generation(label, gen);
  t.finish();
  log("captured generation as standalone trace", t.traceId, label);
}

module.exports = { captureGeneration };
