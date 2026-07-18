"use strict";
// Per-request trace context. This is what makes auto-capture "just work":
// middleware() opens an AsyncLocalStorage scope holding the active Trace, and
// every auto-instrumented LLM call reads getActiveTrace() to attach itself —
// no trace object threaded through the caller's code.

const { AsyncLocalStorage } = require("async_hooks");

const als = new AsyncLocalStorage();

/** Run `fn` with `trace` as the active trace for the whole async subtree. */
function runWithTrace(trace, fn) {
  return als.run(trace, fn);
}

/** The Trace bound to the current async context, or null outside any scope. */
function getActiveTrace() {
  return als.getStore() || null;
}

module.exports = { runWithTrace, getActiveTrace };
