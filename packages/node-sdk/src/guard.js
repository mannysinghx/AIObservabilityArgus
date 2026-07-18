"use strict";
// Prevents double-counting. When an SDK-level patch (openai/anthropic) handles a
// call, it runs the underlying request inside runGuarded(); the fetch patch sees
// isGuarded() === true and passes that request through WITHOUT capturing it, so
// the same LLM call is never recorded twice.

const { AsyncLocalStorage } = require("async_hooks");
const als = new AsyncLocalStorage();

function runGuarded(fn) {
  return als.run(true, fn);
}

function isGuarded() {
  return als.getStore() === true;
}

module.exports = { runGuarded, isGuarded };
