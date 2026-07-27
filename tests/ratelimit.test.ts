/**
 * These run without a Redis server, which exercises the branch that matters
 * most: when Redis is unreachable the limiter must still limit. A limiter that
 * fails open turns "our cache node died" into "and also anyone could brute-force
 * every password during the outage".
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { rateLimit, LIMITS, closeRateLimiter } from "@argus/shared";

// The limiter holds a Redis socket that would otherwise keep the process alive
// (and, when Redis is absent, keep reconnecting) after the last assertion.
after(async () => { await closeRateLimiter(); });

// Unique per run so repeated local runs don't inherit a previous window.
const k = (name: string) => `test:${name}:${process.pid}:${Math.random().toString(36).slice(2)}`;

test("allows up to the limit, then blocks", async () => {
  const key = k("basic");
  for (let i = 0; i < 3; i++) {
    const r = await rateLimit(key, 3, 60_000);
    assert.equal(r.allowed, true, `hit ${i + 1} of 3 should be allowed`);
  }
  const over = await rateLimit(key, 3, 60_000);
  assert.equal(over.allowed, false);
  assert.equal(over.remaining, 0);
});

test("degrades rather than failing open when Redis is absent", async () => {
  const r = await rateLimit(k("degraded"), 1, 60_000);
  // The suite runs with no Redis; if this ever reports non-degraded, the test
  // env gained a Redis and the fallback path is no longer being covered here.
  assert.equal(r.degraded, true, "expected the in-process fallback path");
  assert.equal(r.allowed, true);
});

test("counts each key independently", async () => {
  const a = k("iso-a");
  const b = k("iso-b");
  await rateLimit(a, 1, 60_000);
  assert.equal((await rateLimit(a, 1, 60_000)).allowed, false, "a is exhausted");
  assert.equal((await rateLimit(b, 1, 60_000)).allowed, true, "b is untouched");
});

test("the window resets", async () => {
  const key = k("window");
  const windowMs = 60;
  assert.equal((await rateLimit(key, 1, windowMs)).allowed, true);
  assert.equal((await rateLimit(key, 1, windowMs)).allowed, false);
  await new Promise((r) => setTimeout(r, windowMs + 20));
  assert.equal((await rateLimit(key, 1, windowMs)).allowed, true, "next window starts fresh");
});

test("reports a sane retry-after", async () => {
  const key = k("reset");
  const r = await rateLimit(key, 1, 5_000);
  assert.ok(r.resetMs > 0 && r.resetMs <= 5_000, `resetMs out of range: ${r.resetMs}`);
});

test("login policy is tight enough to matter", () => {
  // A guard on the values themselves: these are the numbers standing between an
  // exposed login form and offline-speed password guessing, and they are easy to
  // relax by accident while debugging.
  assert.ok(LIMITS.login.limit <= 20, "login limit should stay small");
  assert.ok(LIMITS.login.windowMs >= 5 * 60_000, "login window should be minutes, not seconds");
  assert.ok(LIMITS.emailTrigger.limit <= 10, "email triggers cost money — keep this low");
});
