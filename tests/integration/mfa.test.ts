/**
 * The half of two-factor auth that mfa.test.ts cannot reach: everything that
 * lives in Postgres and everything decided at the HTTP layer.
 *
 * tests/mfa.test.ts proves the arithmetic agrees with RFC 6238. What it cannot
 * prove is that a code is refused the *second* time it is presented, that a
 * recovery code is spent exactly once, that a correct password alone hands back
 * no session, or that the enrolment routes sit on the authenticated side of the
 * `/api/auth/` boundary. Each of those is a property of the database and the
 * route table, and each is the kind of thing that silently regresses.
 *
 * Requests go through `app.inject()` against the real Fastify instance for the
 * same reason isolation.test.ts does it: the authorization decisions being
 * tested are made in the preHandler, and none of them are visible from below
 * the HTTP layer.
 */
import { test, describe, before, after } from "node:test";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { closeSharedConnections } from "@argus/shared";
import { buildApp } from "../../apps/web/src/app.js";
import { totpCode, generateRecoveryCodes, STEP_SECONDS } from "../../apps/web/src/totp.js";
import { pool, infraAvailable, type App } from "./helpers.js";

let app: App;
let available = false;
const createdUsers: string[] = [];

// Distinct client addresses, for the reason helpers.ts documents at length:
// login and mfa/verify are rate limited per IP, the counter lives in Redis and
// survives between runs, so fixtures sharing 127.0.0.1 exhaust their own quota
// and fail in a way that looks like a broken feature rather than a working limit.
let clientSeq = Math.floor(Math.random() * 0xfff0);
function ip(): string {
  clientSeq = (clientSeq + 1) & 0xffff;
  return `10.${1 + (clientSeq % 200)}.${(clientSeq >> 8) & 0xff}.${(clientSeq & 0xff) || 1}`;
}

function cookieOf(res: { headers: Record<string, unknown> }): string | null {
  const raw = res.headers["set-cookie"];
  const first = Array.isArray(raw) ? raw[0] : (raw as string | undefined);
  return first ? first.split(";")[0] : null;
}

interface User { email: string; password: string; id: string; cookie: string }

/** A signed-in account. No ClickHouse — nothing here reads trace data. */
async function makeUser(label: string): Promise<User> {
  const nonce = randomUUID().slice(0, 8);
  const email = `${label}-${nonce}@example.test`;
  const password = "correct horse battery staple";
  const res = await app.inject({
    method: "POST", url: "/api/auth/signup", remoteAddress: ip(),
    payload: { email, password, name: label, company: `${label} Ltd ${nonce}` },
  });
  assert.equal(res.statusCode, 200, `signup failed: ${res.body}`);
  const id = res.json().user.id as string;
  createdUsers.push(id);
  return { email, password, id, cookie: cookieOf(res)! };
}

/**
 * The code for the *next* time step.
 *
 * Confirming enrolment spends the current step — that is the replay guard
 * working, not a quirk of the test harness — so any code presented afterwards
 * inside the same 30-second window is correctly refused. Tests that enrol and
 * then sign in have to move to the next step, exactly as a real user's
 * authenticator would have by the time they next reach a login form. There is a
 * test below that pins this behaviour down deliberately rather than leaving it
 * as folklore.
 */
function nextCode(secret: string): string {
  return totpCode(secret, Date.now() + STEP_SECONDS * 1000);
}

/** Walk a user all the way through enrolment; returns the TOTP secret + recovery codes. */
async function enrol(u: User): Promise<{ secret: string; recoveryCodes: string[] }> {
  const setup = await app.inject({ method: "POST", url: "/api/mfa/setup", headers: { cookie: u.cookie } });
  assert.equal(setup.statusCode, 200, `setup failed: ${setup.body}`);
  const secret = setup.json().secret as string;

  const enable = await app.inject({
    method: "POST", url: "/api/mfa/enable", headers: { cookie: u.cookie },
    payload: { code: totpCode(secret) },
  });
  assert.equal(enable.statusCode, 200, `enable failed: ${enable.body}`);
  return { secret, recoveryCodes: enable.json().recoveryCodes as string[] };
}

before(async () => {
  app = await buildApp();
  await app.ready();
  available = await infraAvailable();
});

after(async () => {
  for (const id of createdUsers) {
    await pool.query("DELETE FROM users WHERE id = $1", [id]).catch(() => {});
  }
  await pool.end().catch(() => {});
  // Redis/ClickHouse clients hold the event loop open; without this the file
  // passes every assertion and still fails on the file-level timeout.
  await closeSharedConnections();
  await app?.close().catch(() => {});
});

function dbTest(name: string, fn: () => Promise<void>) {
  test(name, async (t) => {
    if (!available) return t.skip("postgres/clickhouse not available");
    await fn();
  });
}

describe("enrolment", () => {
  dbTest("setup returns a usable secret and an otpauth URI", async () => {
    const u = await makeUser("enrol");
    const res = await app.inject({ method: "POST", url: "/api/mfa/setup", headers: { cookie: u.cookie } });
    assert.equal(res.statusCode, 200);
    const { secret, otpauthUrl } = res.json();
    assert.match(secret, /^[A-Z2-7]{32}$/);
    assert.ok(otpauthUrl.startsWith("otpauth://totp/"));
    assert.ok(otpauthUrl.includes(`secret=${secret}`));
  });

  dbTest("MFA is not active until a code confirms it", async () => {
    const u = await makeUser("unconfirmed");
    await app.inject({ method: "POST", url: "/api/mfa/setup", headers: { cookie: u.cookie } });

    const status = await app.inject({ method: "GET", url: "/api/mfa", headers: { cookie: u.cookie } });
    assert.equal(status.json().enabled, false, "an unconfirmed enrolment must not count as enabled");
    assert.equal(status.json().pendingSetup, true);

    // The load-bearing half: a half-finished setup must not gate login, or the
    // user is locked out of their own account by an abandoned wizard.
    const login = await app.inject({
      method: "POST", url: "/api/auth/login", remoteAddress: ip(),
      payload: { email: u.email, password: u.password },
    });
    assert.equal(login.statusCode, 200);
    assert.ok(!login.json().mfaRequired, "unconfirmed setup must not challenge login");
    assert.ok(cookieOf(login), "unconfirmed setup must still issue a session");
  });

  dbTest("a wrong code does not enable it", async () => {
    const u = await makeUser("wrongenable");
    await app.inject({ method: "POST", url: "/api/mfa/setup", headers: { cookie: u.cookie } });
    const res = await app.inject({
      method: "POST", url: "/api/mfa/enable", headers: { cookie: u.cookie }, payload: { code: "000000" },
    });
    assert.equal(res.statusCode, 400);
    const status = await app.inject({ method: "GET", url: "/api/mfa", headers: { cookie: u.cookie } });
    assert.equal(status.json().enabled, false);
  });

  dbTest("enabling issues ten recovery codes and reports them as remaining", async () => {
    const u = await makeUser("codes");
    const { recoveryCodes } = await enrol(u);
    assert.equal(recoveryCodes.length, 10);
    const status = await app.inject({ method: "GET", url: "/api/mfa", headers: { cookie: u.cookie } });
    assert.equal(status.json().enabled, true);
    assert.equal(status.json().recoveryRemaining, 10);
  });

  dbTest("setup is refused once MFA is already on", async () => {
    const u = await makeUser("resetup");
    await enrol(u);
    const res = await app.inject({ method: "POST", url: "/api/mfa/setup", headers: { cookie: u.cookie } });
    assert.equal(res.statusCode, 400, "changing the secret must go through disable()");
  });
});

describe("login", () => {
  dbTest("a correct password alone yields a challenge and NO session", async () => {
    const u = await makeUser("challenge");
    await enrol(u);
    const res = await app.inject({
      method: "POST", url: "/api/auth/login", remoteAddress: ip(),
      payload: { email: u.email, password: u.password },
    });
    assert.equal(res.statusCode, 200);
    assert.equal(res.json().mfaRequired, true);
    assert.ok(res.json().challenge, "a challenge token must be returned");
    assert.equal(cookieOf(res), null, "no session cookie may be set before the second factor");
  });

  dbTest("the challenge token is not itself a session", async () => {
    const u = await makeUser("notasession");
    await enrol(u);
    const login = await app.inject({
      method: "POST", url: "/api/auth/login", remoteAddress: ip(),
      payload: { email: u.email, password: u.password },
    });
    const challenge = login.json().challenge as string;
    // Try to use it where a session cookie belongs.
    const res = await app.inject({
      method: "GET", url: "/api/mfa", headers: { cookie: `argus_session=${challenge}` },
    });
    assert.equal(res.statusCode, 401, "a challenge token must not authenticate anything");
  });

  dbTest("a valid code completes the login and sets a session", async () => {
    const u = await makeUser("goodcode");
    const { secret } = await enrol(u);
    const login = await app.inject({
      method: "POST", url: "/api/auth/login", remoteAddress: ip(),
      payload: { email: u.email, password: u.password },
    });
    const res = await app.inject({
      method: "POST", url: "/api/auth/mfa/verify", remoteAddress: ip(),
      payload: { challenge: login.json().challenge, code: nextCode(secret) },
    });
    assert.equal(res.statusCode, 200, res.body);
    const cookie = cookieOf(res);
    assert.ok(cookie, "a session cookie must be set");
    const me = await app.inject({ method: "GET", url: "/api/auth/me", headers: { cookie: cookie! } });
    assert.equal(me.statusCode, 200);
    assert.equal(me.json().user.id, u.id);
  });

  dbTest("a wrong code is refused but the challenge survives the typo", async () => {
    const u = await makeUser("typo");
    const { secret } = await enrol(u);
    const login = await app.inject({
      method: "POST", url: "/api/auth/login", remoteAddress: ip(),
      payload: { email: u.email, password: u.password },
    });
    const challenge = login.json().challenge as string;
    const addr = ip();

    const bad = await app.inject({
      method: "POST", url: "/api/auth/mfa/verify", remoteAddress: addr,
      payload: { challenge, code: "000000" },
    });
    assert.equal(bad.statusCode, 401);
    assert.equal(cookieOf(bad), null);

    const good = await app.inject({
      method: "POST", url: "/api/auth/mfa/verify", remoteAddress: addr,
      payload: { challenge, code: nextCode(secret) },
    });
    assert.equal(good.statusCode, 200, "a mistyped code must not cost the user their challenge");
  });

  dbTest("an unknown challenge is refused", async () => {
    const res = await app.inject({
      method: "POST", url: "/api/auth/mfa/verify", remoteAddress: ip(),
      payload: { challenge: "not-a-real-challenge", code: "123456" },
    });
    assert.equal(res.statusCode, 401);
  });

  // The replay guard, persisted. This is the assertion the unit suite cannot
  // make: last_used_step has to survive the round-trip through Postgres.
  dbTest("the same code cannot be used twice", async () => {
    const u = await makeUser("replay");
    const { secret } = await enrol(u);
    const code = nextCode(secret);

    const first = await app.inject({
      method: "POST", url: "/api/auth/login", remoteAddress: ip(),
      payload: { email: u.email, password: u.password },
    });
    const ok = await app.inject({
      method: "POST", url: "/api/auth/mfa/verify", remoteAddress: ip(),
      payload: { challenge: first.json().challenge, code },
    });
    assert.equal(ok.statusCode, 200, ok.body);

    const second = await app.inject({
      method: "POST", url: "/api/auth/login", remoteAddress: ip(),
      payload: { email: u.email, password: u.password },
    });
    const replay = await app.inject({
      method: "POST", url: "/api/auth/mfa/verify", remoteAddress: ip(),
      payload: { challenge: second.json().challenge, code },
    });
    assert.equal(replay.statusCode, 401, "a replayed code must be refused");
    assert.equal(cookieOf(replay), null);
  });

  // Discovered by this suite: the code that confirms enrolment is spent, so it
  // cannot also sign you in during the same 30-second window. That is the replay
  // guard behaving correctly and it costs a real user nothing — enabling MFA
  // leaves you already signed in — but it is surprising enough to pin down.
  dbTest("the code that enabled MFA cannot then be used to sign in", async () => {
    const u = await makeUser("enrolcode");
    const setup = await app.inject({ method: "POST", url: "/api/mfa/setup", headers: { cookie: u.cookie } });
    const secret = setup.json().secret as string;
    const code = totpCode(secret);
    await app.inject({
      method: "POST", url: "/api/mfa/enable", headers: { cookie: u.cookie }, payload: { code },
    });

    const login = await app.inject({
      method: "POST", url: "/api/auth/login", remoteAddress: ip(),
      payload: { email: u.email, password: u.password },
    });
    const res = await app.inject({
      method: "POST", url: "/api/auth/mfa/verify", remoteAddress: ip(),
      payload: { challenge: login.json().challenge, code },
    });
    assert.equal(res.statusCode, 401, "the enrolment code is spent");

    // …and the next step's code works, so the account is not stuck.
    const ok = await app.inject({
      method: "POST", url: "/api/auth/mfa/verify", remoteAddress: ip(),
      payload: { challenge: login.json().challenge, code: nextCode(secret) },
    });
    assert.equal(ok.statusCode, 200, ok.body);
  });

  dbTest("an expired challenge is refused", async () => {
    const u = await makeUser("expired");
    const { secret } = await enrol(u);
    const login = await app.inject({
      method: "POST", url: "/api/auth/login", remoteAddress: ip(),
      payload: { email: u.email, password: u.password },
    });
    // Age the challenge past its TTL rather than waiting five minutes for it.
    await pool.query("UPDATE mfa_challenges SET expires_at = now() - interval '1 minute' WHERE user_id = $1", [u.id]);
    const res = await app.inject({
      method: "POST", url: "/api/auth/mfa/verify", remoteAddress: ip(),
      payload: { challenge: login.json().challenge, code: nextCode(secret) },
    });
    assert.equal(res.statusCode, 401);
  });
});

describe("recovery codes", () => {
  dbTest("a recovery code signs you in, exactly once", async () => {
    const u = await makeUser("recovery");
    const { recoveryCodes } = await enrol(u);
    const code = recoveryCodes[0];

    const login1 = await app.inject({
      method: "POST", url: "/api/auth/login", remoteAddress: ip(),
      payload: { email: u.email, password: u.password },
    });
    const first = await app.inject({
      method: "POST", url: "/api/auth/mfa/verify", remoteAddress: ip(),
      payload: { challenge: login1.json().challenge, code },
    });
    assert.equal(first.statusCode, 200, first.body);
    assert.equal(first.json().usedRecoveryCode, true);
    assert.ok(cookieOf(first));

    const login2 = await app.inject({
      method: "POST", url: "/api/auth/login", remoteAddress: ip(),
      payload: { email: u.email, password: u.password },
    });
    const second = await app.inject({
      method: "POST", url: "/api/auth/mfa/verify", remoteAddress: ip(),
      payload: { challenge: login2.json().challenge, code },
    });
    assert.equal(second.statusCode, 401, "a spent recovery code must not work again");
  });

  dbTest("spending one decrements the remaining count", async () => {
    const u = await makeUser("decrement");
    const { recoveryCodes } = await enrol(u);
    const login = await app.inject({
      method: "POST", url: "/api/auth/login", remoteAddress: ip(),
      payload: { email: u.email, password: u.password },
    });
    const res = await app.inject({
      method: "POST", url: "/api/auth/mfa/verify", remoteAddress: ip(),
      payload: { challenge: login.json().challenge, code: recoveryCodes[3] },
    });
    assert.equal(res.statusCode, 200);
    const status = await app.inject({ method: "GET", url: "/api/mfa", headers: { cookie: cookieOf(res)! } });
    assert.equal(status.json().recoveryRemaining, 9);
  });

  dbTest("a code from someone else's account is refused", async () => {
    const victim = await makeUser("victim");
    await enrol(victim);
    const attacker = await makeUser("attacker");
    const { recoveryCodes } = await enrol(attacker);

    const login = await app.inject({
      method: "POST", url: "/api/auth/login", remoteAddress: ip(),
      payload: { email: victim.email, password: victim.password },
    });
    const res = await app.inject({
      method: "POST", url: "/api/auth/mfa/verify", remoteAddress: ip(),
      payload: { challenge: login.json().challenge, code: recoveryCodes[0] },
    });
    assert.equal(res.statusCode, 401, "recovery codes must be scoped to their own user");
  });

  dbTest("an unissued code is refused", async () => {
    const u = await makeUser("unissued");
    await enrol(u);
    const login = await app.inject({
      method: "POST", url: "/api/auth/login", remoteAddress: ip(),
      payload: { email: u.email, password: u.password },
    });
    const res = await app.inject({
      method: "POST", url: "/api/auth/mfa/verify", remoteAddress: ip(),
      payload: { challenge: login.json().challenge, code: generateRecoveryCodes(1)[0] },
    });
    assert.equal(res.statusCode, 401);
  });
});

describe("disabling", () => {
  dbTest("needs both the password and a current code", async () => {
    const u = await makeUser("disable");
    const { secret } = await enrol(u);

    const noPass = await app.inject({
      method: "POST", url: "/api/mfa/disable", headers: { cookie: u.cookie },
      payload: { password: "wrong password", code: nextCode(secret) },
    });
    assert.equal(noPass.statusCode, 400, "a stolen session alone must not disable MFA");

    const noCode = await app.inject({
      method: "POST", url: "/api/mfa/disable", headers: { cookie: u.cookie },
      payload: { password: u.password, code: "000000" },
    });
    assert.equal(noCode.statusCode, 400);

    const status = await app.inject({ method: "GET", url: "/api/mfa", headers: { cookie: u.cookie } });
    assert.equal(status.json().enabled, true, "MFA must survive both failed attempts");
  });

  dbTest("with both, it turns off and login stops challenging", async () => {
    const u = await makeUser("disableok");
    const { secret } = await enrol(u);
    // A fresh step, so the code isn't one the enable() call already burned.
    const code = nextCode(secret);
    const res = await app.inject({
      method: "POST", url: "/api/mfa/disable", headers: { cookie: u.cookie },
      payload: { password: u.password, code },
    });
    assert.equal(res.statusCode, 200, res.body);

    const login = await app.inject({
      method: "POST", url: "/api/auth/login", remoteAddress: ip(),
      payload: { email: u.email, password: u.password },
    });
    assert.ok(!login.json().mfaRequired, "login must stop challenging once MFA is off");
    assert.ok(cookieOf(login));
  });

  dbTest("turning it off destroys the recovery codes too", async () => {
    const u = await makeUser("disablecodes");
    const { secret } = await enrol(u);
    await app.inject({
      method: "POST", url: "/api/mfa/disable", headers: { cookie: u.cookie },
      payload: { password: u.password, code: nextCode(secret) },
    });
    const left = await pool.query("SELECT 1 FROM mfa_recovery_codes WHERE user_id = $1", [u.id]);
    assert.equal(left.rowCount, 0, "stale recovery codes must not outlive the enrolment");
  });
});

describe("route authorization", () => {
  dbTest("every enrolment route requires a session", async () => {
    for (const [method, url] of [
      ["GET", "/api/mfa"],
      ["POST", "/api/mfa/setup"],
      ["POST", "/api/mfa/enable"],
      ["POST", "/api/mfa/disable"],
      ["POST", "/api/mfa/cancel"],
    ] as const) {
      const res = await app.inject({ method, url, payload: {} });
      assert.equal(res.statusCode, 401, `${method} ${url} must require authentication`);
    }
  });

  dbTest("one user cannot read another's MFA status", async () => {
    const a = await makeUser("tenanta");
    const b = await makeUser("tenantb");
    await enrol(a);
    const res = await app.inject({ method: "GET", url: "/api/mfa", headers: { cookie: b.cookie } });
    assert.equal(res.statusCode, 200);
    assert.equal(res.json().enabled, false, "status must be scoped to the calling user");
  });
});
