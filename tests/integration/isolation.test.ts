/**
 * Tenant isolation.
 *
 * Nearly every security fix recorded in this repository's history is the same
 * bug in a different route: a query that forgot its project scope, an id
 * sanitized one way for the authorization check and another way for the lookup,
 * a join on a caller-supplied trace_id that isn't unique across tenants. Each
 * was found in production or in review, one at a time.
 *
 * The shape of the test is therefore deliberately blunt. Two unrelated
 * customers, each with a distinctive marker string threaded through every field
 * of their data. For every endpoint, as tenant A:
 *
 *   - asking for B's project must be refused, and
 *   - the response body must not contain B's marker anywhere.
 *
 * The second assertion is the one that matters. A route can return HTTP 200 with
 * an empty-looking payload that still carries another tenant's aggregate in a
 * sum, a name, or a groupUniqArray. Searching the raw response text for the
 * marker catches leaks through fields nobody thought to check.
 */
import { test, before, after, describe } from "node:test";
import assert from "node:assert/strict";
import { buildApp } from "../../apps/web/src/app.js";
import { closeRateLimiter } from "@argus/shared";
import { infraAvailable, makeTenant, cleanup, pool, type App, type Tenant } from "./helpers.js";

let app: App;
let A: Tenant;
let B: Tenant;
let available = false;

before(async () => {
  available = await infraAvailable();
  if (!available) return;
  app = await buildApp();
  A = await makeTenant(app, "alpha");
  B = await makeTenant(app, "beta");
});

after(async () => {
  if (available) await cleanup([A, B]);
  await pool.end().catch(() => {});
  await closeRateLimiter();
  await app?.close().catch(() => {});
});

const SKIP_REASON = "needs Postgres + ClickHouse (run `make up`, or see the CI isolation job)";

/**
 * A test that needs live databases.
 *
 * The skip decision has to be made INSIDE the test body. node:test evaluates a
 * `{ skip: ... }` option while it is collecting tests, which happens before any
 * `before()` hook has run — so a flag set in `before()` is always still false at
 * that point and every test silently skips, including on a machine where the
 * databases are up. A suite that reports "44 skipped" when it should report "44
 * passed" is worse than no suite: it is a green check mark over an untested
 * authorization boundary.
 */
function isoTest(name: string, fn: () => Promise<void>): void {
  test(name, async (t) => {
    if (!available) {
      t.skip(SKIP_REASON);
      return;
    }
    await fn();
  });
}

/** Every project-scoped read endpoint. Kept in sync with the guard() list in app.ts. */
const SCOPED_READ_ENDPOINTS = [
  "overview", "threat", "attacks", "incidents", "review",
  "sessions", "traces", "analytics", "prompts",
];

describe("cross-tenant reads", () => {
  for (const name of SCOPED_READ_ENDPOINTS) {
    isoTest(`/api/${name} refuses another tenant's project`, async () => {
      const res = await app.inject({
        method: "GET",
        url: `/api/${name}?project=${B.projectId}`,
        headers: { cookie: A.cookie },
      });
      assert.equal(res.statusCode, 403, `expected 403, got ${res.statusCode}: ${res.body.slice(0, 300)}`);
    });

    isoTest(`/api/${name} never leaks another tenant's data`, async () => {
      // Ask for A's *own* project — the legitimate request. Anything of B's in
      // the response arrived through a query that isn't scoped, which is how the
      // eval-scores leak and the trace_id join collisions happened.
      const res = await app.inject({
        method: "GET",
        url: `/api/${name}?project=${A.projectId}`,
        headers: { cookie: A.cookie },
      });
      assert.equal(res.statusCode, 200, `own project should be readable: ${res.body.slice(0, 300)}`);
      assert.ok(
        !res.body.includes(B.secret),
        `response for /api/${name} contained tenant B's marker:\n${res.body.slice(0, 600)}`,
      );
    });
  }
});

describe("cross-tenant trace access", () => {
  isoTest("cannot read another tenant's trace by id", async () => {
    const res = await app.inject({
      method: "GET",
      url: `/api/trace/${B.traceId}?project=${B.projectId}`,
      headers: { cookie: A.cookie },
    });
    assert.equal(res.statusCode, 403);
  });

  isoTest("cannot read another tenant's trace by claiming your own project", async () => {
    // The interesting attack: authorize against a project you *do* own, then
    // hand over someone else's trace id and hope the lookup ignores the scope.
    const res = await app.inject({
      method: "GET",
      url: `/api/trace/${B.traceId}?project=${A.projectId}`,
      headers: { cookie: A.cookie },
    });
    assert.equal(res.statusCode, 200);
    assert.ok(!res.body.includes(B.secret), `leaked B's trace content:\n${res.body.slice(0, 600)}`);
  });
});

describe("cross-tenant writes", () => {
  isoTest("cannot set a verdict on another tenant's security event", async () => {
    const res = await app.inject({
      method: "POST",
      url: "/api/verdict",
      headers: { cookie: A.cookie },
      payload: { eventId: B.eventId, verdict: "false_positive", project: B.projectId },
    });
    assert.equal(res.statusCode, 403);
  });

  isoTest("cannot set a verdict by claiming your own project", async () => {
    // Event ids are discoverable and the write re-inserts the row, so an
    // unscoped lookup here is a cross-tenant *mutation*, not just a read.
    const res = await app.inject({
      method: "POST",
      url: "/api/verdict",
      headers: { cookie: A.cookie },
      payload: { eventId: B.eventId, verdict: "false_positive", project: A.projectId },
    });
    assert.equal(res.statusCode, 404, "the event must not be findable under A's scope");
  });

  isoTest("cannot change another tenant's settings", async () => {
    const res = await app.inject({
      method: "PUT",
      url: "/api/settings",
      headers: { cookie: A.cookie },
      payload: { project: B.projectId, config: { sampling: { trace_sample_rate: 0 } } },
    });
    assert.equal(res.statusCode, 403);
  });

  isoTest("cannot create an API key on another tenant's project", async () => {
    const res = await app.inject({
      method: "POST",
      url: "/api/keys",
      headers: { cookie: A.cookie },
      payload: { project: B.projectId },
    });
    assert.equal(res.statusCode, 403);
  });

  isoTest("cannot list another tenant's API keys", async () => {
    const res = await app.inject({
      method: "GET",
      url: `/api/keys?project=${B.projectId}`,
      headers: { cookie: A.cookie },
    });
    assert.equal(res.statusCode, 403);
  });

  isoTest("cannot invite themselves into another tenant's org", async () => {
    const res = await app.inject({
      method: "POST",
      url: "/api/members/invite",
      headers: { cookie: A.cookie },
      payload: { project: B.projectId, email: A.email, role: "admin" },
    });
    assert.equal(res.statusCode, 403);
  });

  isoTest("cannot read another tenant's members or audit log", async () => {
    for (const url of [`/api/members?project=${B.projectId}`, `/api/audit?project=${B.projectId}`]) {
      const res = await app.inject({ method: "GET", url, headers: { cookie: A.cookie } });
      assert.equal(res.statusCode, 403, `${url} returned ${res.statusCode}`);
    }
  });
});

describe("project catalog and metadata", () => {
  isoTest("/api/projects lists only your own organizations", async () => {
    const res = await app.inject({ method: "GET", url: "/api/projects", headers: { cookie: A.cookie } });
    assert.equal(res.statusCode, 200);
    assert.ok(res.body.includes(A.projectId), "should list your own app");
    assert.ok(!res.body.includes(B.projectId), "must not list another customer's app");
  });

  isoTest("?all=1 is ignored for non-platform-admins", async () => {
    // The flag exists for the operator console. A normal user setting it by hand
    // must get their own catalog, not everyone's.
    const res = await app.inject({ method: "GET", url: "/api/projects?all=1", headers: { cookie: A.cookie } });
    assert.equal(res.statusCode, 200);
    assert.ok(!res.body.includes(B.projectId));
  });

  isoTest("cannot read another tenant's project metadata", async () => {
    const res = await app.inject({
      method: "GET",
      url: `/api/project/${B.projectId}`,
      headers: { cookie: A.cookie },
    });
    assert.equal(res.statusCode, 403);
  });

  isoTest("cannot poll another tenant's onboarding status", async () => {
    const res = await app.inject({
      method: "GET",
      url: `/api/onboarding/status/${B.projectId}`,
      headers: { cookie: A.cookie },
    });
    assert.equal(res.statusCode, 403);
  });
});

describe("platform-admin surface", () => {
  const ADMIN_ROUTES = ["/api/admin/overview", "/api/admin/users", "/api/admin/orgs", "/api/admin/audit"];
  for (const url of ADMIN_ROUTES) {
    isoTest(`${url} is refused to ordinary users`, async () => {
      const res = await app.inject({ method: "GET", url, headers: { cookie: A.cookie } });
      assert.equal(res.statusCode, 403);
    });
  }

  isoTest("an ordinary user cannot grant themselves platform admin", async () => {
    const res = await app.inject({
      method: "POST",
      url: `/api/admin/users/${A.userId}/platform-admin`,
      headers: { cookie: A.cookie },
      payload: { value: true },
    });
    assert.equal(res.statusCode, 403);
    const row = await pool.query<{ is_platform_admin: boolean }>(
      "SELECT is_platform_admin FROM users WHERE id = $1",
      [A.userId],
    );
    assert.equal(row.rows[0].is_platform_admin, false, "privilege escalation succeeded");
  });

  isoTest("an ordinary user cannot delete another tenant's company", async () => {
    const res = await app.inject({
      method: "DELETE",
      url: `/api/admin/orgs/${B.orgId}`,
      headers: { cookie: A.cookie },
    });
    assert.equal(res.statusCode, 403);
    const row = await pool.query("SELECT 1 FROM organizations WHERE id = $1", [B.orgId]);
    assert.equal(row.rowCount, 1, "tenant B's company was deleted");
  });
});

describe("unauthenticated access", () => {
  isoTest("every /api data route requires a session", async () => {
    for (const name of SCOPED_READ_ENDPOINTS) {
      const res = await app.inject({ method: "GET", url: `/api/${name}?project=${A.projectId}` });
      assert.equal(res.statusCode, 401, `/api/${name} answered ${res.statusCode} with no session`);
    }
  });

  isoTest("a garbage session cookie is not a session", async () => {
    const res = await app.inject({
      method: "GET",
      url: `/api/overview?project=${A.projectId}`,
      headers: { cookie: "argus_session=not-a-real-token" },
    });
    assert.equal(res.statusCode, 401);
  });
});

describe("project id handling", () => {
  // The authorization check and the ClickHouse query must agree, character for
  // character, about which project id they are talking about. They once used
  // different sanitizers, so a crafted id could be authorized as one project and
  // queried as another.
  const HOSTILE = [
    "' OR 1=1 --",
    "../../etc/passwd",
    "%27%20OR%201%3D1",
    "",
  ];
  for (const bad of HOSTILE) {
    isoTest(`rejects or empties hostile project id ${JSON.stringify(bad)}`, async () => {
      const res = await app.inject({
        method: "GET",
        url: `/api/overview?project=${encodeURIComponent(bad)}`,
        headers: { cookie: A.cookie },
      });
      assert.ok(
        res.statusCode === 400 || res.statusCode === 403,
        `expected 400/403, got ${res.statusCode}: ${res.body.slice(0, 300)}`,
      );
      assert.ok(!res.body.includes(A.secret) && !res.body.includes(B.secret));
    });
  }

  isoTest("a project id that sanitizes onto someone else's is still refused", async () => {
    // Append characters the sanitizer strips. If auth and query strip
    // differently, this is authorized as garbage and queried as B.
    const res = await app.inject({
      method: "GET",
      url: `/api/overview?project=${encodeURIComponent(B.projectId + "'")}`,
      headers: { cookie: A.cookie },
    });
    assert.equal(res.statusCode, 403);
  });
});
