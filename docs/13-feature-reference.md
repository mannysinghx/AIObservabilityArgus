# 13 — Feature Reference

Everything added in the platform release, where to find it, and how to use it.

Organised by audience: **Operators** run Argus, **Security teams** use it daily,
**Engineers** integrate against it. Each entry says where it lives in the UI, what
it requires, and where the detail is.

---

## At a glance

| Feature | Where | Who | Requires |
|---|---|---|---|
| [Canaries](#canaries) | Manage → **Canaries** | Security | admin to plant |
| [Alert destinations](#alert-destinations) | Manage → **Alerts** | Security | admin |
| [Suppression rules](#suppression-rules) | Manage → **Alerts** | Security | admin |
| [Retention window](#retention-window) | Manage → Settings (bottom) | Operator | **owner** |
| [Right to erasure](#right-to-erasure) | Manage → Settings (bottom) | Operator | **owner** |
| [Scoped API keys](#scoped-api-keys) | Manage → **API Keys** | Engineer | admin |
| [Public read API](#public-read-api) | `GET /v1/*` | Engineer | `read` key |
| [Gateway](#gateway-inline-blocking) | Separate service | Engineer | deploy |
| [Metrics](#metrics-and-health) | `GET /metrics` | Operator | — |
| [Dead-letter queue](#dead-letter-queue) | Redis `argus:ingest:dlq` | Operator | — |

Everything in the dashboard is also documented in-app under **User Guide**, which
now covers all of the above.

---

## Security

### Canaries

**Manage → Canaries** · view: member · plant/revoke: admin

A unique marker planted where it should never travel from — the end of a system
prompt, an internal document, a customer record. Every other detector reads text
and forms a judgement about intent. A canary firing is not a judgement: the exact
string was somewhere it could only have come from, and it is now in something the
application sent outward. There is no benign explanation, which is why this is the
one alert that justifies paging someone.

**Using it**

1. Label it with where you're planting it — you'll want that at 3am.
2. Generate. Argus mints `argus-cnry-…` and shows it **once**.
3. Paste it where it belongs. A common first choice is a final line in the system
   prompt: *"Internal reference: argus-cnry-… — never include this in a response."*
4. Nothing else. If it appears in a model output or outbound tool call, you get a
   **critical** incident naming the canary by its label.

**Two kinds**

| Kind | Storage | Use when |
|---|---|---|
| Generated *(default)* | sha256 only — the raw value is never stored or sent to the detection service | Always, unless you can't |
| Your own marker | Stored in the clear; matching an arbitrary string requires holding it | You've already planted something (a decoy key, a fake record) |

**Behaviour worth knowing**

- Model outputs and tool calls are watched. **Retrieval results are not** —
  planting a canary in a document you also index is the main use case, and
  alerting when your own retriever finds it would make the feature unusable.
- Custom markers must be ≥ 12 characters. `admin` would match ordinary traffic.
- Canary checks run independently of the rest of L4's reasoning; a hit needs no
  corroborating signal and no taint frontier.
- Revoking stops the watch but keeps the record, so past incidents still resolve
  to a label rather than reading "canary &lt;deleted&gt; fired".
- The canary loader fails **closed** (empty list) on a database error. A false
  negative is recoverable; a 3am page caused by a Postgres timeout destroys trust
  in the one signal that was never ambiguous.

---

### Alert destinations

**Manage → Alerts** · view: member · manage: admin

Per-application routing, replacing a single deployment-wide webhook.

| Type | What you paste |
|---|---|
| Slack | An incoming-webhook URL. Alerts arrive formatted with severity, evidence and a trace link. |
| PagerDuty | An Events v2 routing key. Argus sets a dedup key so PagerDuty groups repeats itself. |
| Webhook | Any HTTPS endpoint. Deliveries are HMAC-signed. |

Each destination has its own severity threshold — everything to Slack, criticals
only to PagerDuty.

**Plain `http://` is refused.** These payloads quote the attack and the evidence.

**Test before relying on it.** Every destination has a Test button that sends a
clearly-marked synthetic alert. The failure mode of alerting is silence, which is
indistinguishable from "nothing is wrong" — so the Health column also shows last
successful delivery and a consecutive-failure count.

**Verifying a webhook**

Two headers accompany each delivery:

| Header | Value |
|---|---|
| `x-argus-timestamp` | Unix seconds at send time |
| `x-argus-signature` | `v1=` + `HMAC-SHA256(secret, "<timestamp>.<raw body>")` in hex |

Recompute and compare; reject old timestamps. The timestamp is inside the signed
material specifically so a captured delivery cannot be replayed. Without this,
anyone who learns the URL can forge incidents into your pipeline.

**Dedup.** A poisoned document retrieved on every request produces a finding every
time. Argus sends the first and suppresses identical repeats for 15 minutes
(`ALERT_DEDUP_WINDOW_S`). A *more severe* finding on the same content still goes
out — escalation is news.

---

### Suppression rules

**Manage → Alerts** (lower card) · manage: admin

When a detector reliably fires on something known to be fine, silence *that thing*
rather than the detector. Suppressed findings are still recorded and still appear
in Threat Center; they stop paging.

Two things are mandatory:

- **A target** — a rule ID, a category, or a tool. A rule naming nothing would
  silence the entire application.
- **A reason.** An unexplained suppression is indistinguishable from a mistake six
  months later, and nobody removes what they don't understand.

Rules can expire (30/90 days), which is usually right: it forces a re-check rather
than letting a blind spot become permanent.

### Static assessment

**Assessments** (Security group) · view: any role · run/edit: member+

Where L1–L4 judge live traffic, this judges the application *as built* — before
an attacker supplies any input. Three tabs, meant to be used in order:
**Architecture** (describe the app once; pre-fills the rest), **Runs** (paste a
prompt, run it, browse past runs), **Findings** (everything from every run, with
open/resolved/accepted triage).

The same capabilities are available to scripts via `/api/assess/*`, and the pure
engines sit behind `/v1/assess/*` on the detection service:

- **`POST /v1/assess/prompt`** — 20 deterministic rules (`IG-PROMPT-001..020`)
  over prompt templates: instruction/data mixing, secrets in prompts, model-
  controlled authorization, direct execution of output, and so on. Every finding
  carries a transparent 5-factor risk score (versioned, recomputable from its
  stored factors), ranked mitigations from a curated catalog, OWASP LLM /
  MITRE ATLAS / NIST AI RMF references, and a mapping into the runtime
  category taxonomy so assessment and runtime findings can share storage and
  routing later.
- **`POST /v1/assess/graph`** — trust-boundary analysis over an architecture
  graph (nodes + edges): untrusted→trusted instruction flow, model output into
  interpreters, write-capable tools without human approval, cross-tenant data
  paths, retrieval without provenance.
- **`POST /v1/assess/policy`** — a fail-closed policy-as-code evaluator
  (dotted-path conditions, implicit AND; unknown fields and unknown operators
  never match).

Everything under `argus_detection/assessment/` is pure — no DB, no network, no
model calls — ported from InjectGuard with its golden tests, so the engines can
later run in the worker or gateway unchanged. `/health` reports
`assessment.prompt_rules` and `assessment.scoring_version` for deploy
verification.

**Phase 2 — tenanted storage and dashboard API.** Assessments now persist:
`POST /api/assess/prompt` (member+) runs the engine and records the run and its
findings under the caller's project; `GET /api/assessments`,
`/api/assessment/:id`, `/api/assessment-findings` read them back through the
same project guard as every other data view; `PUT`-style
`POST /api/assessment/graph` stores one architecture graph per project and
`POST /api/assessment/graph/analyze` runs the analyzer over it;
`POST /api/assessment/finding/status` records the analyst's disposition
(open/resolved/accepted), scoped by (id AND project) like `/api/verdict`.
Prompt *contents* are never stored — the assessment keeps document names,
context facts, and the engine's already-redacted evidence excerpts (Postgres
migration `013_assessments.sql` explains the reduction from InjectGuard's
schema). The web service now needs `DETECTION_URL` (+ `DETECTION_API_KEY`)
set, same as the worker. Isolation coverage:
`tests/integration/assessments.test.ts`.

**Phase 3 — the dashboard views.** The Assessments page renders all of the
above: a run form whose application-facts checkboxes are pre-filled from the
saved architecture graph, run history, a per-run breakdown (every finding with
its transparent risk rationale, factor scores, and ranked mitigations behind
`<details>`), a cross-run Findings table with inline status triage, and a
component/connection editor with a "Save & analyze" action. Everything the page
renders — evidence excerpts especially — is engine output derived from customer
prompts, so it is escaped on the way in; the CSP is the backstop, not the
control. Severity pills render from each finding's `argus_severity` (the runtime
spelling) rather than the native label, because the engine's lowest band is
`informational` and no such pill style exists.

Not yet ported from InjectGuard: policy *storage* (the evaluator is merged and
callable), controls, and report generation.

---

## Data governance

### Retention window

**Manage → Settings**, bottom card · **owner** only

How long this application's data is kept. Past the window, rows are deleted from
every table — traces, observations, security events, scores, and the raw ingest
archive.

- Saving applies **immediately**. Shortening 90 → 7 days destroys the difference
  when you press Apply, not overnight.
- `0` means keep forever — and that is literal; the raw archive holds every payload
  verbatim.
- A sweep runs hourly in the worker (`RETENTION_INTERVAL_MS`), logging what it did.
- `retention_days <= 0` is a no-op by design. Reading an unset column as "delete
  everything" would turn a misconfiguration into total data loss.

### Right to erasure

**Manage → Settings**, bottom card · **owner** only

For GDPR Art. 17 / CCPA requests. Enter the value your app sends as `userId`; every
trace for that person is deleted across all tables.

- **Check first.** The preview reports how many traces will be destroyed. A
  mistyped ID matches nothing, and "erased 0" is indistinguishable from success.
- Erasure is **synchronous** (`mutations_sync=2`) — when it reports done, the rows
  are gone, not queued.
- Recorded in the audit log with the subject ID. That entry is the evidence the
  request was honoured.

---

## Integration

### Scoped API keys

**Manage → API Keys** · admin

| Scope | Can | Lives |
|---|---|---|
| `ingest` | Send telemetry. Read nothing. | Inside your app, on every host that runs it |
| `read` | Read this application's data via `/v1` | One dashboard, one connector |

Keeping them separate matters because the ingest key is, by deployment count, the
most exposed credential you hold. If it leaks it should be able to add junk
telemetry — not download every prompt and completion it ever sent.

Existing keys were **not** granted `read` on upgrade. Keys carry a label, show
their scopes and last use, and revoke immediately rather than when a cache expires.
Argus refuses to revoke the last *ingest* key so an app can't be orphaned; read
keys have no such restriction.

### Public read API

`GET /v1/*` · `Authorization: Bearer ak_live_…` with the `read` scope

| Endpoint | Returns |
|---|---|
| `/v1/me` | The key's application and scopes — a connectivity check |
| `/v1/traces` | Traces, newest first |
| `/v1/traces/:id` | One trace in full: every span with complete input/output, plus its security events |
| `/v1/observations` | Spans; filter `traceId`, `type` |
| `/v1/security-events` | Filter `severity`, `category`, `outcome`, `verdict` |
| `/v1/summary` | Window counters, cheap enough to poll |

All lists take `limit` (max 1000), `since`, `until`, `cursor`.

**Cursor paging, not offset.** With offsets, a trace arriving between two pages
shifts everything down and the reader silently skips a record — for a security
export that is the whole failure. Walk `nextCursor` until it returns null.

**An unknown filter value returns 400**, not an empty page. A monitoring query
filtered on a typo'd severity would otherwise report "no critical events" forever
and look like good news.

The key names the application, so no endpoint takes a project parameter — there is
nothing to point at another tenant.

Full reference: [`docs/11-public-api.md`](11-public-api.md).

### Gateway (inline blocking)

Separate service (`apps/gateway`) · OpenAI-compatible

```python
client = OpenAI(
    base_url="https://your-argus-gateway/v1",
    api_key=OPENAI_API_KEY,                       # forwarded untouched, never stored
    default_headers={"x-argus-key": "ak_live_…"}, # identifies the application
)
```

Refuses a high-confidence prompt injection before the model sees it. Also provides
tracing with **no SDK change**, since every call through it emits a trace.

**It fails open.** This is the only part of Argus on your critical path. If
detection is slow, down or erroring, the request goes through unscanned. A security
tool that takes production offline on a bad day is uninstalled within the week, and
then it protects nothing.

| Setting | Default | Meaning |
|---|---|---|
| `GATEWAY_MODE` | `observe` | `observe` scores and records; `block` refuses |
| `GATEWAY_BLOCK_THRESHOLD` | `75` | Score at or above which a request is refused |
| `GATEWAY_LATENCY_BUDGET_MS` | `300` | Past this, the request proceeds. Slow = down |
| `GATEWAY_ON_FAILURE` | `open` | `closed` refuses on outage |

Anything other than the exact strings `block` / `closed` is read as `observe` /
`open` — a typo must never be what enables blocking.

**Start in observe.** Run a week, review what *would* have been blocked, then
switch.

**Scope of blocking:** only `direct_injection` and `jailbreak`, only on the user's
turn. This layer sees one message with no trace context, so it cannot judge
indirect injection, exfiltration or behavioural deviation — those are cross-span
patterns and Argus's actual speciality, judged by L4 with the whole trace. The
system prompt is never scanned; it is a list of instructions by nature.

Everything allowed is still scanned in full by the async pipeline seconds later.

**Where the threshold comes from** — measured against the labelled corpus:

| Threshold | Attacks blocked | Benign wrongly blocked |
|---:|---:|---:|
| 85 | 4/20 | 0/20 |
| **75** | **7/20** | **0/20** |
| 70 | 10/20 | 0/20 |

Every benign item scores 0.0, so the corpus alone would justify lower. 20 negatives
is thin evidence, so 75 — where two independent rules must fire — is a principled
line rather than a curve-fit. `test_quality_gate.py` fails CI if this starts
refusing benign traffic or drifts so high it blocks nothing.

Full reference: [`docs/12-gateway.md`](12-gateway.md).

---

## Operations

### Metrics and health

`GET /metrics` on **web**, **ingest** and the **worker** (`WORKER_HEALTH_PORT`,
default 3003). Prometheus text format.

| Metric | Watch for |
|---|---|
| `argus_consumer_lag{group}` | The number that catches a stalled pipeline. Growing = data is not landing |
| `argus_consumer_pending{group}` | Delivered but unacked. Persistent growth = stall |
| `argus_dlq_length` | Quarantined events. Non-zero deserves a look |
| `argus_stream_length` | Ingest backlog |
| `argus_http_requests_total`, `argus_http_duration_ms` | Per-route traffic and latency |
| `argus_ingest_events_total`, `argus_ingest_rate_limited_total` | Throughput and quota pressure |
| `gateway_blocked_total`, `gateway_scan_degraded_total` | **Degraded is the one to alert on** — it means the gateway is failing open, i.e. protecting nothing |
| `worker_dlq_total`, `worker_batch_errors_total` | Processing health |

The worker's `/health` returns **503** when a consumer group is backed up past
`WORKER_STALL_PENDING`, so a platform health check pages instead of reporting green
over a stopped pipeline.

### Dead-letter queue

Redis stream `argus:ingest:dlq`.

An event that fails `CONSUMER_MAX_DELIVERIES` times (default 5) is retried
individually to identify the actual culprit, then quarantined with its original
payload and failure reason. Its neighbours are acked and continue. The queue drains
instead of stopping.

Inspect with `XRANGE argus:ingest:dlq - +`. Each entry carries `group`, `id`,
`reason`, `event` and `at`.

---

## Hardening (no UI, but worth knowing)

| Change | Effect |
|---|---|
| Rate limiting | Login, signup, password reset (per IP **and** per email), plus a per-project ingest quota (`INGEST_RATE_LIMIT`) |
| CSP + security headers | `script-src 'self'` with no `unsafe-inline`, on every response including errors and 404s |
| Detection service auth | `DETECTION_API_KEY`. Permissive when unset, but it warns at startup and `/health` reports `auth:false` — unauthenticated is a visible state, not an assumed one |
| `ARGUS_SIGNUP_MODE` | `open` \| `invite_only` \| `closed` |
| `ARGUS_BOOTSTRAP_TOKEN` | Closes the race where the first stranger to find a fresh deployment becomes its platform admin |
| Immediate key revocation | Redis epoch, not just pub/sub — a subscriber that misses the message still sees the change |
| Session cookie `Secure` | Follows the actual scheme, so HTTP deployments can stay signed in |
| Audit coverage | Login, failed login, logout, rejected signups, canary and channel changes, erasure |
| Error handler | 5xx is logged in full and answered `{"error":"internal error"}` — error bodies are an information-disclosure channel |

---

## Defects fixed

Each was found by building or testing, not by reading.

| Defect | Impact |
|---|---|
| `content_sha256` written as `""` while the correlation query filters `!= ''` | The "recurring poisoned sources" panel could never return a row |
| Invitations activated on an **unverified** email | Signing up as `victim@company.com` joined you to their organisation |
| Malformed `?project=` reached Postgres as a UUID | HTTP 500 with the driver's error text in the body |
| Failed batches were never retried | The consumer continued with cursor `">"`, which only delivers new messages. Pending entries sat unprocessed forever — **silent data loss** |
| `deleteOrg` purged 4 of 5 tables | `raw_events` was missed; every payload a deleted customer sent stayed on disk |
| Redis connections had no close path | Any process that touched Redis could not exit cleanly |

**One finding was retracted.** The analysis flagged ReDoS in the ingest redaction
patterns. Measurement against every backtracking-bait shape showed they complete in
~0ms; the patterns were rewritten for correctness (card and phone competed for the
same digits) but that was not a vulnerability fix.

---

## Configuration index

New environment variables, all documented in `.env.example`:

**Accounts** `ARGUS_SIGNUP_MODE` · `ARGUS_BOOTSTRAP_TOKEN` ·
`REQUIRE_EMAIL_VERIFICATION` · `ARGUS_FORCE_SECURE_COOKIE`

**Detection** `DETECTION_API_KEY`

**Ingest** `INGEST_RATE_LIMIT` · `MAX_BUFFERED_SPANS`

**Retention** `ARGUS_DEFAULT_RETENTION_DAYS` · `RETENTION_INTERVAL_MS` ·
`RETENTION_ENABLED`

**Alerting** `ALERT_DEDUP_WINDOW_S` · `ALERT_TIMEOUT_MS` · `PUBLIC_URL`

**API** `READ_RATE_LIMIT`

**Operations** `WORKER_HEALTH_PORT` · `WORKER_STALL_PENDING` ·
`CONSUMER_MAX_DELIVERIES`

**Gateway** `GATEWAY_MODE` · `GATEWAY_BLOCK_THRESHOLD` ·
`GATEWAY_LATENCY_BUDGET_MS` · `GATEWAY_ON_FAILURE` · `GATEWAY_UPSTREAM` ·
`GATEWAY_PORT`

### Migrations

`010_canaries` · `011_key_scopes` · `012_alert_channels` — idempotent, applied by
`node scripts/migrate.mjs` on deploy. `011` grants no existing key the `read`
scope: silently widening every key in every deployment during an upgrade would be
the opposite of the point.

---

## Verification

| Suite | Count | Command |
|---|---|---|
| Unit | 35 | `npm test` |
| Integration | 123 | `npm run test:isolation` *(needs `make up`)* |
| Detection | 43 | `cd services/detection && pytest -q` |

Integration tests run against real Postgres, ClickHouse and Redis, plus a live
detection service and real HTTP receivers. CI runs all three on every PR.

The tenant-isolation suite drives the real HTTP surface as a signed-in user of the
wrong tenant, asserting both that access is refused *and* that no response
containing the other tenant's marker string is ever returned.
