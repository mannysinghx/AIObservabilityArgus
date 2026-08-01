# 14 — Merged Features (InjectGuard → Argus)

**What this document is for:** Argus absorbed a second product, InjectGuard — an
AI security *assessment and governance* platform. This is the map of what came
across, where each piece lives now, how to reach it, and what deliberately did
not come. If you are looking for a capability and can't find it in the UI, look
here first — a few merged pieces (policies, controls, reports) are still
API-only or not yet ported.

**Status:** Phases 1–3 shipped. The assessment loop is usable in the dashboard
under **Assessments**; Phase 4 (synthesis) is next.

| Phase | What | Commit | State |
|---|---|---|---|
| 1 | Assessment engines + `/v1/assess/*` | `371ce4c` | ✅ shipped |
| 2 | Tenanted storage + `/api/assess*` | `731b0ab` | ✅ shipped |
| 3 | Dashboard UI — Assessments (Runs / Findings / Architecture) | see `git log` | ✅ shipped |
| 4 | Synthesis: trace-derived graphs, runtime→risk feedback, policy-driven blocking | — | planned |
| 5 | Decommission the standalone InjectGuard deployment | — | planned |

---

## Why the two products merged

They answer the two halves of the same question and barely overlapped:

- **Argus (runtime)** — "is my AI app being attacked *right now*?" Traces,
  L1–L4 detection, canaries, alerts, inline blocking.
- **InjectGuard (static)** — "is my AI app *built* safely, and can I prove it?"
  Prompt scanning, architecture analysis, risk scoring, mitigations, compliance
  framework mapping.

Argus hosts the merged product because its platform layer (tenancy, ingestion,
keys, alerting) was the harder half to rebuild, and because assessment wants
trace data far more than traces want assessment data. One consequence worth
internalizing: **an InjectGuard "application" is an Argus project.** There is no
separate app registry — you assess the same project you observe.

---

## The merged feature map

Everything below is live in the codebase today.

### 1. Prompt scanner — 20 deterministic rules

Finds unsafe patterns in prompt templates *before* deployment: instruction/data
mixing, secrets in prompts, model-controlled authorization, direct execution of
model output, missing delimiters, tool-definition injection, and more.

| | |
|---|---|
| **Code** | [`services/detection/argus_detection/assessment/scanner/`](../services/detection/argus_detection/assessment/scanner/) — `rules.py` (the 20 rules), `engine.py`, `types.py` |
| **Rule IDs** | `IG-PROMPT-001` … `IG-PROMPT-020` — **stable identifiers**, never renumber them; storage and the taxonomy map key on them |
| **Engine API** | `POST /v1/assess/prompt` (detection service) |
| **Dashboard API** | `POST /api/assess/prompt` (member+) |
| **UI** | Assessments → Runs tab |
| **Tests** | [`services/detection/tests/test_assessment_scanner.py`](../services/detection/tests/test_assessment_scanner.py) |

Rules are not regex-only: six are structural/context-aware classes that consult
architecture facts (e.g. `IG-PROMPT-012` fires when the app has write-capable
tools and no human approval, regardless of prompt wording). Evidence excerpts
are secret-redacted at extraction.

### 2. Transparent risk scoring

Five factors (likelihood, impact, exposure, control weakness, confidence),
fixed weights, a stored rationale string, and a version stamp — so any score is
reproducible and recomputable, and "why did this change?" is always answerable.

| | |
|---|---|
| **Code** | [`assessment/risk.py`](../services/detection/argus_detection/assessment/risk.py) — `compute_risk`, `factors_from_signal`, `severity_for` |
| **Version** | `SCORING_VERSION = "1.0.0"`, stored on every run and finding |
| **Where it surfaces** | the `risk` object on every assessment finding; `overall_risk` on the assessment |
| **Tests** | [`test_assessment_risk.py`](../services/detection/tests/test_assessment_risk.py) |

Weights sum to 0.95; confidence is a separate ±5 adjustment rather than a base
weight. Severity bands: ≥90 critical, ≥70 high, ≥40 medium, ≥15 low.

### 3. Architecture graph analysis

Models the app as nodes (user, model, tool, interpreter, memory, retrieval) and
edges, then derives risk from *topology*: untrusted→trusted instruction flow,
model output into an interpreter, write-capable tools without approval,
cross-tenant data paths, untrusted content into memory, retrieval without
provenance.

| | |
|---|---|
| **Code** | [`assessment/graph.py`](../services/detection/argus_detection/assessment/graph.py) — `GraphNode`, `GraphEdge`, `analyze_graph` (7 insight rules) |
| **Engine API** | `POST /v1/assess/graph` |
| **Dashboard API** | `POST /api/assessment/graph` (save), `POST /api/assessment/graph/analyze` (run), `GET /api/assessment-graph` (read) |
| **Storage** | one graph per project, replace-on-write (`assessment_graphs`) |
| **UI** | Assessments → Architecture tab (editor + "Save & analyze") |
| **Tests** | [`test_assessment_graph.py`](../services/detection/tests/test_assessment_graph.py) |

InjectGuard read this graph from ORM rows; here it is plain dataclasses, which
is what makes Phase 4 possible — building the graph automatically from observed
traces instead of asking a human to draw it.

### 4. Mitigation catalog + architecture-aware ranking

Turns "you have a problem" into a ranked, justified "do this first." Twelve
curated mitigations, scored against the finding category *and* application facts
(public exposure, write tools, sensitive data, business criticality), each with
implementation guidance and a validation procedure.

| | |
|---|---|
| **Code** | [`assessment/mitigations.py`](../services/detection/argus_detection/assessment/mitigations.py) — `CATALOG`, `rank_mitigations`, `AppFacts` |
| **Where it surfaces** | the `mitigations` array on each finding (top 3 by default; `top_mitigations` controls it) |
| **Invariant** | every category the scanner can emit must have ≥1 applicable mitigation — enforced by a test |

### 5. Deterministic policy engine

Policy-as-code with dotted-path conditions and implicit AND. **Fails closed**:
unknown fields and unknown operators never match, so a typo can't silently
widen a policy. No LLM is ever consulted.

| | |
|---|---|
| **Code** | [`assessment/policy.py`](../services/detection/argus_detection/assessment/policy.py) — `evaluate_conditions`, `evaluate_policy` |
| **Engine API** | `POST /v1/assess/policy` |
| **Operators** | `exists`, `in`, `gte`, `lte`, `gt`, `lt`, `matches`, plus scalar equality |
| **UI / storage** | not yet — the evaluator merged, policy *storage* is Phase 2b/3 |
| **Tests** | [`test_assessment_policy.py`](../services/detection/tests/test_assessment_policy.py) |

### 6. Compliance framework registry

OWASP LLM Top 10 (2025), a MITRE ATLAS subset, NIST AI RMF functions, and a NIST
GenAI Profile subset — data-driven, so it extends without code changes. Every
scanner rule carries framework references, which is what turns a detection into
something a compliance audit can consume.

| | |
|---|---|
| **Code** | [`assessment/frameworks.py`](../services/detection/argus_detection/assessment/frameworks.py) |
| **Where it surfaces** | the `frameworks` array on each finding, stored per finding |

### 7. Taxonomy bridge (new — built for the merge)

The one component that did not exist in either product. InjectGuard categorizes
*weaknesses* ("how is this built unsafely"); Argus categorizes *attack events*
("what did this hostile input do"). This maps between them so assessment
findings can share dashboards, storage, and alert routing with runtime findings.

| | |
|---|---|
| **Code** | [`assessment/taxonomy.py`](../services/detection/argus_detection/assessment/taxonomy.py) |
| **Where it surfaces** | `argus_category` + `argus_severity` on every finding and graph insight |
| **Deliberate null** | `prompt-quality` maps to `None` — hygiene findings have no attack class, and callers must skip them rather than invent one |
| **Tests** | [`test_assessment_taxonomy.py`](../services/detection/tests/test_assessment_taxonomy.py) — tripwires that fail if a new rule is added without extending the map |

### 8. Secret redaction for evidence

Credential-shape scrubbing (API keys, tokens, JWTs, private keys, password
assignments) applied before any assessment evidence leaves the engine.

| | |
|---|---|
| **Code** | [`assessment/redaction.py`](../services/detection/argus_detection/assessment/redaction.py) |

Note it deliberately targets *credentials*, not PII: ingest-side redaction
([`packages/shared/src/redact.ts`](../packages/shared/src/redact.ts)) owns PII
masking, and an evidence line must keep enough prompt text to stay reviewable.

---

## Where the data lives

Migration [`deploy/postgres/migrations/013_assessments.sql`](../deploy/postgres/migrations/013_assessments.sql)
— three tables, down from InjectGuard's ~15:

| Table | Holds |
|---|---|
| `assessment_graphs` | one architecture graph per project, replace-on-write |
| `assessments` | one row per run: kind, context facts, document *names*, counts, max severity, overall risk, scoring version |
| `assessment_findings` | one row per finding: rule, category, severity, evidence, frameworks, taxonomy bridge, full risk breakdown, ranked mitigations, analyst status |

**Prompt contents are never stored.** The assessment keeps document names/kinds,
the deterministic context, and redacted evidence excerpts. Prompts are customer
IP that frequently contains the very secrets the scanner exists to flag —
retaining them would make Argus the disclosure.

Storage and tenancy live in [`apps/web/src/assessments.ts`](../apps/web/src/assessments.ts).
Every query names the project in its `WHERE` clause, and detail lookups are
scoped by `(id AND project_id)` — never id alone, because the ACL validates the
*claimed* project. Isolation is pinned by
[`tests/integration/assessments.test.ts`](../tests/integration/assessments.test.ts).

---

## API quick reference

**Detection service** (internal; `Authorization: Bearer $DETECTION_API_KEY` when configured):

```
POST /v1/assess/prompt     scan documents → findings + risk + mitigations
POST /v1/assess/graph      analyze an architecture graph → insights
POST /v1/assess/policy     evaluate one policy against a context
GET  /health               includes assessment.prompt_rules + scoring_version
```

**Dashboard** (session auth, project-scoped):

```
GET  /api/assessments                    runs for a project
GET  /api/assessment/:id                 one run + its findings
GET  /api/assessment-findings            findings across runs
GET  /api/assessment-graph               the stored graph
POST /api/assess/prompt                  run a prompt assessment      (member+)
POST /api/assessment/graph               save the graph               (member+)
POST /api/assessment/graph/analyze       analyze the stored graph     (member+)
POST /api/assessment/finding/status      open | resolved | accepted   (member+)
```

Requests are capped (50 documents × 100k chars, 200 graph items) so an open
engine can't become a free CPU oracle through the dashboard.

**Configuration:** the web service now needs `DETECTION_URL` and
`DETECTION_API_KEY`, the same values the worker uses. Without them,
`/api/assess/*` returns `503 assessment engine unavailable`.

---

## What deliberately did NOT merge

**Dropped — Argus already has a better version:**

| InjectGuard had | Argus uses instead |
|---|---|
| JWT auth, 30-min access tokens | server-side sessions ([`apps/web/src/auth.ts`](../apps/web/src/auth.ts)) |
| Its own orgs/workspaces/memberships | Argus orgs → projects → memberships |
| Hardcoded RBAC dict + vestigial role tables | `roleGate()` + `ROLE_RANK` |
| Alembic (`create_all`-based, no real upgrade path) | numbered idempotent SQL in `deploy/postgres/migrations/` |
| Next.js app shell, org switcher, dashboard chrome | the existing dashboard |
| Celery + Redis job scaffold | assessments run synchronously; the worker owns async work |

**Dropped — dead on arrival:** `test_cases`, `test_campaigns`, `test_executions`
(zero references in InjectGuard), and the active-testing runner, which was M6's
headline but was wired to nothing — the `authorized_endpoint` assessment type
was accepted, authorized, and then produced no findings.

**Not merged yet — planned:**

| Feature | Where it still lives | Plan |
|---|---|---|
| Controls + evidence, coverage view | `injectguard/apps/api/injectguard_api/services/controls.py` | Phase 2b/3 |
| Policy *storage*, scope inheritance, exceptions | `services/policies.py` | Phase 2b/3 (the evaluator already merged) |
| Reports — executive/technical/governance, PDF/MD/CSV | `services/reports.py`, `reports/pdf.py` | Phase 3 |
| Hash-chained tamper-evident audit + verify endpoint | `services/audit.py` | after fixing its ordering/concurrency fork |
| Browser Guard extension + telemetry ingest | `injectguard/apps/extension/` | Phase 5 — kept as a free-tool distribution channel, repointed at Argus ingest |

The standalone InjectGuard deployment (Railway project `injectguard-prod`) keeps
running untouched until Phase 5. Nothing in this merge has changed it.

---

## Verifying a deployment

```bash
# The engine is live and carries all 20 rules:
curl -s $DETECTION_URL/health | jq .assessment
# → { "prompt_rules": 20, "scoring_version": "1.0.0" }

# Storage exists:
psql $DATABASE_URL -c "\dt assessment*"

# Full engine suite (95 tests incl. the L1 quality gate):
cd services/detection && pytest -q

# Tenant isolation for the assessment routes (needs Postgres + ClickHouse):
npm run test:isolation
```

---

## Related documents

- [04 — Security Detection Engine](04-security-detection-engine.md) — the runtime L1–L4 pipeline these features sit alongside
- [13 — Feature Reference](13-feature-reference.md) — every feature and where to find it in the UI
- [05 — Data Model](05-data-model.md) — the ClickHouse/Postgres schemas
