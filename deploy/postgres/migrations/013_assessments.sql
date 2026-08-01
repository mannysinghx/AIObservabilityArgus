-- Argus: static assessment storage (Phase 2 of the InjectGuard merge).
--
-- Phase 1 put the assessment engines (prompt scanner, graph analyzer, risk,
-- mitigations) behind /v1/assess/* on the detection service — pure functions,
-- nothing stored. These tables give assessments a tenanted home so a run is a
-- record ("what did we find, when, against what facts") rather than a response
-- that evaporates. InjectGuard modeled this across ~15 tables (applications,
-- components, trust boundaries, campaigns, executions, evidence, risk_scores);
-- most of that structure existed to serve features Argus already has or that
-- died unused, so this is the deliberate reduction: an application IS an Argus
-- project, a graph is one JSONB document, and a finding carries its risk
-- breakdown and mitigation ranking inline — they are immutable computation
-- results keyed by scoring_version, not rows anyone edits.
--
-- Every table carries project_id and every query in apps/web/src/assessments.ts
-- keys on it directly — the publicRoutes.ts position ("the key names the
-- project; there is no parameter to check") adapted to session routes: the
-- WHERE clause names the project, so an unscoped id lookup has no code path.

CREATE TABLE IF NOT EXISTS assessment_graphs (
    -- One architecture graph per project, replace-on-write (the InjectGuard
    -- PUT-graph semantics). History adds nothing until something consumes it,
    -- and the graph's future source of truth is observed traces anyway (Phase 4).
    project_id  UUID PRIMARY KEY REFERENCES projects(id) ON DELETE CASCADE,
    nodes       JSONB NOT NULL DEFAULT '[]',
    edges       JSONB NOT NULL DEFAULT '[]',
    updated_by  TEXT,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS assessments (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id      UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    -- 'prompt' (documents scanned) or 'graph' (stored graph analyzed). One
    -- column, not a state machine: runs are synchronous — the engine is 20
    -- regex-class rules over a page of text, so "queued/running" states would
    -- describe a queue that does not exist.
    kind            TEXT NOT NULL DEFAULT 'prompt',
    -- The deterministic inputs, kept verbatim so any score is reproducible:
    -- context facts for prompt runs; the analyzed graph for graph runs.
    context         JSONB NOT NULL DEFAULT '{}',
    -- Document names + kinds only — contents are NOT stored. Prompts are the
    -- customer's IP and often carry the very secrets the scanner flags; the
    -- findings keep redacted evidence excerpts, which is what review needs.
    documents       JSONB NOT NULL DEFAULT '[]',
    finding_count   INT  NOT NULL DEFAULT 0,
    max_severity    TEXT,                          -- null when the run was clean
    overall_risk    INT  NOT NULL DEFAULT 0,       -- max finding final_score
    scoring_version TEXT NOT NULL DEFAULT '',
    created_by      TEXT,                          -- user id; audit_log has the rest
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_assessments_project
    ON assessments(project_id, created_at DESC);

CREATE TABLE IF NOT EXISTS assessment_findings (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    assessment_id   UUID NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
    -- Denormalized on purpose: findings are queried by project directly (the
    -- Findings view, cross-assessment rollups), and a scope that requires a
    -- join through assessments is a scope someone will eventually forget.
    project_id      UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    document_index  INT  NOT NULL DEFAULT 0,
    document_name   TEXT NOT NULL DEFAULT '',
    rule_id         TEXT NOT NULL,                 -- IG-PROMPT-### or a graph rule
    title           TEXT NOT NULL DEFAULT '',
    category        TEXT NOT NULL DEFAULT '',      -- native assessment category
    severity        TEXT NOT NULL DEFAULT '',      -- native label (informational..critical)
    confidence      TEXT NOT NULL DEFAULT '',
    explanation     TEXT NOT NULL DEFAULT '',
    affected_lines  INT[] NOT NULL DEFAULT '{}',
    evidence        TEXT NOT NULL DEFAULT '',      -- already secret-redacted by the engine
    recommendation  TEXT NOT NULL DEFAULT '',
    frameworks      JSONB NOT NULL DEFAULT '[]',   -- OWASP-LLM / MITRE-ATLAS / NIST refs
    -- The runtime-taxonomy bridge (may be null: hygiene findings have no attack
    -- class). What lets these rows sit next to security_events in dashboards.
    argus_category  TEXT,
    argus_severity  TEXT NOT NULL DEFAULT '',
    risk            JSONB NOT NULL DEFAULT '{}',   -- full transparent breakdown
    mitigations     JSONB NOT NULL DEFAULT '[]',   -- ranked recommendations
    -- The one mutable column: the analyst's disposition, mirroring the
    -- security_events verdict flow. open | resolved | accepted.
    analyst_status  TEXT NOT NULL DEFAULT 'open',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_assessment_findings_project
    ON assessment_findings(project_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_assessment_findings_assessment
    ON assessment_findings(assessment_id);
