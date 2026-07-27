-- Argus: per-project alert channels and suppression rules.
--
-- Alerting was a single ALERT_WEBHOOK_URL environment variable shared by the
-- whole deployment: every tenant's incidents went to one endpoint, chosen by
-- whoever ran the server, and a customer could not route their own alerts
-- anywhere. `alerting.channels` existed in the settings JSON and was read by
-- nothing.
--
-- Channels are a table rather than more JSON in detection_configs because they
-- hold secrets (webhook URLs are bearer credentials — anyone with the Slack URL
-- can post as you), need per-channel delivery state, and want their own audit
-- trail.
CREATE TABLE IF NOT EXISTS alert_channels (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id    UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    kind          TEXT NOT NULL,              -- webhook | slack | pagerduty | email
    label         TEXT NOT NULL DEFAULT '',
    -- Endpoint/credential. Never returned by the API in full; the UI shows a
    -- redacted form.
    target        TEXT NOT NULL,
    -- Optional shared secret. When set, webhook deliveries carry an HMAC
    -- signature so the receiver can verify the payload really came from us —
    -- otherwise anyone who learns the URL can forge incidents into their
    -- pipeline, which is a strange thing for a security product to allow.
    signing_secret TEXT,
    min_severity  TEXT NOT NULL DEFAULT 'high',
    enabled       BOOLEAN NOT NULL DEFAULT true,
    created_by    TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Delivery health, so a channel that has been silently failing for a week
    -- is visible rather than assumed working.
    last_success_at TIMESTAMPTZ,
    last_error_at   TIMESTAMPTZ,
    last_error      TEXT,
    consecutive_failures INT NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_alert_channels_project ON alert_channels(project_id) WHERE enabled;

-- Suppression. The table has existed since 001 and nothing read it, while the
-- roadmap named false-positive noise as the top churn risk. A detector you
-- cannot quiet is a detector that gets muted wholesale.
ALTER TABLE suppression_rules ADD COLUMN IF NOT EXISTS category   TEXT;
ALTER TABLE suppression_rules ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ;
ALTER TABLE suppression_rules ADD COLUMN IF NOT EXISTS enabled    BOOLEAN NOT NULL DEFAULT true;
CREATE INDEX IF NOT EXISTS idx_suppression_active
    ON suppression_rules(project_id) WHERE enabled;
