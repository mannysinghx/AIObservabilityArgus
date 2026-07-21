-- Argus: activate per-application settings. The detection_configs.config JSONB
-- already held layer toggles + alert severity; this backfills the new top-level
-- keys (sampling, redaction) into existing rows so every project has a complete
-- config the runtime can read.
--
-- `defaults || config` shallow-merges with the EXISTING config winning: any key
-- already present is kept untouched; only the missing top-level keys are added.
-- New projects get the full shape from the app (onboarding), so this only heals
-- rows created before this migration. Idempotent — re-running is a no-op.

UPDATE detection_configs
SET config = '{"sampling":{"trace_sample_rate":1},"redaction":{"mode":"off"}}'::jsonb || config
WHERE NOT (config ? 'sampling') OR NOT (config ? 'redaction');
