-- Argus: platform administrator (super-admin). A platform admin sees and manages
-- every organization, user, and project — the operator layer above tenant roles.
-- The first account to sign up is made a platform admin automatically.

ALTER TABLE users ADD COLUMN IF NOT EXISTS is_platform_admin BOOLEAN NOT NULL DEFAULT false;
