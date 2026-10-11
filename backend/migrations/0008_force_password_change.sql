-- 0008_force_password_change
-- Force a password change on first login so the shipped admin/admin default
-- cannot survive into a running deployment. The seed sets this TRUE for the
-- default admin when it falls back to the 'admin' password (see seed_saas_defaults).
-- Idempotent.

ALTER TABLE users ADD COLUMN IF NOT EXISTS must_change_password BOOLEAN NOT NULL DEFAULT FALSE;
