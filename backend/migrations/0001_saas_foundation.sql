-- 0001_saas_foundation
-- Multi-tenant users + RBAC and tenant-scoping columns.
-- All statements are idempotent so re-running is safe.

CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    organization_id INTEGER NOT NULL DEFAULT 1 REFERENCES organizations(id) ON DELETE CASCADE,
    username TEXT NOT NULL UNIQUE,
    email TEXT,
    full_name TEXT,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'viewer',
    active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login_at TIMESTAMP
);

-- Tenant ownership for the core data tables.
ALTER TABLE emails      ADD COLUMN IF NOT EXISTS organization_id INTEGER NOT NULL DEFAULT 1;
ALTER TABLE simulations ADD COLUMN IF NOT EXISTS organization_id INTEGER NOT NULL DEFAULT 1;

-- Richer API-key metadata for the ingestion API.
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS last_used_at TIMESTAMP;
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS created_by TEXT;

CREATE INDEX IF NOT EXISTS idx_emails_org   ON emails (organization_id);
CREATE INDEX IF NOT EXISTS idx_users_org    ON users (organization_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_org  ON api_keys (organization_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys (key_hash);
