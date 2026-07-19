-- Tenant isolation: give the two tables that had no tenant link an organization_id,
-- so their read endpoints can be scoped like every other tenant-owned table.
-- Existing rows default to the primary org (1); new rows carry the real tenant.

ALTER TABLE audit_log   ADD COLUMN IF NOT EXISTS organization_id INTEGER NOT NULL DEFAULT 1;
ALTER TABLE siem_events ADD COLUMN IF NOT EXISTS organization_id INTEGER NOT NULL DEFAULT 1;

-- Best-effort backfill of siem_events from the stored payload (org id is inside it),
-- guarded so a non-JSON payload can never fail the migration.
UPDATE siem_events
   SET organization_id = COALESCE(NULLIF(payload_json::jsonb ->> 'organization_id', '')::int, organization_id)
 WHERE payload_json ~ '^\s*\{.*\}\s*$';

CREATE INDEX IF NOT EXISTS idx_audit_org ON audit_log (organization_id);
CREATE INDEX IF NOT EXISTS idx_siem_org  ON siem_events (organization_id);
