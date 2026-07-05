-- 0002_soc_blue_team
-- Threat-intel blocklist, case SLA fields, ATT&CK rule tagging, remediation log.
-- Idempotent.

-- Threat intelligence indicators (blocklist / allowlist / watchlist), per tenant.
CREATE TABLE IF NOT EXISTS intel_indicators (
    id SERIAL PRIMARY KEY,
    organization_id INTEGER NOT NULL DEFAULT 1 REFERENCES organizations(id) ON DELETE CASCADE,
    type TEXT NOT NULL,                 -- url | domain | ip | email | sha256 | md5 | ...
    value TEXT NOT NULL,
    verdict TEXT NOT NULL DEFAULT 'block',   -- block | allow | suspicious
    source TEXT DEFAULT 'manual',
    description TEXT,
    confidence INTEGER DEFAULT 80,
    hits INTEGER DEFAULT 0,
    expires_at TIMESTAMP,
    created_by TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (organization_id, type, value)
);

-- Remediation / response action audit trail.
CREATE TABLE IF NOT EXISTS remediation_actions (
    id SERIAL PRIMARY KEY,
    organization_id INTEGER NOT NULL DEFAULT 1 REFERENCES organizations(id) ON DELETE CASCADE,
    email_id INTEGER REFERENCES emails(id) ON DELETE SET NULL,
    action_type TEXT NOT NULL,          -- notify | ticket | clawback | block_ioc
    target TEXT,
    status TEXT NOT NULL DEFAULT 'recorded',  -- sent | recorded | skipped | failed
    detail TEXT,
    created_by TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Case SLA tracking for MTTD / MTTR.
ALTER TABLE cases ADD COLUMN IF NOT EXISTS sla_minutes INTEGER;
ALTER TABLE cases ADD COLUMN IF NOT EXISTS due_at TIMESTAMP;
ALTER TABLE cases ADD COLUMN IF NOT EXISTS first_response_at TIMESTAMP;
ALTER TABLE cases ADD COLUMN IF NOT EXISTS resolved_at TIMESTAMP;

-- ATT&CK tagging for detection rules (coverage dashboard).
ALTER TABLE detection_rules ADD COLUMN IF NOT EXISTS attack_technique TEXT;
ALTER TABLE detection_rules ADD COLUMN IF NOT EXISTS attack_tactic TEXT;

CREATE INDEX IF NOT EXISTS idx_intel_org_value ON intel_indicators (organization_id, value);
CREATE INDEX IF NOT EXISTS idx_intel_verdict ON intel_indicators (verdict);
CREATE INDEX IF NOT EXISTS idx_remediation_email ON remediation_actions (email_id);
CREATE INDEX IF NOT EXISTS idx_remediation_org ON remediation_actions (organization_id);
CREATE INDEX IF NOT EXISTS idx_cases_status ON cases (status);
CREATE INDEX IF NOT EXISTS idx_cases_due ON cases (due_at);
