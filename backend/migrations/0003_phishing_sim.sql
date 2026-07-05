-- 0003_phishing_sim
-- Employee roster (CSV-uploaded targets) + launched-campaign registry for the
-- AI-automated / manual GoPhish phishing-simulation feature. Idempotent.

CREATE TABLE IF NOT EXISTS sim_targets (
    id SERIAL PRIMARY KEY,
    organization_id INTEGER NOT NULL DEFAULT 1 REFERENCES organizations(id) ON DELETE CASCADE,
    email TEXT NOT NULL,
    first_name TEXT DEFAULT '',
    last_name TEXT DEFAULT '',
    department TEXT DEFAULT 'General',
    position TEXT DEFAULT '',
    active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (organization_id, email)
);

CREATE TABLE IF NOT EXISTS sim_campaigns (
    id SERIAL PRIMARY KEY,
    organization_id INTEGER NOT NULL DEFAULT 1 REFERENCES organizations(id) ON DELETE CASCADE,
    gophish_campaign_id INTEGER,
    name TEXT NOT NULL,
    mode TEXT NOT NULL DEFAULT 'AI',           -- AI | Manual
    theme TEXT,
    status TEXT NOT NULL DEFAULT 'Launched',
    target_count INTEGER DEFAULT 0,
    created_by TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_sim_targets_org ON sim_targets (organization_id);
CREATE INDEX IF NOT EXISTS idx_sim_targets_dept ON sim_targets (department);
CREATE INDEX IF NOT EXISTS idx_sim_campaigns_org ON sim_campaigns (organization_id);
CREATE INDEX IF NOT EXISTS idx_sim_campaigns_gpid ON sim_campaigns (gophish_campaign_id);
