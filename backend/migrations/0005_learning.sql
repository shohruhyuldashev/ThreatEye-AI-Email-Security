-- 0005_learning
-- Adaptive reputation learned from analyst verdicts (the feedback loop). Idempotent.

CREATE TABLE IF NOT EXISTS reputation (
    id SERIAL PRIMARY KEY,
    organization_id INTEGER NOT NULL DEFAULT 1 REFERENCES organizations(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,                 -- sender_domain | sender_addr | url_domain
    value TEXT NOT NULL,
    score INTEGER NOT NULL DEFAULT 0,   -- [-100, 100]: + leans malicious, - leans benign
    confirmed_count INTEGER DEFAULT 0,
    safe_count INTEGER DEFAULT 0,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (organization_id, kind, value)
);

CREATE INDEX IF NOT EXISTS idx_reputation_lookup ON reputation (organization_id, value);
