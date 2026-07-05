-- 0004_attachments_reports
-- Attachment verdicts, email source tagging, and the user-reported-phishing intake.
-- Idempotent.

ALTER TABLE emails ADD COLUMN IF NOT EXISTS source TEXT DEFAULT 'watcher';

ALTER TABLE attachments ADD COLUMN IF NOT EXISTS sha256 TEXT;
ALTER TABLE attachments ADD COLUMN IF NOT EXISTS verdict TEXT DEFAULT 'clean';

CREATE TABLE IF NOT EXISTS phishing_reports (
    id SERIAL PRIMARY KEY,
    organization_id INTEGER NOT NULL DEFAULT 1 REFERENCES organizations(id) ON DELETE CASCADE,
    email_id INTEGER REFERENCES emails(id) ON DELETE SET NULL,
    reporter TEXT,
    notes TEXT,
    verdict TEXT,
    risk_score INTEGER DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'New',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_emails_source ON emails (source);
CREATE INDEX IF NOT EXISTS idx_reports_org ON phishing_reports (organization_id);
CREATE INDEX IF NOT EXISTS idx_reports_email ON phishing_reports (email_id);
