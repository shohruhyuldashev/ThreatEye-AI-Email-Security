-- 0010_sim_registry
-- Server-side registry of the phishing-simulation mail WE sent, so the watcher can
-- recognise its own simulations without any attacker-visible marker in the email.
-- An attacker cannot learn this exists (nothing is written into the email) nor
-- forge a match (the subject is LLM-random and the row expires).
CREATE TABLE IF NOT EXISTS sim_registry (
    id SERIAL PRIMARY KEY,
    organization_id INTEGER NOT NULL DEFAULT 1,
    recipient TEXT NOT NULL,
    sender TEXT,
    subject TEXT,
    fingerprint TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_sim_registry_recipient ON sim_registry (recipient);
CREATE INDEX IF NOT EXISTS idx_sim_registry_expires ON sim_registry (expires_at);
