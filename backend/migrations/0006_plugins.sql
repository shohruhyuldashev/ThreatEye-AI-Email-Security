-- 0006_plugins
-- Installed .tap plugins + content tagging so a plugin can be cleanly removed.
-- Idempotent.

CREATE TABLE IF NOT EXISTS plugins (
    id SERIAL PRIMARY KEY,
    organization_id INTEGER NOT NULL DEFAULT 1 REFERENCES organizations(id) ON DELETE CASCADE,
    plugin_id TEXT NOT NULL,
    name TEXT NOT NULL,
    version TEXT,
    author TEXT,
    category TEXT DEFAULT 'detection',
    description TEXT,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    signed BOOLEAN DEFAULT FALSE,
    manifest_json TEXT NOT NULL,
    counts_json TEXT,
    installed_by TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (organization_id, plugin_id)
);

-- Tag detection rules with their owning plugin so uninstall is exact.
ALTER TABLE detection_rules ADD COLUMN IF NOT EXISTS plugin_id TEXT;

CREATE INDEX IF NOT EXISTS idx_plugins_org ON plugins (organization_id);
CREATE INDEX IF NOT EXISTS idx_detrules_plugin ON detection_rules (plugin_id);
