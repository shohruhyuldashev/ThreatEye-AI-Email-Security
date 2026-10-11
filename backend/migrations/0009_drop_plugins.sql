-- 0009_drop_plugins
-- The .tap plugin feature was removed. Drop its table. Content that plugins had
-- written into detection_rules / intel_indicators / playbooks stays (it is plain
-- detection data); only the plugin registry and its management surface are gone.
-- The detection_rules.plugin_id column is left in place (harmless metadata).
-- Idempotent.

DROP TABLE IF EXISTS plugins;
