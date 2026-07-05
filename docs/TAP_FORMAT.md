# ThreatEye Analysis Plugin — the `.tap` format

A **`.tap`** file is how you extend ThreatEye's detection without touching the code.
It is a single **JSON document** (extension `.tap`) that bundles *declarative*
detection content. A plugin contains **no executable code** — only data the engine
already knows how to run — so installing a third-party plugin can never run arbitrary
code on the server. That's the whole point: safe, shareable detection packs.

Upload one from **Settings → Plugins** (or `POST /api/plugins/upload`, admin only).

## Structure

```json
{
  "tap_version": "1.0",
  "plugin": {
    "id": "emotet-pack",            // slug: [a-z0-9._-], 2–64 chars (unique per tenant)
    "name": "Emotet Detection Pack",
    "version": "2024.10",
    "author": "ThreatEye Community",
    "description": "Known Emotet infrastructure + a delivery rule.",
    "category": "detection"          // detection | intel | enrichment | response | bundle
  },

  "detection_rules": [
    {
      "rule_id": "emotet_delivery",
      "name": "Emotet malware delivery",
      "description": "High-scoring malware/attachment email.",
      "severity": "High",            // Low | Medium | High | Critical
      "attack_technique": "T1566.001",
      "attack_tactic": "Initial Access",
      "conditions": {                // only these keys are allowed (no code / no eval):
        "min_score": 60,             //   min_score, threat_type_contains,
        "threat_type_contains": "Malware"  //   feature_true, signal_contains
      }
    }
  ],

  "intel_indicators": [
    { "type": "domain", "value": "badmailer.top", "verdict": "block", "confidence": 90, "description": "Emotet C2" },
    { "type": "sha256", "value": "aa..ff", "verdict": "block" }
    // type ∈ url|domain|ip|email|sha256|md5|filename ; verdict ∈ block|allow|suspicious
  ],

  "playbooks": [
    { "name": "Emotet response", "trigger_action": "quarantine",
      "steps": [ { "type": "timeline", "message": "Emotet playbook executed" } ] }
  ],

  "signature": null                  // optional HMAC-SHA256 hex (see Integrity)
}
```

At least one of `detection_rules` / `intel_indicators` / `playbooks` is required.

## What happens on install

- **Detection rules** are added to the live rule engine (tagged with the plugin id,
  their `rule_id` namespaced as `plug:<plugin>:<rule_id>`), so they immediately affect
  scoring and ATT&CK coverage.
- **Intel indicators** are merged into the tenant blocklist/allowlist (`source =
  plugin:<id>`) and enforced by the detector on the next email.
- **Playbooks** are registered for their trigger action.
- Re-uploading the same `plugin.id` **replaces** the previous version. Removing the
  plugin deletes exactly the content it added.

## Integrity (optional)

If an operator sets a `plugin_signing_key` in Settings, a plugin whose `signature`
is a valid `HMAC-SHA256(key, canonical_content)` is marked **trusted**; unsigned
plugins still install but are flagged **unverified**. Canonical content = the compact,
key-sorted JSON of `tap_version`+`plugin`+`detection_rules`+`intel_indicators`+`playbooks`.

## Safety model

- Declarative only — no Python/JS, no shell, no network callbacks.
- Rule conditions are restricted to a fixed allow-list of keys.
- Admin-only upload, 2 MB size cap, strict schema validation.
- Per-tenant isolation; uninstall is exact and reversible.
