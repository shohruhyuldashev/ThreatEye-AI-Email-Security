"""
ThreatEye plugin engine — the `.tap` (ThreatEye Analysis Plugin) format.

A `.tap` file is a JSON document that bundles **declarative** detection content —
detection rules, threat-intel indicators, and SOAR playbooks. It contains NO
executable code by design: a plugin can only add data the engine already knows how
to run, so installing a third-party plugin can't run arbitrary code on the server
(the key supply-chain safety property for a security product).

Optional integrity: a `.tap` may carry an HMAC signature over its content; when a
`plugin_signing_key` setting is configured, signed plugins are verified and marked
trusted, unsigned ones are accepted but flagged unverified.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
from typing import Any

from db import get_db_connection

TAP_VERSION = "1.0"
VALID_CATEGORIES = {"detection", "intel", "enrichment", "response", "bundle"}
# Condition keys the rule engine understands — anything else is rejected (no eval).
ALLOWED_RULE_CONDITIONS = {"min_score", "threat_type_contains", "feature_true", "signal_contains"}
ALLOWED_INTEL_TYPES = {"url", "domain", "ip", "email", "sha256", "md5", "filename"}
ALLOWED_VERDICTS = {"block", "allow", "suspicious"}
_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{1,63}$")


class PluginError(Exception):
    pass


# --------------------------------------------------------------------------- validation
def _canonical_content(data: dict) -> bytes:
    """Bytes signed/verified: the content sections, excluding the signature itself."""
    payload = {k: data.get(k) for k in ("tap_version", "plugin", "detection_rules", "intel_indicators", "playbooks")}
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def validate_tap(data: dict) -> dict:
    """Validate a parsed .tap document, returning a normalised copy. Raises PluginError."""
    if not isinstance(data, dict):
        raise PluginError("Plugin must be a JSON object")
    if str(data.get("tap_version")) != TAP_VERSION:
        raise PluginError(f"Unsupported tap_version (expected {TAP_VERSION})")

    meta = data.get("plugin") or {}
    pid = str(meta.get("id", "")).strip().lower()
    if not _ID_RE.match(pid):
        raise PluginError("plugin.id must be a slug: [a-z0-9._-], 2-64 chars")
    if not str(meta.get("name", "")).strip():
        raise PluginError("plugin.name is required")
    category = str(meta.get("category", "detection")).lower()
    if category not in VALID_CATEGORIES:
        raise PluginError(f"plugin.category must be one of {sorted(VALID_CATEGORIES)}")

    rules = data.get("detection_rules") or []
    intel = data.get("intel_indicators") or []
    playbooks = data.get("playbooks") or []
    if not (rules or intel or playbooks):
        raise PluginError("Plugin has no content (need detection_rules, intel_indicators, or playbooks)")

    for r in rules:
        if not str(r.get("rule_id", "")).strip() or not str(r.get("name", "")).strip():
            raise PluginError("each detection rule needs rule_id and name")
        conds = r.get("conditions") or {}
        bad = set(conds) - ALLOWED_RULE_CONDITIONS
        if bad:
            raise PluginError(f"rule '{r.get('rule_id')}' has unsupported conditions: {sorted(bad)}")

    for i in intel:
        if i.get("type") not in ALLOWED_INTEL_TYPES:
            raise PluginError(f"intel type must be one of {sorted(ALLOWED_INTEL_TYPES)}")
        if not str(i.get("value", "")).strip():
            raise PluginError("each intel indicator needs a value")
        if (i.get("verdict") or "block") not in ALLOWED_VERDICTS:
            raise PluginError(f"intel verdict must be one of {sorted(ALLOWED_VERDICTS)}")

    return {
        "tap_version": TAP_VERSION,
        "plugin": {
            "id": pid,
            "name": str(meta["name"]).strip(),
            "version": str(meta.get("version", "1.0")),
            "author": str(meta.get("author", "unknown")),
            "category": category,
            "description": str(meta.get("description", "")),
        },
        "detection_rules": rules,
        "intel_indicators": intel,
        "playbooks": playbooks,
        "signature": data.get("signature"),
    }


def parse_tap(raw: bytes | str) -> dict:
    try:
        data = json.loads(raw)
    except Exception as e:
        raise PluginError(f"Invalid .tap JSON: {e}")
    return validate_tap(data)


def _signing_key() -> str:
    try:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT value FROM settings WHERE key = 'plugin_signing_key'")
        row = c.fetchone()
        conn.close()
        return (row["value"] if row else "") or ""
    except Exception:
        return ""


def sign_tap(data: dict, key: str) -> str:
    return hmac.new(key.encode(), _canonical_content(validate_tap(data)), hashlib.sha256).hexdigest()


def _verify_signature(data: dict) -> bool:
    key = _signing_key()
    sig = data.get("signature")
    if not key or not sig:
        return False
    expected = hmac.new(key.encode(), _canonical_content(data), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, str(sig))


# --------------------------------------------------------------------------- install / remove
def _prefixed_rule_id(plugin_id: str, rule_id: str) -> str:
    return f"plug:{plugin_id}:{rule_id}"


def install_plugin(organization_id: int, data: dict, installed_by: str = "admin") -> dict[str, Any]:
    """Validate + install a plugin's content. Re-installing the same id replaces it."""
    tap = validate_tap(data)
    plugin_id = tap["plugin"]["id"]
    signed = _verify_signature(tap)

    conn = get_db_connection()
    c = conn.cursor()

    # Replace any prior version of this plugin first.
    _remove_content(c, organization_id, plugin_id)

    counts = {"rules": 0, "intel": 0, "playbooks": 0}
    for r in tap["detection_rules"]:
        c.execute(
            '''
            INSERT INTO detection_rules (rule_id, name, description, conditions_json, severity, enabled, attack_technique, attack_tactic, plugin_id)
            VALUES (?, ?, ?, ?, ?, TRUE, ?, ?, ?)
            ON CONFLICT (rule_id) DO UPDATE SET
                name=excluded.name, description=excluded.description, conditions_json=excluded.conditions_json,
                severity=excluded.severity, enabled=TRUE, attack_technique=excluded.attack_technique,
                attack_tactic=excluded.attack_tactic, plugin_id=excluded.plugin_id
            ''',
            (
                _prefixed_rule_id(plugin_id, r["rule_id"]), r["name"], r.get("description", ""),
                json.dumps(r.get("conditions", {})), r.get("severity", "Medium"),
                r.get("attack_technique"), r.get("attack_tactic"), plugin_id,
            ),
        )
        counts["rules"] += 1

    for i in tap["intel_indicators"]:
        c.execute(
            '''
            INSERT INTO intel_indicators (organization_id, type, value, verdict, source, description, confidence, created_by)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT (organization_id, type, value) DO UPDATE SET
                verdict=excluded.verdict, source=excluded.source, description=excluded.description, confidence=excluded.confidence
            ''',
            (
                organization_id, str(i["type"]).lower(), str(i["value"]).strip().lower(),
                (i.get("verdict") or "block").lower(), f"plugin:{plugin_id}",
                i.get("description", ""), int(i.get("confidence", 80)),
                f"plugin:{plugin_id}",
            ),
        )
        counts["intel"] += 1

    for p in tap["playbooks"]:
        c.execute(
            '''
            INSERT INTO playbooks (organization_id, name, trigger_action, steps_json, enabled)
            VALUES (?, ?, ?, ?, TRUE)
            ''',
            (organization_id, f"[{plugin_id}] {p.get('name', 'playbook')}", p.get("trigger_action", "quarantine"),
             json.dumps(p.get("steps", []))),
        )
        counts["playbooks"] += 1

    c.execute(
        '''
        INSERT INTO plugins (organization_id, plugin_id, name, version, author, category, description, enabled, signed, manifest_json, counts_json, installed_by)
        VALUES (?, ?, ?, ?, ?, ?, ?, TRUE, ?, ?, ?, ?)
        ON CONFLICT (organization_id, plugin_id) DO UPDATE SET
            name=excluded.name, version=excluded.version, author=excluded.author, category=excluded.category,
            description=excluded.description, enabled=TRUE, signed=excluded.signed,
            manifest_json=excluded.manifest_json, counts_json=excluded.counts_json, installed_by=excluded.installed_by
        ''',
        (
            organization_id, plugin_id, tap["plugin"]["name"], tap["plugin"]["version"], tap["plugin"]["author"],
            tap["plugin"]["category"], tap["plugin"]["description"], signed,
            json.dumps(tap["plugin"]), json.dumps(counts), installed_by,
        ),
    )
    conn.commit()
    conn.close()
    return {"plugin_id": plugin_id, "name": tap["plugin"]["name"], "signed": signed, "installed": counts}


def _remove_content(c, organization_id: int, plugin_id: str) -> None:
    c.execute("DELETE FROM detection_rules WHERE plugin_id = ?", (plugin_id,))
    c.execute("DELETE FROM intel_indicators WHERE organization_id = ? AND source = ?", (organization_id, f"plugin:{plugin_id}"))
    c.execute("DELETE FROM playbooks WHERE organization_id = ? AND name LIKE ?", (organization_id, f"[{plugin_id}] %"))


def remove_plugin(organization_id: int, plugin_id: str) -> bool:
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT 1 FROM plugins WHERE organization_id = ? AND plugin_id = ?", (organization_id, plugin_id))
    if not c.fetchone():
        conn.close()
        return False
    _remove_content(c, organization_id, plugin_id)
    c.execute("DELETE FROM plugins WHERE organization_id = ? AND plugin_id = ?", (organization_id, plugin_id))
    conn.commit()
    conn.close()
    return True


def set_enabled(organization_id: int, plugin_id: str, enabled: bool) -> bool:
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT 1 FROM plugins WHERE organization_id = ? AND plugin_id = ?", (organization_id, plugin_id))
    if not c.fetchone():
        conn.close()
        return False
    c.execute("UPDATE plugins SET enabled = ? WHERE organization_id = ? AND plugin_id = ?", (enabled, organization_id, plugin_id))
    c.execute("UPDATE detection_rules SET enabled = ? WHERE plugin_id = ?", (enabled, plugin_id))
    conn.commit()
    conn.close()
    return True


def list_plugins(organization_id: int) -> list[dict[str, Any]]:
    conn = get_db_connection()
    c = conn.cursor()
    c.execute(
        "SELECT plugin_id, name, version, author, category, description, enabled, signed, counts_json, installed_by, created_at "
        "FROM plugins WHERE organization_id = ? ORDER BY created_at DESC",
        (organization_id,),
    )
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    for r in rows:
        try:
            r["counts"] = json.loads(r.pop("counts_json") or "{}")
        except Exception:
            r["counts"] = {}
    return rows
