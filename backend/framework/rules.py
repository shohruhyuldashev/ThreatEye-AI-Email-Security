from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml

from db import get_db_connection


RULES_DIR = Path(__file__).resolve().parents[1] / "rules"


def load_detection_rules():
    RULES_DIR.mkdir(exist_ok=True)
    conn = get_db_connection()
    c = conn.cursor()
    # Support both native (.yaml) and Sigma-style (.yml) detection files.
    paths = sorted(RULES_DIR.glob("*.yaml")) + sorted(RULES_DIR.glob("*.yml"))
    for path in paths:
        data = yaml.safe_load(path.read_text()) or {}
        rule_id = data.get("id") or path.stem
        # Conditions live top-level (native) or under `detection.conditions` (Sigma-style).
        conditions = data.get("conditions") or (data.get("detection", {}) or {}).get("conditions", {}) or {}
        # ATT&CK tags: explicit fields, or parsed from Sigma-style `tags: [attack.t1566...]`.
        technique = data.get("attack_technique")
        tactic = data.get("attack_tactic")
        if not technique:
            for tag in data.get("tags", []) or []:
                t = str(tag).lower()
                if t.startswith("attack.t"):
                    technique = t.split("attack.", 1)[1].upper()
                    break
        c.execute('''
            INSERT INTO detection_rules (rule_id, name, description, conditions_json, severity, enabled, attack_technique, attack_tactic)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(rule_id) DO UPDATE SET
                name=excluded.name,
                description=excluded.description,
                conditions_json=excluded.conditions_json,
                severity=excluded.severity,
                enabled=excluded.enabled,
                attack_technique=excluded.attack_technique,
                attack_tactic=excluded.attack_tactic
        ''', (
            rule_id,
            data.get("name") or data.get("title", rule_id),
            data.get("description", ""),
            json.dumps(conditions),
            data.get("severity", "Medium"),
            bool(data.get("enabled", True)),
            technique,
            tactic,
        ))
    conn.commit()
    conn.close()


def evaluate_detection_rules(analysis: dict[str, Any]) -> list[dict[str, Any]]:
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT rule_id, name, conditions_json, severity FROM detection_rules WHERE enabled = TRUE")
    rows = [dict(row) for row in c.fetchall()]
    conn.close()

    matches = []
    features = analysis.get("features", {}) or {}
    for row in rows:
        conditions = json.loads(row["conditions_json"] or "{}")
        if _matches(conditions, analysis, features):
            matches.append({
                "rule_id": row["rule_id"],
                "name": row["name"],
                "severity": row["severity"],
            })
    return matches


def _matches(conditions: dict[str, Any], analysis: dict[str, Any], features: dict[str, Any]) -> bool:
    if "min_score" in conditions and int(analysis.get("final_risk_score", 0)) < int(conditions["min_score"]):
        return False
    if "threat_type_contains" in conditions and conditions["threat_type_contains"].lower() not in str(analysis.get("threat_type", "")).lower():
        return False
    if "feature_true" in conditions and not features.get(conditions["feature_true"]):
        return False
    if "signal_contains" in conditions:
        evidence = analysis.get("evidence", {}) or {}
        signals = " ".join(evidence.get("signals", []))
        if conditions["signal_contains"].lower() not in signals.lower():
            return False
    return True

