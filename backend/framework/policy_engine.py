from __future__ import annotations

import json
from typing import Any

from db import get_db_connection


DEFAULT_POLICIES = [
    {
        "name": "Critical risk quarantine",
        "conditions": {"min_risk_score": 80},
        "action": "quarantine",
        "severity": "Critical",
        "enabled": True,
    },
    {
        "name": "BEC hold for review",
        "conditions": {"threat_type_contains": "BEC"},
        "action": "hold_for_review",
        "severity": "High",
        "enabled": True,
    },
    {
        "name": "Prompt injection quarantine",
        "conditions": {"feature_true": "prompt_injection_detected"},
        "action": "quarantine",
        "severity": "High",
        "enabled": True,
    },
]


def seed_default_policies():
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM policies")
    if c.fetchone()[0] == 0:
        for policy in DEFAULT_POLICIES:
            c.execute('''
                INSERT INTO policies (organization_id, name, conditions_json, action, severity, enabled)
                VALUES (1, ?, ?, ?, ?, ?)
            ''', (
                policy["name"],
                json.dumps(policy["conditions"]),
                policy["action"],
                policy["severity"],
                policy["enabled"],
            ))
    conn.commit()
    conn.close()


def apply_policies(analysis: dict[str, Any], organization_id: int = 1) -> dict[str, Any]:
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('''
        SELECT id, name, conditions_json, action, severity
        FROM policies
        WHERE organization_id = ? AND enabled = TRUE
        ORDER BY id ASC
    ''', (organization_id,))
    policies = [dict(row) for row in c.fetchall()]
    conn.close()

    matches = []
    features = analysis.get("features", {}) or {}
    for policy in policies:
        conditions = json.loads(policy["conditions_json"] or "{}")
        if _matches(conditions, analysis, features):
            matches.append(policy)

    action = "allow"
    severity = "Low"
    if matches:
        priority = {"quarantine": 3, "hold_for_review": 2, "allow": 1}
        best = max(matches, key=lambda p: priority.get(p["action"], 0))
        action = best["action"]
        severity = best["severity"]

    return {
        "policy_action": action,
        "policy_severity": severity,
        "matched_policies": [{"id": p["id"], "name": p["name"], "action": p["action"]} for p in matches],
    }


SUPPORTED_CONDITIONS = {"min_risk_score", "threat_type_contains", "feature_true", "sender_domain"}


def _matches(conditions: dict[str, Any], analysis: dict[str, Any], features: dict[str, Any]) -> bool:
    # Fail closed. A policy with no conditions, or with any unrecognised condition key,
    # must NOT match — otherwise a typo like {"min_score": 90} (correct key is
    # "min_risk_score") is silently ignored and the policy fires on EVERY email,
    # quarantining all mail. An action-bearing rule you can't fully evaluate is not
    # allowed to take its action.
    if not conditions or any(k not in SUPPORTED_CONDITIONS for k in conditions):
        return False

    min_risk = conditions.get("min_risk_score")
    if min_risk is not None and int(analysis.get("final_risk_score", 0)) < int(min_risk):
        return False

    threat_text = conditions.get("threat_type_contains")
    if threat_text and threat_text.lower() not in str(analysis.get("threat_type", "")).lower():
        return False

    feature_true = conditions.get("feature_true")
    if feature_true and not bool(features.get(feature_true)):
        return False

    sender_domain = conditions.get("sender_domain")
    if sender_domain and sender_domain.lower() not in str(analysis.get("sender", "")).lower():
        return False

    return True

