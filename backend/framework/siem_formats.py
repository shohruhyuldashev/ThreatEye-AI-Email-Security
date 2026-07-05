"""
Normalise ThreatEye alerts into common SIEM schemas so downstream tooling can
ingest them without custom parsers. Pure functions — trivially testable offline.

Supported: raw (native), ECS (Elastic Common Schema), OCSF (Open Cybersecurity
Schema Framework, Email Activity class).
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _severity_id(score: int) -> int:
    # OCSF severity_id: 1 Informational .. 5 Critical
    if score >= 90:
        return 5
    if score >= 70:
        return 4
    if score >= 40:
        return 3
    if score >= 20:
        return 2
    return 1


def to_ecs(event_type: str, payload: dict[str, Any]) -> dict[str, Any]:
    score = int(payload.get("risk_score", 0) or 0)
    return {
        "@timestamp": _now_iso(),
        "event": {
            "kind": "alert",
            "category": ["email", "threat"],
            "action": event_type,
            "risk_score": score,
            "provider": "threateye",
        },
        "email": {
            "from": {"address": payload.get("sender")},
            "to": {"address": payload.get("recipient")},
            "subject": payload.get("subject"),
        },
        "threat": {
            "framework": "MITRE ATT&CK",
            "technique": {
                "id": (payload.get("mitre") or {}).get("technique_id"),
                "name": (payload.get("mitre") or {}).get("technique"),
            },
            "tactic": {"name": (payload.get("mitre") or {}).get("tactic")},
            "indicator": [
                {"type": i.get("type"), "value": i.get("value")}
                for i in (payload.get("iocs") or [])
            ],
        },
        "rule": {"name": ", ".join(r.get("name", "") for r in (payload.get("rule_matches") or []))},
        "organization": {"id": payload.get("organization_id")},
        "message": payload.get("threat_type"),
        "labels": {"threat_type": payload.get("threat_type")},
    }


def to_ocsf(event_type: str, payload: dict[str, Any]) -> dict[str, Any]:
    score = int(payload.get("risk_score", 0) or 0)
    return {
        # OCSF Email Activity (class_uid 4009), category Network Activity (4).
        "class_uid": 4009,
        "class_name": "Email Activity",
        "category_uid": 4,
        "activity_id": 1,
        "time": int(datetime.now(timezone.utc).timestamp() * 1000),
        "severity_id": _severity_id(score),
        "metadata": {"product": {"name": "ThreatEye", "vendor_name": "ThreatEye"}, "version": "1.1.0"},
        "email": {
            "from": payload.get("sender"),
            "to": [payload.get("recipient")] if payload.get("recipient") else [],
            "subject": payload.get("subject"),
        },
        "risk_level": payload.get("threat_type"),
        "risk_score": score,
        "attacks": [
            {
                "tactic": {"name": (payload.get("mitre") or {}).get("tactic")},
                "technique": {
                    "uid": (payload.get("mitre") or {}).get("technique_id"),
                    "name": (payload.get("mitre") or {}).get("technique"),
                },
            }
        ],
        "observables": [
            {"type": i.get("type"), "value": i.get("value")}
            for i in (payload.get("iocs") or [])
        ],
        "org": {"uid": str(payload.get("organization_id", ""))},
        "type_name": event_type,
    }


def format_event(fmt: str, event_type: str, payload: dict[str, Any]) -> dict[str, Any]:
    fmt = (fmt or "raw").lower()
    if fmt == "ecs":
        return to_ecs(event_type, payload)
    if fmt == "ocsf":
        return to_ocsf(event_type, payload)
    return {"event_type": event_type, **payload}
