"""
Shared detection-persistence pipeline.

Both the IMAP watcher and the API ingestion endpoint route a decoded message
through the hybrid detector and then call `persist_detection` to run policies,
rules, IOC/MITRE enrichment, and write the full SOC evidence trail — tenant-scoped
by `organization_id`. Keeping this in one place means the two entry points can
never drift apart.
"""
from __future__ import annotations

import json
import logging
from typing import Any, Optional

from framework.audit import audit_log
from framework.ioc import extract_iocs, persist_iocs
from framework.mitre import map_mitre
from framework.playbooks import execute_playbooks
from framework.policy_engine import apply_policies
from framework.rules import evaluate_detection_rules
from framework.siem import export_siem_event, siem_min_score
from framework.soc_metrics import sla_for
from framework.threat_intel import enrich
from framework.attachment_scanner import scan_attachment
from framework.learning import apply_reputation

logger = logging.getLogger(__name__)


def _blocklisted_hashes(organization_id: int, cursor) -> set[str]:
    """Fetch blocklisted file hashes for attachment hash-reputation."""
    try:
        cursor.execute(
            "SELECT LOWER(value) AS v FROM intel_indicators "
            "WHERE organization_id = ? AND verdict = 'block' AND type IN ('sha256', 'md5')",
            (organization_id,),
        )
        return {row["v"] for row in cursor.fetchall()}
    except Exception:
        return set()


def persist_detection(
    cursor,
    *,
    organization_id: int,
    sender: str,
    subject: str,
    recipient: str,
    content: str,
    analysis: dict[str, Any],
    attachments: Optional[list[dict[str, Any]]] = None,
    source: str = "watcher",
) -> dict[str, Any]:
    """
    Persist a completed hybrid analysis and all derived SOC artefacts.

    The caller supplies an open cursor and is responsible for the surrounding
    commit/close, so the whole ingest is one transaction.
    """
    attachments = attachments or []

    rule_matches = evaluate_detection_rules(analysis)
    analysis["rule_matches"] = rule_matches
    policy_result = apply_policies(analysis, organization_id)
    analysis["policy"] = policy_result
    iocs = extract_iocs(content, attachments)
    mitre = map_mitre(analysis.get("threat_type", "Unknown"), analysis.get("features", {}))

    # Threat-intel enrichment against the tenant blocklist/allowlist.
    intel = enrich(organization_id, iocs, cursor)
    analysis["intel"] = intel

    # Attachment malware analysis (static + optional macro/clamd), hash-reputation aware.
    intel_hashes = _blocklisted_hashes(organization_id, cursor)
    for attachment in attachments:
        scan = scan_attachment(
            attachment.get("filename", ""),
            attachment.get("content_type", ""),
            attachment.get("payload"),
            intel_hashes,
        )
        attachment["scan"] = scan
    attachment_risk = max((a.get("scan", {}).get("risk_score", 0) for a in attachments), default=0)

    phishing_score = analysis.get("final_risk_score", 0)
    url_threat_score = analysis.get("heuristic_score", 0)
    ai_reason = analysis.get("explanation", "No reason provided")
    threat_type = analysis.get("threat_type", "Unknown")
    confidence_score = analysis.get("confidence_score", 0)
    recommended_action = analysis.get("recommended_action", "")

    # A blocklist match is decisive: force quarantine and reflect it in the score/evidence.
    if intel.get("block"):
        phishing_score = max(int(phishing_score), 90)
        threat_type = threat_type if threat_type not in ("Unknown", "Safe") else "Known-Bad Indicator"
        evidence = analysis.setdefault("evidence", {})
        signals = evidence.setdefault("signals", [])
        blocked = ", ".join(m["value"] for m in intel.get("matches", []) if m["verdict"] == "block")
        signals.insert(0, f"Threat-intel blocklist match: {blocked}")

    # A malicious attachment is also decisive.
    if attachment_risk >= 80:
        phishing_score = max(int(phishing_score), attachment_risk)
        if threat_type in ("Unknown", "Safe"):
            threat_type = "Malware / Attachment"
        evidence = analysis.setdefault("evidence", {})
        signals = evidence.setdefault("signals", [])
        bad = [a for a in attachments if a.get("scan", {}).get("risk_score", 0) >= 80]
        for a in bad[:2]:
            for sig in a["scan"].get("signals", [])[:2]:
                signals.insert(0, f"Attachment: {sig}")

    # Adaptive reputation learned from past analyst verdicts (feedback loop).
    rep = apply_reputation(organization_id, sender, analysis.get("urls_found", []), cursor)
    if rep.get("delta"):
        phishing_score = max(0, min(100, int(phishing_score) + rep["delta"]))
        evidence = analysis.setdefault("evidence", {})
        signals = evidence.setdefault("signals", [])
        signals.insert(0, f"Learned reputation: {rep['verdict']} (score {rep['delta']:+d})")

    urls_list_str = json.dumps(analysis.get("urls_found", []))
    evidence_json = json.dumps(analysis.get("evidence", {}))
    agent_verdicts_json = json.dumps(analysis.get("agent_verdicts", {}))

    is_threat = (
        phishing_score > 70
        or url_threat_score > 70
        or policy_result["policy_action"] == "quarantine"
        or intel.get("block", False)
    )
    if policy_result["policy_action"] == "hold_for_review" and not intel.get("block"):
        status = "Needs Review"
    else:
        status = "Quarantined" if is_threat else "Allowed"

    cursor.execute(
        '''
        INSERT INTO emails (
            organization_id, sender, subject, risk_score, url_threat_score, urls_found, status,
            threat_type, confidence_score, recommended_action, ai_analysis_log,
            evidence_json, agent_verdicts_json, source
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''',
        (
            organization_id, sender, subject, phishing_score, url_threat_score, urls_list_str, status,
            threat_type, confidence_score, recommended_action, ai_reason,
            evidence_json, agent_verdicts_json, source,
        ),
    )
    email_id = cursor.lastrowid

    persist_iocs(email_id, iocs, cursor)
    cursor.execute(
        '''
        INSERT INTO mitre_mappings (email_id, technique_id, technique, tactic, defense)
        VALUES (?, ?, ?, ?, ?)
        ''',
        (email_id, mitre["technique_id"], mitre["technique"], mitre["tactic"], mitre["defense"]),
    )
    for attachment in attachments:
        scan = attachment.get("scan", {})
        cursor.execute(
            '''
            INSERT INTO attachments (email_id, filename, content_type, size_bytes, risk_score, signals_json, sha256, verdict)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''',
            (
                email_id,
                attachment.get("filename", ""),
                attachment.get("content_type", ""),
                attachment.get("size_bytes", 0) or scan.get("size", 0),
                scan.get("risk_score", 0),
                json.dumps(scan.get("signals", [])),
                scan.get("sha256", ""),
                scan.get("verdict", "clean"),
            ),
        )

    cursor.execute(
        "INSERT INTO email_timeline (email_id, event_type, details) VALUES (?, 'received', ?)",
        (email_id, f"Message received from {sender} via {source}"),
    )
    cursor.execute(
        "INSERT INTO email_timeline (email_id, event_type, details) VALUES (?, 'analyzed', ?)",
        (email_id, f"AI verdict: {threat_type}, score {phishing_score}, confidence {confidence_score}"),
    )
    cursor.execute(
        "INSERT INTO email_timeline (email_id, event_type, details) VALUES (?, 'policy_evaluated', ?)",
        (email_id, f"Policy action: {policy_result['policy_action']} ({policy_result['policy_severity']})"),
    )
    if rule_matches:
        cursor.execute(
            "INSERT INTO email_timeline (email_id, event_type, details) VALUES (?, 'rules_matched', ?)",
            (email_id, ", ".join(rule["name"] for rule in rule_matches)),
        )
    cursor.execute(
        "INSERT INTO email_timeline (email_id, event_type, details) VALUES (?, 'mitre_mapped', ?)",
        (email_id, f"{mitre['technique_id']} {mitre['technique']}"),
    )

    case_id = None
    siem_payload = {
        "email_id": email_id,
        "organization_id": organization_id,
        "sender": sender,
        "subject": subject,
        "recipient": recipient,
        "risk_score": phishing_score,
        "threat_type": threat_type,
        "policy": policy_result,
        "mitre": mitre,
        "iocs": iocs,
        "rule_matches": rule_matches,
    }
    if is_threat:
        cursor.execute(
            "INSERT INTO quarantine (email_id, recipient, ai_reason) VALUES (?, ?, ?)",
            (email_id, recipient, ai_reason),
        )
        cursor.execute(
            "INSERT INTO email_timeline (email_id, event_type, details) VALUES (?, 'quarantined', ?)",
            (email_id, recommended_action or "Message moved to quarantine"),
        )
        if policy_result["policy_severity"] in {"Critical", "High"}:
            sla = sla_for(policy_result["policy_severity"])
            cursor.execute(
                '''
                INSERT INTO cases (organization_id, email_id, title, severity, status, description, sla_minutes, due_at)
                VALUES (?, ?, ?, ?, 'Open', ?, ?, CURRENT_TIMESTAMP + make_interval(mins => ?))
                ''',
                (organization_id, email_id, f"{threat_type}: {subject}", policy_result["policy_severity"], recommended_action, sla, sla),
            )
            case_id = cursor.lastrowid
            cursor.execute(
                "INSERT INTO case_events (case_id, event_type, details) VALUES (?, 'created', ?)",
                (case_id, recommended_action or threat_type),
            )
            cursor.execute(
                "INSERT INTO email_timeline (email_id, event_type, details) VALUES (?, 'case_created', ?)",
                (email_id, f"Case #{case_id} created"),
            )
        audit_log("email_quarantined", source, "email", email_id, ai_reason, organization_id=organization_id)
        export_siem_event("threateye.email_alert", siem_payload)
        execute_playbooks(policy_result["policy_action"], email_id, case_id, siem_payload, cursor)
    elif phishing_score >= siem_min_score():
        # Delivered, but scored high enough that the SOC should still see it.
        # Without this, everything under the quarantine bar is invisible in the
        # SIEM — which is precisely the band worth threat-hunting over.
        export_siem_event("threateye.email_suspicious", siem_payload)

    return {
        "email_id": email_id,
        "status": status,
        "is_threat": is_threat,
        "case_id": case_id,
        "phishing_score": phishing_score,
        "url_threat_score": url_threat_score,
        "threat_type": threat_type,
        "confidence_score": confidence_score,
        "recommended_action": recommended_action,
        "policy": policy_result,
        "rule_matches": rule_matches,
        "iocs": iocs,
        "mitre": mitre,
    }
