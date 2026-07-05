from __future__ import annotations


MITRE_MAP = {
    "Credential Harvesting": {
        "technique_id": "T1566.002",
        "technique": "Spearphishing Link",
        "tactic": "Initial Access",
        "defense": "Block URL, reset exposed credentials, enforce phishing-resistant MFA.",
    },
    "Suspicious Link": {
        "technique_id": "T1566.002",
        "technique": "Spearphishing Link",
        "tactic": "Initial Access",
        "defense": "Detonate URL in sandbox and block domain if malicious.",
    },
    "Malware": {
        "technique_id": "T1566.001",
        "technique": "Spearphishing Attachment",
        "tactic": "Initial Access",
        "defense": "Sandbox attachment, block hash, and isolate affected hosts.",
    },
    "BEC": {
        "technique_id": "T1566",
        "technique": "Phishing",
        "tactic": "Initial Access",
        "defense": "Verify payment requests out-of-band and enforce finance approval workflow.",
    },
    "AI Evasion": {
        "technique_id": "T1566",
        "technique": "Phishing",
        "tactic": "Initial Access",
        "defense": "Quarantine adversarial content and review prompt-injection indicators.",
    },
}


def map_mitre(threat_type: str, features: dict | None = None) -> dict:
    text = (threat_type or "").lower()
    features = features or {}
    if features.get("prompt_injection_detected"):
        return MITRE_MAP["AI Evasion"]
    if "bec" in text or "payment" in text or "invoice" in text:
        return MITRE_MAP["BEC"]
    if "credential" in text or "harvesting" in text:
        return MITRE_MAP["Credential Harvesting"]
    if "malware" in text or "attachment" in text:
        return MITRE_MAP["Malware"]
    if "link" in text or "phishing" in text:
        return MITRE_MAP["Suspicious Link"]
    return {
        "technique_id": "T1566",
        "technique": "Phishing",
        "tactic": "Initial Access",
        "defense": "Monitor, collect evidence, and escalate if additional indicators appear.",
    }

