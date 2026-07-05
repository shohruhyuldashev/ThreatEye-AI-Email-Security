"""
MITRE ATT&CK coverage: what we can detect (defended by enabled rules / mappings)
vs. what we've actually observed in traffic, grouped by tactic.

Scoped to the email-borne techniques this platform reasons about; extend
TECHNIQUE_CATALOG as detection content grows.
"""
from __future__ import annotations

from typing import Any

from db import get_db_connection

# The email-threat techniques ThreatEye is designed to cover.
TECHNIQUE_CATALOG = {
    "T1566": {"name": "Phishing", "tactic": "Initial Access"},
    "T1566.001": {"name": "Spearphishing Attachment", "tactic": "Initial Access"},
    "T1566.002": {"name": "Spearphishing Link", "tactic": "Initial Access"},
    "T1598": {"name": "Phishing for Information", "tactic": "Reconnaissance"},
    "T1204": {"name": "User Execution", "tactic": "Execution"},
    "T1204.001": {"name": "Malicious Link", "tactic": "Execution"},
    "T1204.002": {"name": "Malicious File", "tactic": "Execution"},
    "T1534": {"name": "Internal Spearphishing", "tactic": "Lateral Movement"},
    "T1656": {"name": "Impersonation", "tactic": "Initial Access"},
}


def get_coverage(organization_id: int) -> dict[str, Any]:
    conn = get_db_connection()
    c = conn.cursor()

    # Observed: techniques actually seen in this tenant's mail.
    c.execute(
        '''
        SELECT m.technique_id, COUNT(*) AS n
        FROM mitre_mappings m JOIN emails e ON m.email_id = e.id
        WHERE e.organization_id = ?
        GROUP BY m.technique_id
        ''',
        (organization_id,),
    )
    observed = {row["technique_id"]: row["n"] for row in c.fetchall()}

    # Defended: techniques tagged on enabled detection rules.
    c.execute("SELECT attack_technique FROM detection_rules WHERE enabled = TRUE AND attack_technique IS NOT NULL")
    defended = {row["attack_technique"] for row in c.fetchall() if row["attack_technique"]}
    conn.close()

    tactics: dict[str, list] = {}
    covered = 0
    for tid, meta in TECHNIQUE_CATALOG.items():
        is_defended = tid in defended
        n_observed = observed.get(tid, 0)
        if is_defended:
            covered += 1
        status = "defended" if is_defended else ("observed" if n_observed else "gap")
        tactics.setdefault(meta["tactic"], []).append({
            "technique_id": tid,
            "technique": meta["name"],
            "defended": is_defended,
            "observed": n_observed,
            "status": status,
        })

    total = len(TECHNIQUE_CATALOG)
    return {
        "tactics": tactics,
        "summary": {
            "total_techniques": total,
            "defended": covered,
            "observed": len([t for t in TECHNIQUE_CATALOG if observed.get(t)]),
            "coverage_pct": round((covered / total) * 100, 1) if total else 0.0,
        },
    }
