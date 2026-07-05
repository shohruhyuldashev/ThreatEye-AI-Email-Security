"""
SOC operational metrics: SLA tracking, MTTD/MTTR, and the analyst triage queue.
"""
from __future__ import annotations

from typing import Any

from db import get_db_connection

# SLA targets in minutes by severity (first response / resolution target).
SLA_MINUTES = {
    "Critical": 60,
    "High": 240,
    "Medium": 1440,
    "Low": 4320,
}
DEFAULT_SLA_MINUTES = 1440


def sla_for(severity: str) -> int:
    return SLA_MINUTES.get(severity, DEFAULT_SLA_MINUTES)


def _seconds_between(cursor, expr_a: str, expr_b: str, where: str, params: tuple) -> float | None:
    """AVG of EPOCH(expr_b - expr_a) seconds for rows matching `where`."""
    cursor.execute(
        f"SELECT AVG(EXTRACT(EPOCH FROM ({expr_b} - {expr_a}))) "
        f"FROM cases c LEFT JOIN emails e ON c.email_id = e.id WHERE {where}",
        params,
    )
    row = cursor.fetchone()
    return float(row[0]) if row and row[0] is not None else None


def get_metrics(organization_id: int) -> dict[str, Any]:
    conn = get_db_connection()
    c = conn.cursor()

    c.execute("SELECT COUNT(*) FROM cases WHERE organization_id = ? AND status NOT IN ('Closed','Resolved')", (organization_id,))
    open_cases = c.fetchone()[0]

    c.execute("SELECT COUNT(*) FROM cases WHERE organization_id = ? AND status IN ('Closed','Resolved')", (organization_id,))
    closed_cases = c.fetchone()[0]

    # SLA breaches: past due and not yet resolved.
    c.execute(
        "SELECT COUNT(*) FROM cases WHERE organization_id = ? AND resolved_at IS NULL "
        "AND due_at IS NOT NULL AND due_at < CURRENT_TIMESTAMP",
        (organization_id,),
    )
    sla_breaches = c.fetchone()[0]

    # MTTD ≈ time from message received (email.timestamp) to case created.
    mttd = _seconds_between(
        c, "e.timestamp", "c.created_at",
        "c.organization_id = ? AND e.timestamp IS NOT NULL", (organization_id,),
    )
    # MTTR = time from case created to resolved.
    mttr = _seconds_between(
        c, "c.created_at", "c.resolved_at",
        "c.organization_id = ? AND c.resolved_at IS NOT NULL", (organization_id,),
    )

    c.execute(
        "SELECT severity, COUNT(*) FROM cases WHERE organization_id = ? AND status NOT IN ('Closed','Resolved') GROUP BY severity",
        (organization_id,),
    )
    open_by_severity = {row[0]: row[1] for row in c.fetchall()}

    conn.close()
    return {
        "open_cases": open_cases,
        "closed_cases": closed_cases,
        "sla_breaches": sla_breaches,
        "mttd_minutes": round(mttd / 60, 1) if mttd is not None else None,
        "mttr_minutes": round(mttr / 60, 1) if mttr is not None else None,
        "open_by_severity": open_by_severity,
        "sla_targets_minutes": SLA_MINUTES,
    }


def get_triage_queue(organization_id: int, limit: int = 50) -> list[dict[str, Any]]:
    """
    Prioritised worklist: emails needing analyst attention (quarantined /
    needs-review / unreviewed high risk), newest & riskiest first.
    """
    conn = get_db_connection()
    c = conn.cursor()
    c.execute(
        '''
        SELECT e.id, e.sender, e.subject, e.risk_score, e.threat_type, e.status,
               e.review_status, e.timestamp, e.recommended_action,
               q.id AS quarantine_id,
               ca.id AS case_id, ca.severity AS case_severity, ca.due_at, ca.status AS case_status
        FROM emails e
        LEFT JOIN quarantine q ON q.email_id = e.id
        LEFT JOIN cases ca ON ca.email_id = e.id
        WHERE e.organization_id = ?
          AND (
                e.status IN ('Quarantined', 'Needs Review')
                OR (e.risk_score >= 50 AND COALESCE(e.review_status, 'Unreviewed') = 'Unreviewed')
          )
        ORDER BY e.risk_score DESC, e.timestamp DESC
        LIMIT ?
        ''',
        (organization_id, limit),
    )
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    for r in rows:
        # A simple priority band for the UI.
        score = r.get("risk_score") or 0
        if score >= 80 or (r.get("case_severity") in ("Critical", "High")):
            r["priority"] = "P1"
        elif score >= 50:
            r["priority"] = "P2"
        else:
            r["priority"] = "P3"
    return rows
