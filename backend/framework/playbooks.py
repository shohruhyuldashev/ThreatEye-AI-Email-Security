from __future__ import annotations

import json
from typing import Any

from db import get_db_connection
from framework.siem import export_siem_event


DEFAULT_PLAYBOOKS = [
    {
        "name": "Critical phishing response",
        "trigger_action": "quarantine",
        "steps": [
            {"type": "timeline", "message": "SOAR playbook started"},
            {"type": "siem_export", "event_type": "threateye.critical_email"},
            {"type": "case_note", "message": "Recommend credential reset and MFA verification."},
        ],
        "enabled": True,
    },
    {
        "name": "BEC finance verification",
        "trigger_action": "hold_for_review",
        "steps": [
            {"type": "timeline", "message": "BEC verification playbook started"},
            {"type": "case_note", "message": "Verify sender and payment request out-of-band."},
        ],
        "enabled": True,
    },
]


def seed_default_playbooks():
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM playbooks")
    if c.fetchone()[0] == 0:
        for playbook in DEFAULT_PLAYBOOKS:
            c.execute('''
                INSERT INTO playbooks (organization_id, name, trigger_action, steps_json, enabled)
                VALUES (1, ?, ?, ?, ?)
            ''', (
                playbook["name"],
                playbook["trigger_action"],
                json.dumps(playbook["steps"]),
                playbook["enabled"],
            ))
    conn.commit()
    conn.close()


def execute_playbooks(trigger_action: str, email_id: int, case_id: int | None, context: dict[str, Any], cursor=None) -> list[dict[str, Any]]:
    conn = None
    if cursor is None:
        conn = get_db_connection()
        cursor = conn.cursor()
    cursor.execute('''
        SELECT id, name, steps_json
        FROM playbooks
        WHERE organization_id = 1 AND enabled = TRUE AND trigger_action = ?
    ''', (trigger_action,))
    playbooks = [dict(row) for row in cursor.fetchall()]

    runs = []
    for playbook in playbooks:
        steps = json.loads(playbook["steps_json"] or "[]")
        results = []
        for step in steps:
            result = _execute_step(cursor, step, email_id, case_id, context)
            results.append(result)
        cursor.execute('''
            INSERT INTO playbook_runs (playbook_id, email_id, case_id, status, result_json)
            VALUES (?, ?, ?, 'completed', ?)
        ''', (playbook["id"], email_id, case_id, json.dumps(results)))
        runs.append({"playbook": playbook["name"], "results": results})

    if conn:
        conn.commit()
        conn.close()
    return runs


def _execute_step(cursor, step: dict[str, Any], email_id: int, case_id: int | None, context: dict[str, Any]) -> dict[str, Any]:
    step_type = step.get("type")
    if step_type == "timeline":
        cursor.execute('''
            INSERT INTO email_timeline (email_id, event_type, details)
            VALUES (?, 'playbook', ?)
        ''', (email_id, step.get("message", "Playbook step executed")))
        return {"type": step_type, "status": "ok"}
    if step_type == "case_note" and case_id:
        cursor.execute('''
            INSERT INTO case_events (case_id, event_type, details)
            VALUES (?, 'playbook_note', ?)
        ''', (case_id, step.get("message", "")))
        return {"type": step_type, "status": "ok"}
    if step_type == "siem_export":
        return {"type": step_type, **export_siem_event(step.get("event_type", "threateye.email_alert"), context)}
    return {"type": step_type or "unknown", "status": "skipped"}
