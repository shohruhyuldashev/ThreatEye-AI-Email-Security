"""
Outbound response integrations + remediation actions.

Every connector is offline-safe: if its target isn't configured (in settings), the
action is recorded with status 'skipped' rather than failing. All actions are written
to `remediation_actions` for an auditable response trail.

Config keys (Settings): slack_webhook_url, teams_webhook_url, jira_url, jira_token,
jira_project, remediation_webhook_url.
"""
from __future__ import annotations

import json
import logging
from typing import Any

import requests

from db import get_db_connection

logger = logging.getLogger(__name__)

CONFIG_KEYS = (
    "slack_webhook_url", "teams_webhook_url",
    "jira_url", "jira_token", "jira_project",
    "remediation_webhook_url",
    "m365_tenant_id", "m365_client_id", "m365_client_secret", "m365_mailboxes",
    "google_sa_json", "google_mailboxes",
)


def _load_config() -> dict[str, str]:
    conn = get_db_connection()
    c = conn.cursor()
    placeholders = ",".join(["?"] * len(CONFIG_KEYS))
    c.execute(f"SELECT key, value FROM settings WHERE key IN ({placeholders})", CONFIG_KEYS)
    from framework.secretbox import decrypt_setting
    cfg = {row["key"]: decrypt_setting(row["key"], row["value"]) for row in c.fetchall()}
    conn.close()
    return cfg


def _record(cursor, organization_id, email_id, action_type, target, status, detail, created_by):
    cursor.execute(
        '''
        INSERT INTO remediation_actions
            (organization_id, email_id, action_type, target, status, detail, created_by)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ''',
        (organization_id, email_id, action_type, target, status, detail, created_by),
    )


def _post_json(url: str, body: dict[str, Any], headers: dict | None = None) -> tuple[str, str]:
    try:
        resp = requests.post(url, json=body, headers=headers or {}, timeout=6)
        if 200 <= resp.status_code < 300:
            return "sent", f"HTTP {resp.status_code}"
        return "failed", f"HTTP {resp.status_code}: {resp.text[:200]}"
    except Exception as exc:
        return "failed", str(exc)


def run_remediation(
    organization_id: int,
    email_id: int,
    actions: list[str],
    context: dict[str, Any],
    created_by: str = "analyst",
    cursor=None,
) -> list[dict[str, Any]]:
    """
    Execute the requested response actions for an email.
    `actions` ⊆ {notify, ticket, clawback, block_ioc}.
    """
    owns_conn = cursor is None
    conn = get_db_connection() if owns_conn else None
    c = conn.cursor() if owns_conn else cursor
    cfg = _load_config()
    results = []

    subject = context.get("subject", "")
    sender = context.get("sender", "")
    threat = context.get("threat_type", "Unknown")
    score = context.get("risk_score", 0)
    summary = f"[ThreatEye] {threat} ({score}) from {sender} — {subject}"

    for action in actions:
        if action == "notify":
            targets = []
            if cfg.get("slack_webhook_url"):
                st, detail = _post_json(cfg["slack_webhook_url"], {"text": summary})
                _record(c, organization_id, email_id, "notify", "slack", st, detail, created_by)
                targets.append({"target": "slack", "status": st})
            if cfg.get("teams_webhook_url"):
                st, detail = _post_json(cfg["teams_webhook_url"], {"text": summary})
                _record(c, organization_id, email_id, "notify", "teams", st, detail, created_by)
                targets.append({"target": "teams", "status": st})
            if not targets:
                _record(c, organization_id, email_id, "notify", "chat", "skipped", "No chat webhook configured", created_by)
                targets.append({"target": "chat", "status": "skipped"})
            results.append({"action": "notify", "results": targets})

        elif action == "ticket":
            if cfg.get("jira_url") and cfg.get("jira_token") and cfg.get("jira_project"):
                body = {
                    "fields": {
                        "project": {"key": cfg["jira_project"]},
                        "summary": summary[:250],
                        "description": context.get("recommended_action", threat),
                        "issuetype": {"name": "Task"},
                    }
                }
                headers = {"Authorization": f"Bearer {cfg['jira_token']}"}
                st, detail = _post_json(cfg["jira_url"].rstrip("/") + "/rest/api/2/issue", body, headers)
                _record(c, organization_id, email_id, "ticket", "jira", st, detail, created_by)
                results.append({"action": "ticket", "target": "jira", "status": st})
            else:
                _record(c, organization_id, email_id, "ticket", "jira", "skipped", "Jira not configured", created_by)
                results.append({"action": "ticket", "target": "jira", "status": "skipped"})

        elif action == "clawback":
            # Prefer a real provider connector (M365 Graph / Google Workspace), then a
            # configurable webhook, then record the intent — all offline-safe.
            from framework.mail_remediation import clawback as provider_clawback
            real = provider_clawback(cfg, sender, subject)
            if real is not None:
                _record(c, organization_id, email_id, "clawback", real.get("provider", "provider"),
                        real.get("status", "failed"), json.dumps(real), created_by)
                results.append({"action": "clawback", **real})
            elif cfg.get("remediation_webhook_url"):
                st, detail = _post_json(cfg["remediation_webhook_url"], {
                    "action": "clawback", "email_id": email_id, "sender": sender, "subject": subject,
                })
                _record(c, organization_id, email_id, "clawback", "webhook", st, detail, created_by)
                results.append({"action": "clawback", "status": st})
            else:
                _record(c, organization_id, email_id, "clawback", "mailbox", "recorded",
                        "Clawback intent recorded (no provider connector configured)", created_by)
                results.append({"action": "clawback", "status": "recorded"})

        elif action == "block_ioc":
            from framework.threat_intel import auto_block_iocs
            n = auto_block_iocs(organization_id, email_id, created_by)
            _record(c, organization_id, email_id, "block_ioc", "intel", "recorded", f"{n} indicator(s) blocklisted", created_by)
            results.append({"action": "block_ioc", "status": "recorded", "count": n})

    if owns_conn:
        conn.commit()
        conn.close()
    return results
