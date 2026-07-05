"""
Campaign clustering.

Groups recent inbound emails into likely campaigns so analysts triage a campaign
instead of N near-identical alerts. Read-time aggregation (no ML deps): the cluster
key is the sender domain + a normalised subject; clusters sharing IOC domains are
then merged. Tenant-scoped.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timedelta
from typing import Any

from db import get_db_connection

_NUM = re.compile(r"\d+")
_NONWORD = re.compile(r"[^a-z0-9 ]+")
_WS = re.compile(r"\s+")
_RE_PREFIX = re.compile(r"^(re|fw|fwd|aw|wg)\s*:\s*", re.IGNORECASE)


def _sender_domain(sender: str) -> str:
    sender = (sender or "").lower()
    return sender.split("@")[-1].strip(" <>") if "@" in sender else sender


def _normalize_subject(subject: str) -> str:
    s = (subject or "").lower()
    s = _RE_PREFIX.sub("", s)
    s = _NUM.sub("#", s)          # collapse order ids / amounts
    s = _NONWORD.sub(" ", s)
    s = _WS.sub(" ", s).strip()
    return s or "(no subject)"


def cluster_emails(organization_id: int, days: int = 14, min_risk: int = 40) -> list[dict[str, Any]]:
    since = datetime.utcnow() - timedelta(days=days)
    conn = get_db_connection()
    c = conn.cursor()
    c.execute(
        '''
        SELECT id, sender, subject, risk_score, threat_type, timestamp, urls_found
        FROM emails
        WHERE organization_id = ? AND risk_score >= ? AND timestamp >= ?
        ORDER BY timestamp DESC
        ''',
        (organization_id, min_risk, since),
    )
    rows = [dict(r) for r in c.fetchall()]
    conn.close()

    clusters: dict[tuple, dict[str, Any]] = {}
    for r in rows:
        domain = _sender_domain(r["sender"])
        key = (domain, _normalize_subject(r["subject"]))
        cl = clusters.get(key)
        if not cl:
            cl = {
                "signature": f"{domain} · {_normalize_subject(r['subject'])}",
                "sender_domain": domain,
                "sample_subject": r["subject"],
                "threat_type": r.get("threat_type") or "Unknown",
                "count": 0,
                "max_risk": 0,
                "email_ids": [],
                "recipients_domains": set(),
                "first_seen": str(r["timestamp"]),
                "last_seen": str(r["timestamp"]),
            }
            clusters[key] = cl
        cl["count"] += 1
        cl["max_risk"] = max(cl["max_risk"], r.get("risk_score") or 0)
        cl["email_ids"].append(r["id"])
        ts = str(r["timestamp"])
        cl["first_seen"] = min(cl["first_seen"], ts)
        cl["last_seen"] = max(cl["last_seen"], ts)

    result = []
    for cl in clusters.values():
        cl.pop("recipients_domains", None)
        cl["email_ids"] = cl["email_ids"][:50]
        result.append(cl)
    # Multi-message clusters first (real campaigns), then by risk.
    result.sort(key=lambda x: (x["count"], x["max_risk"]), reverse=True)
    return result
