"""
Adaptive learning / feedback loop.

Closes the loop between analyst decisions, simulation outcomes, and future scoring:
  - `learn_from_verdict`: a "Confirmed Phishing" verdict lowers the sender/domain
    reputation and blocklists its IOCs; "Marked Safe" raises it (fewer repeat
    false positives).
  - `apply_reputation`: turns learned reputation into a score adjustment at ingest.
  - `sync_sim_behavior`: repeat sim-clickers get a higher behavioural risk, which the
    detector already factors in via user_profiles.
"""
from __future__ import annotations

import re
from typing import Any

from framework.netutil import tld_extract

from db import get_db_connection

_CONFIRMED_DELTA = 40
_SAFE_DELTA = -40
_CLAMP = 100
_MALICIOUS_AT = 60
_TRUSTED_AT = -60


def _domain(addr: str) -> str:
    addr = (addr or "").lower().strip(" <>")
    host = addr.split("@")[-1] if "@" in addr else addr
    ext = tld_extract(host)
    return f"{ext.domain}.{ext.suffix}".strip(".") if ext.suffix else ext.domain


def _url_domain(url: str) -> str:
    ext = tld_extract(url)
    return f"{ext.domain}.{ext.suffix}".strip(".") if ext.suffix else ext.domain


def _bump(cursor, org: int, kind: str, value: str, delta: int, confirmed: bool = False, safe: bool = False) -> None:
    if not value:
        return
    cursor.execute(
        '''
        INSERT INTO reputation (organization_id, kind, value, score, confirmed_count, safe_count, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        ON CONFLICT (organization_id, kind, value) DO UPDATE SET
            score = GREATEST(-100, LEAST(100, reputation.score + ?)),
            confirmed_count = reputation.confirmed_count + ?,
            safe_count = reputation.safe_count + ?,
            updated_at = CURRENT_TIMESTAMP
        ''',
        (
            org, kind, value, max(-_CLAMP, min(_CLAMP, delta)), 1 if confirmed else 0, 1 if safe else 0,
            delta, 1 if confirmed else 0, 1 if safe else 0,
        ),
    )


def learn_from_verdict(organization_id: int, email_id: int, review_status: str, actor: str = "analyst") -> dict[str, Any]:
    """Update learned reputation from an analyst verdict; blocklist IOCs on confirmed phishing."""
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT sender FROM emails WHERE id = ? AND organization_id = ?", (email_id, organization_id))
    row = c.fetchone()
    if not row:
        conn.close()
        return {"learned": False}
    sender = row["sender"]
    sender_domain = _domain(sender)

    c.execute("SELECT type, value FROM iocs WHERE email_id = ?", (email_id,))
    iocs = [dict(r) for r in c.fetchall()]

    learned = {"reputation": [], "blocklisted": 0}
    if review_status == "Confirmed Phishing":
        _bump(c, organization_id, "sender_domain", sender_domain, _CONFIRMED_DELTA, confirmed=True)
        learned["reputation"].append(sender_domain)
        for ioc in iocs:
            if ioc["type"] in ("url", "domain"):
                _bump(c, organization_id, "url_domain", _url_domain(ioc["value"]), _CONFIRMED_DELTA, confirmed=True)
        conn.commit()
        conn.close()
        # Promote IOCs to the blocklist (separate transaction).
        from framework.threat_intel import auto_block_iocs
        learned["blocklisted"] = auto_block_iocs(organization_id, email_id, f"feedback:{actor}")
        return {"learned": True, **learned}

    if review_status == "Marked Safe":
        _bump(c, organization_id, "sender_addr", (sender or "").lower(), _SAFE_DELTA, safe=True)
        _bump(c, organization_id, "sender_domain", sender_domain, _SAFE_DELTA // 2, safe=True)
        learned["reputation"].append(sender_domain)

    conn.commit()
    conn.close()
    return {"learned": True, **learned}


def apply_reputation(organization_id: int, sender: str, urls: list[str], cursor) -> dict[str, Any]:
    """
    Return a score adjustment from learned reputation for this sender/URLs.
    Positive delta = raise risk (known-bad-ish), negative = lower risk (trusted).
    """
    values = {(sender or "").lower(), _domain(sender)}
    for u in (urls or [])[:5]:
        values.add(_url_domain(u))
    values.discard("")
    if not values:
        return {"delta": 0, "verdict": "neutral", "matches": []}

    placeholders = ",".join(["?"] * len(values))
    cursor.execute(
        f"SELECT kind, value, score FROM reputation WHERE organization_id = ? AND LOWER(value) IN ({placeholders})",
        (organization_id, *values),
    )
    rows = [dict(r) for r in cursor.fetchall()]
    if not rows:
        return {"delta": 0, "verdict": "neutral", "matches": []}

    worst = max((r["score"] for r in rows), default=0)
    best = min((r["score"] for r in rows), default=0)
    delta = 0
    verdict = "neutral"
    if worst >= _MALICIOUS_AT:
        delta = 25
        verdict = "known-bad (learned)"
    elif best <= _TRUSTED_AT:
        delta = -25
        verdict = "trusted (learned)"
    return {"delta": delta, "verdict": verdict, "matches": rows}


def sync_sim_behavior(organization_id: int) -> dict[str, Any]:
    """Fold GoPhish sim outcomes into user_profiles so repeat clickers get higher behavioural risk."""
    from services.gophish_client import get_results
    data = get_results()
    employees = data.get("employees", [])
    if not employees:
        return {"updated": 0, "note": data.get("error", "No clickers to sync.")}

    # Count failures per employee email.
    fails: dict[str, int] = {}
    for e in employees:
        email = (e.get("email") or "").lower()
        if email:
            fails[email] = fails.get(email, 0) + 1

    conn = get_db_connection()
    c = conn.cursor()
    updated = 0
    for email, n in fails.items():
        risk = min(100, 30 + 20 * n)
        role = "Employee"
        c.execute("SELECT department FROM sim_targets WHERE organization_id = ? AND email = ?", (organization_id, email))
        row = c.fetchone()
        if row and row["department"]:
            role = row["department"]
        c.execute(
            '''
            INSERT INTO user_profiles (email, role, behavioral_risk_score, failed_simulations_count, typical_topics)
            VALUES (?, ?, ?, ?, '')
            ON CONFLICT (email) DO UPDATE SET
                behavioral_risk_score = GREATEST(user_profiles.behavioral_risk_score, ?),
                failed_simulations_count = ?
            ''',
            (email, role, risk, n, risk, n),
        )
        updated += 1
    conn.commit()
    conn.close()
    return {"updated": updated, "repeat_clickers": sum(1 for n in fails.values() if n > 1)}


def learning_summary(organization_id: int) -> dict[str, Any]:
    conn = get_db_connection()
    c = conn.cursor()
    # False positives: quarantined then marked safe by an analyst.
    c.execute(
        "SELECT COUNT(*) FROM emails WHERE organization_id = ? AND status = 'Quarantined' AND review_status = 'Marked Safe'",
        (organization_id,),
    )
    false_positives = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM emails WHERE organization_id = ? AND review_status = 'Confirmed Phishing'", (organization_id,))
    confirmed = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM reputation WHERE organization_id = ? AND score >= ?", (organization_id, _MALICIOUS_AT))
    learned_bad = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM reputation WHERE organization_id = ? AND score <= ?", (organization_id, _TRUSTED_AT))
    learned_trusted = c.fetchone()[0]
    c.execute(
        "SELECT email, behavioral_risk_score, failed_simulations_count FROM user_profiles "
        "WHERE failed_simulations_count > 0 ORDER BY failed_simulations_count DESC, behavioral_risk_score DESC LIMIT 10"
    )
    repeat_clickers = [dict(r) for r in c.fetchall()]
    c.execute(
        "SELECT kind, value, score, confirmed_count, safe_count FROM reputation "
        "WHERE organization_id = ? ORDER BY ABS(score) DESC LIMIT 20",
        (organization_id,),
    )
    top_reputation = [dict(r) for r in c.fetchall()]
    conn.close()
    return {
        "false_positives": false_positives,
        "confirmed_phishing": confirmed,
        "learned_bad": learned_bad,
        "learned_trusted": learned_trusted,
        "repeat_clickers": repeat_clickers,
        "top_reputation": top_reputation,
    }
