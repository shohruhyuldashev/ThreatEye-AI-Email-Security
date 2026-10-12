"""
Server-side phishing-simulation registry.

When we launch a GoPhish simulation we record each (recipient, sender, subject,
body-fingerprint) here with an expiry. The IMAP watcher then recognises its OWN
simulation mail by matching against this registry — with NO marker written into
the email itself. So an attacker inspecting a received simulation cannot discover
any special header (there is none), cannot learn the mechanism exists, and cannot
forge a match without knowing the LLM-random subject + body of an active campaign.

A secret-named signed header (see security.sim_header_name / make_sim_token) is an
independent, hidden second layer checked by the watcher as well.
"""
from __future__ import annotations

import hashlib
import logging
import os

from db import get_db_connection

logger = logging.getLogger(__name__)

SIM_REGISTRY_TTL_SECONDS = int(os.getenv("SIM_REGISTRY_TTL_SECONDS", str(14 * 24 * 3600)))


def fingerprint(subject: str, body: str) -> str:
    return hashlib.sha256(((subject or "") + "\x00" + (body or "")).encode("utf-8", "ignore")).hexdigest()


def register_simulation(organization_id: int, recipient: str, sender: str,
                        subject: str, body: str = "") -> None:
    """Record one sent simulation so the watcher can recognise it later."""
    try:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute(
            "INSERT INTO sim_registry (organization_id, recipient, sender, subject, fingerprint, expires_at) "
            "VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP + (? || ' seconds')::interval)",
            (organization_id, (recipient or "").lower(), (sender or "").lower(),
             subject or "", fingerprint(subject, body), SIM_REGISTRY_TTL_SECONDS),
        )
        conn.commit()
        conn.close()
    except Exception as e:
        logger.warning("sim_registry insert failed: %s", e)


def is_simulation(recipient: str, subject: str, body: str = "") -> bool:
    """
    True if an incoming email matches a non-expired registered simulation. Matched
    on recipient + subject (tight: the subject is LLM-random), or on the body
    fingerprint. No attacker-visible data is involved.
    """
    try:
        conn = get_db_connection()
        c = conn.cursor()
        fp = fingerprint(subject, body)
        c.execute(
            "SELECT 1 FROM sim_registry "
            "WHERE (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP) "
            "AND ( (LOWER(recipient) = ? AND subject = ?) OR fingerprint = ? ) "
            "LIMIT 1",
            ((recipient or "").lower(), subject or "", fp),
        )
        hit = c.fetchone() is not None
        conn.close()
        return hit
    except Exception as e:
        logger.warning("sim_registry lookup failed: %s", e)
        return False


def purge_expired() -> int:
    try:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("DELETE FROM sim_registry WHERE expires_at IS NOT NULL AND expires_at < CURRENT_TIMESTAMP")
        n = c.rowcount or 0
        conn.commit()
        conn.close()
        return n
    except Exception:
        return 0
