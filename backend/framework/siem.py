"""
SIEM alert forwarding.

The destination + auth are configured from the SOC panel (Settings → SIEM) and
stored in the `settings` table, falling back to environment variables. Auth is
flexible enough for the common SIEMs:

  - Splunk HEC:   header=Authorization, prefix="Splunk "
  - Elastic:      header=Authorization, prefix="ApiKey "
  - Datadog:      header=DD-API-KEY,    prefix=""
  - Generic:      header=Authorization, prefix="Bearer "

Every attempt is recorded in `siem_events` so the SOC panel can show delivery status.
"""
from __future__ import annotations

import json
import logging
import os
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import requests

from db import get_db_connection
from framework.siem_formats import format_event

logger = logging.getLogger(__name__)

# Alerts are dispatched in the background so a slow/down SIEM never blocks email
# ingestion, and transient failures are retried with backoff.
_executor = ThreadPoolExecutor(max_workers=int(os.getenv("SIEM_WORKERS", "4")), thread_name_prefix="siem")
SIEM_RETRIES = int(os.getenv("SIEM_RETRIES", "3"))

_SIEM_KEYS = (
    "siem_webhook_url", "siem_api_key", "siem_auth_header", "siem_auth_prefix", "siem_format",
    "siem_min_score",
)


def siem_config() -> dict[str, str]:
    """Resolve SIEM settings from the DB, falling back to environment."""
    settings: dict[str, str] = {}
    try:
        conn = get_db_connection()
        c = conn.cursor()
        placeholders = ",".join(["?"] * len(_SIEM_KEYS))
        c.execute(f"SELECT key, value FROM settings WHERE key IN ({placeholders})", _SIEM_KEYS)
        settings = {row["key"]: row["value"] for row in c.fetchall()}
        conn.close()
    except Exception:
        pass
    return {
        "webhook_url": (settings.get("siem_webhook_url") or os.getenv("SIEM_WEBHOOK_URL", "")).strip(),
        "api_key": settings.get("siem_api_key") or os.getenv("SIEM_API_KEY", ""),
        "auth_header": (settings.get("siem_auth_header") or os.getenv("SIEM_AUTH_HEADER", "Authorization")).strip(),
        "auth_prefix": settings.get("siem_auth_prefix") if settings.get("siem_auth_prefix") is not None
        else os.getenv("SIEM_AUTH_PREFIX", "Bearer "),
        "format": (settings.get("siem_format") or os.getenv("SIEM_FORMAT", "raw")).lower(),
        "min_score": _int(settings.get("siem_min_score") or os.getenv("SIEM_MIN_SCORE", "40"), 40),
    }


def _int(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def siem_min_score() -> int:
    """
    Lowest risk score that is still worth forwarding. Emails at or above the
    quarantine threshold always go; this covers the band below it, so
    "suspicious but delivered" mail is visible to the SOC instead of invisible.
    """
    return siem_config()["min_score"]


def _auth_headers(cfg: dict[str, str]) -> dict[str, str]:
    headers = {"Content-Type": "application/json"}
    if cfg.get("api_key") and cfg.get("auth_header"):
        headers[cfg["auth_header"]] = f"{cfg.get('auth_prefix', '')}{cfg['api_key']}"
    return headers


def send_to_siem(event_type: str, payload: dict[str, Any], cfg: dict[str, str] | None = None) -> dict[str, Any]:
    """POST a single formatted event to the configured SIEM. Does not log to the DB."""
    cfg = cfg or siem_config()
    body = format_event(cfg.get("format", "raw"), event_type, payload)
    if not cfg.get("webhook_url"):
        return {"status": "skipped", "response_code": None, "error": "No SIEM webhook configured", "destination": "not_configured"}
    try:
        resp = requests.post(cfg["webhook_url"], json=body, headers=_auth_headers(cfg), timeout=6)
        status = "sent" if 200 <= resp.status_code < 300 else "failed"
        return {
            "status": status,
            "response_code": resp.status_code,
            "error": "" if status == "sent" else resp.text[:500],
            "destination": cfg["webhook_url"],
        }
    except Exception as exc:
        return {"status": "failed", "response_code": None, "error": str(exc), "destination": cfg["webhook_url"]}


def _deliver_with_retry(event_type: str, payload: dict[str, Any]) -> None:
    """Runs in a background thread: POST to the SIEM (retrying transient failures), then log."""
    cfg = siem_config()
    if not cfg.get("webhook_url"):
        result = {"status": "skipped", "response_code": None, "error": "No SIEM webhook configured", "destination": "not_configured"}
    else:
        result = {"status": "failed", "response_code": None, "error": "no attempt", "destination": cfg["webhook_url"]}
        for attempt in range(1, SIEM_RETRIES + 1):
            result = send_to_siem(event_type, payload, cfg)
            if result["status"] == "sent":
                break
            if attempt < SIEM_RETRIES:
                time.sleep(min(2 ** (attempt - 1), 8))  # 1s, 2s, 4s… backoff
                logger.warning("SIEM delivery attempt %d/%d failed (%s); retrying", attempt, SIEM_RETRIES, result.get("error"))

    try:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute('''
            INSERT INTO siem_events (event_type, payload_json, destination, status, response_code, error, organization_id)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (event_type, json.dumps(payload), result.get("destination", "not_configured"),
              result["status"], result.get("response_code"), result.get("error", ""),
              int(payload.get("organization_id", 1) or 1)))
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error("Failed to record SIEM event: %s", e)


def replay_failed(limit: int = 50) -> dict[str, Any]:
    """
    Re-dispatch alerts whose delivery ultimately failed (SIEM was down, network
    blip, bad token). Without this a failed alert is logged and then lost, which
    is exactly the alert you least want to lose. Replayed rows are marked so a
    second call doesn't send them twice; a fresh failure lands as a new row and
    stays replayable.
    """
    try:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute(
            "SELECT id, event_type, payload_json FROM siem_events "
            "WHERE status = 'failed' ORDER BY id DESC LIMIT ?",
            (limit,),
        )
        rows = c.fetchall()
    except Exception as e:
        logger.error("SIEM replay query failed: %s", e)
        return {"replayed": 0, "error": str(e)}

    replayed, skipped = 0, 0
    for row in rows:
        try:
            payload = json.loads(row["payload_json"])
        except Exception:
            skipped += 1
            continue
        export_siem_event(row["event_type"], payload)
        c.execute("UPDATE siem_events SET status = 'replayed' WHERE id = ?", (row["id"],))
        replayed += 1

    try:
        conn.commit()
        conn.close()
    except Exception:
        pass
    return {"replayed": replayed, "skipped": skipped}


def export_siem_event(event_type: str, payload: dict[str, Any]) -> dict[str, Any]:
    """
    Forward an alert to the SIEM in real time. Dispatched to a background worker so
    it never blocks ingestion; the worker retries transient failures with backoff
    and records the outcome in `siem_events`.
    """
    try:
        _executor.submit(_deliver_with_retry, event_type, dict(payload))
        return {"status": "dispatched"}
    except Exception as e:
        # Never let SIEM forwarding break ingestion.
        logger.error("SIEM dispatch failed: %s", e)
        return {"status": "failed", "error": str(e)}
