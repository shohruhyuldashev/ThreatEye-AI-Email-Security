"""
Cloud mail connectors — ingest and protect mailboxes on Microsoft 365 and Google
Workspace, not just IMAP. Each connector polls the configured mailboxes for new
mail, routes every message through the SAME detection pipeline as the IMAP watcher
(services.ingest.persist_detection), and quarantines phishing in place.

Config (Settings → Integrations, encrypted at rest):
  Microsoft 365 : m365_tenant_id, m365_client_id, m365_client_secret, m365_mailboxes
                  (app registration with Mail.Read / Mail.ReadWrite application perms)
  Google        : google_sa_json (service account with domain-wide delegation,
                  scope https://www.googleapis.com/auth/gmail.modify), google_mailboxes

Both are OPTIONAL and OAuth/TLS only. If a connector is not configured it is a no-op.
Runs inside the single-watcher process (same lock as the IMAP watcher), so mail is
never double-processed.
"""
from __future__ import annotations

import base64
import json
import logging
import os
import re
import time
from datetime import datetime, timezone

import requests

from db import get_db_connection
from services.ingest import persist_detection

logger = logging.getLogger(__name__)

GRAPH = "https://graph.microsoft.com/v1.0"
QUARANTINE_LABEL = "ThreatEye Quarantine"


# ----------------------------------------------------------------- shared helpers
def _load_cfg(keys: tuple) -> dict:
    from framework.secretbox import decrypt_setting
    conn = get_db_connection()
    try:
        c = conn.cursor()
        ph = ",".join(["?"] * len(keys))
        c.execute(f"SELECT key, value FROM settings WHERE key IN ({ph})", keys)
        return {row["key"]: decrypt_setting(row["key"], row["value"]) for row in c.fetchall()}
    finally:
        conn.close()


def _already_seen(message_id: str) -> bool:
    if not message_id:
        return False
    conn = get_db_connection()
    try:
        c = conn.cursor()
        c.execute("SELECT 1 FROM mail_seen WHERE message_id = ?", (message_id,))
        return c.fetchone() is not None
    finally:
        conn.close()


def _mark_seen(message_id: str, source: str) -> None:
    if not message_id:
        return
    conn = get_db_connection()
    try:
        c = conn.cursor()
        c.execute("INSERT INTO mail_seen (message_id, source) VALUES (?, ?) "
                  "ON CONFLICT (message_id) DO NOTHING", (message_id, source))
        conn.commit()
    finally:
        conn.close()


def _auth_from_headers(headers: dict) -> dict:
    """Derive SPF/DKIM/DMARC + reply-to mismatch from raw header lines."""
    ar = " ".join(str(v) for k, v in headers.items()
                  if k.lower() in ("authentication-results", "received-spf", "arc-authentication-results"))
    low = ar.lower()

    def verdict(mech):
        m = re.search(mech + r"=(pass|fail|softfail|neutral|none|temperror|permerror)", low)
        if not m:
            return "unknown"
        return "pass" if m.group(1) == "pass" else ("fail" if m.group(1) in ("fail", "softfail") else "unknown")

    return {"spf": verdict("spf"), "dkim": verdict("dkim"), "dmarc": verdict("dmarc")}


def _route(org: int, source: str, message_id: str, sender: str, recipient: str,
           subject: str, body: str, headers: dict, quarantine_cb=None) -> None:
    """Dedup, detect, persist, and quarantine one message. Shared by all connectors."""
    if _already_seen(message_id):
        return
    # Skip our own signed phishing simulations (same rule as the IMAP watcher).
    try:
        from framework.security import verify_sim_token, sim_header_name
        from framework.sim_registry import is_simulation
        sig = headers.get(sim_header_name().lower()) or headers.get(sim_header_name())
        if sig and verify_sim_token(sig) and is_simulation(recipient, subject, body):
            _mark_seen(message_id, source)
            return
    except Exception:
        pass

    from services.ai_detector import analyze_email_hybrid
    metadata = _auth_from_headers(headers)
    metadata.update({"sender": sender, "subject": subject,
                     "reply_to": headers.get("reply-to", "") or headers.get("Reply-To", "")})
    content = f"Subject: {subject}\nBody: {body}"
    try:
        analysis = analyze_email_hybrid(content, metadata)
    except Exception as e:
        logger.error("%s detection failed for %s: %s", source, message_id, e)
        return

    conn = get_db_connection()
    try:
        c = conn.cursor()
        result = persist_detection(
            c, organization_id=org, sender=sender, subject=subject, recipient=recipient,
            content=content, analysis=analysis, attachments=[], source=source,
        )
        conn.commit()
    finally:
        conn.close()

    _mark_seen(message_id, source)
    if result.get("is_threat") and quarantine_cb:
        try:
            quarantine_cb()
            logger.warning("%s: quarantined phishing '%s' (score %s)", source, subject, result.get("phishing_score"))
        except Exception as e:
            logger.error("%s quarantine move failed: %s", source, e)


# ----------------------------------------------------------------- Microsoft 365
def _m365_token(cfg: dict) -> str | None:
    tenant, cid, secret = cfg.get("m365_tenant_id"), cfg.get("m365_client_id"), cfg.get("m365_client_secret")
    if not (tenant and cid and secret):
        return None
    try:
        r = requests.post(
            f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token",
            data={"client_id": cid, "client_secret": secret,
                  "scope": "https://graph.microsoft.com/.default", "grant_type": "client_credentials"},
            timeout=10)
        return r.json().get("access_token") if r.ok else None
    except Exception as e:
        logger.warning("M365 token error: %s", type(e).__name__)  # nosemgrep
        return None


def _m365_ensure_folder(token: str, mbx: str) -> str | None:
    """Find or create the quarantine mail folder; return its id."""
    h = {"Authorization": f"Bearer {token}"}
    try:
        r = requests.get(f"{GRAPH}/users/{mbx}/mailFolders", headers=h,
                         params={"$filter": f"displayName eq '{QUARANTINE_LABEL}'"}, timeout=10)
        vals = r.json().get("value", []) if r.ok else []
        if vals:
            return vals[0]["id"]
        r = requests.post(f"{GRAPH}/users/{mbx}/mailFolders", headers={**h, "Content-Type": "application/json"},
                          json={"displayName": QUARANTINE_LABEL}, timeout=10)
        return r.json().get("id") if r.ok else None
    except Exception:
        return None


def poll_m365_once() -> int:
    cfg = _load_cfg(("m365_tenant_id", "m365_client_id", "m365_client_secret", "m365_mailboxes"))
    mailboxes = [m.strip() for m in (cfg.get("m365_mailboxes") or "").split(",") if m.strip()]
    if not mailboxes:
        return 0
    token = _m365_token(cfg)
    if not token:
        logger.warning("M365 mailboxes configured but token acquisition failed.")
        return 0
    h = {"Authorization": f"Bearer {token}"}
    processed = 0
    for mbx in mailboxes:
        folder_id = _m365_ensure_folder(token, mbx)
        try:
            r = requests.get(
                f"{GRAPH}/users/{mbx}/mailFolders/inbox/messages", headers=h,
                params={"$top": 25, "$orderby": "receivedDateTime desc",
                        "$select": "id,subject,from,toRecipients,bodyPreview,body,internetMessageHeaders"},
                timeout=20)
            if not r.ok:
                logger.warning("M365 fetch %s: HTTP %s", mbx, r.status_code)
                continue
            for msg in r.json().get("value", []):
                mid = msg.get("id")
                sender = (((msg.get("from") or {}).get("emailAddress") or {}).get("address") or "")
                subject = msg.get("subject") or ""
                body = ((msg.get("body") or {}).get("content")) or msg.get("bodyPreview") or ""
                headers = {hd.get("name", "").lower(): hd.get("value", "")
                           for hd in (msg.get("internetMessageHeaders") or [])}

                def _quarantine(_mbx=mbx, _mid=mid, _fid=folder_id):
                    if _fid:
                        requests.post(f"{GRAPH}/users/{_mbx}/messages/{_mid}/move",
                                      headers={**h, "Content-Type": "application/json"},
                                      json={"destinationId": _fid}, timeout=10)

                _route(1, "m365", mid, sender, mbx, subject, body, headers,
                       quarantine_cb=_quarantine if folder_id else None)
                processed += 1
        except Exception as e:
            logger.error("M365 poll error for %s: %s", mbx, e)
    return processed


# ----------------------------------------------------------------- Google Workspace
def _gmail_service(cfg: dict, user: str):
    raw = cfg.get("google_sa_json")
    if not raw:
        return None
    try:
        from google.oauth2 import service_account
        from googleapiclient.discovery import build
        info = json.loads(raw)
        creds = service_account.Credentials.from_service_account_info(
            info, scopes=["https://www.googleapis.com/auth/gmail.modify"]).with_subject(user)
        return build("gmail", "v1", credentials=creds, cache_discovery=False)
    except Exception as e:
        logger.warning("Gmail service build failed for %s: %s", user, e)
        return None


def poll_gmail_once() -> int:
    cfg = _load_cfg(("google_sa_json", "google_mailboxes"))
    mailboxes = [m.strip() for m in (cfg.get("google_mailboxes") or "").split(",") if m.strip()]
    if not mailboxes or not cfg.get("google_sa_json"):
        return 0
    processed = 0
    for user in mailboxes:
        svc = _gmail_service(cfg, user)
        if not svc:
            continue
        try:
            resp = svc.users().messages().list(userId="me", q="newer_than:1d in:inbox", maxResults=25).execute()
            for ref in resp.get("messages", []):
                mid = ref["id"]
                if _already_seen(mid):
                    continue
                full = svc.users().messages().get(userId="me", id=mid, format="full").execute()
                payload = full.get("payload", {})
                headers = {h["name"].lower(): h["value"] for h in payload.get("headers", [])}
                sender = re.sub(r".*<|>.*", "", headers.get("from", "")) or headers.get("from", "")
                subject = headers.get("subject", "")
                body = _gmail_body(payload)

                def _quarantine(_svc=svc, _mid=mid):
                    _svc.users().messages().modify(
                        userId="me", id=_mid,
                        body={"addLabelIds": ["SPAM"], "removeLabelIds": ["INBOX"]}).execute()

                _route(1, "gmail", mid, sender, user, subject, body, headers, quarantine_cb=_quarantine)
                processed += 1
        except Exception as e:
            logger.error("Gmail poll error for %s: %s", user, e)
    return processed


def _gmail_body(payload: dict) -> str:
    def _decode(data):
        try:
            return base64.urlsafe_b64decode(data.encode()).decode("utf-8", "ignore")
        except Exception:
            return ""
    if payload.get("body", {}).get("data"):
        return _decode(payload["body"]["data"])
    for part in payload.get("parts", []) or []:
        if part.get("mimeType", "").startswith("text/") and part.get("body", {}).get("data"):
            return _decode(part["body"]["data"])
        inner = _gmail_body(part)
        if inner:
            return inner
    return ""


# ----------------------------------------------------------------- runner
def run_mail_connectors():
    """Poll the cloud mail connectors on an interval (no-op until configured)."""
    interval = int(os.getenv("MAIL_CONNECTOR_POLL_SECONDS", "60"))
    logger.info("Cloud mail connectors (M365/Gmail) polling every %ss.", interval)
    while True:
        try:
            n = poll_m365_once() + poll_gmail_once()
            if n:
                logger.info("Cloud connectors processed %s message(s).", n)
        except Exception as e:
            logger.error("Mail connector cycle error: %s", e)
        time.sleep(interval)
