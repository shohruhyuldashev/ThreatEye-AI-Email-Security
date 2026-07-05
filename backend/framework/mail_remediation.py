"""
Real mailbox clawback connectors (Microsoft 365 Graph + Google Workspace).

Both are best-effort and offline-safe: if the provider isn't configured, the
caller records the clawback intent instead. Credentials come from Settings.

M365 (app-only, client credentials) — requires a Graph app with `Mail.ReadWrite`
application permission + admin consent. Config keys:
  m365_tenant_id, m365_client_id, m365_client_secret, m365_mailboxes (comma list)

Google Workspace (service account w/ domain-wide delegation, scope
gmail.modify) — config keys:
  google_sa_json (the service-account JSON), google_mailboxes (comma list)
"""
from __future__ import annotations

import json
import logging
from typing import Any

import requests

logger = logging.getLogger(__name__)

GRAPH = "https://graph.microsoft.com/v1.0"


# ----------------------------------------------------------------- Microsoft 365
def _m365_token(cfg: dict) -> str | None:
    tenant = cfg.get("m365_tenant_id")
    client_id = cfg.get("m365_client_id")
    secret = cfg.get("m365_client_secret")
    if not (tenant and client_id and secret):
        return None
    try:
        resp = requests.post(
            f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token",
            data={
                "client_id": client_id,
                "client_secret": secret,
                "scope": "https://graph.microsoft.com/.default",
                "grant_type": "client_credentials",
            },
            timeout=8,
        )
        if resp.ok:
            return resp.json().get("access_token")
        logger.warning(f"M365 token error: {resp.status_code} {resp.text[:200]}")
    except Exception as e:
        logger.warning(f"M365 token exception: {e}")
    return None


def m365_clawback(cfg: dict, sender: str, subject: str) -> dict[str, Any] | None:
    """Soft-delete matching messages across the configured mailboxes. None if not configured."""
    mailboxes = [m.strip() for m in (cfg.get("m365_mailboxes") or "").split(",") if m.strip()]
    if not mailboxes:
        return None
    token = _m365_token(cfg)
    if not token:
        return {"provider": "m365", "status": "failed", "detail": "auth failed / not configured"}

    headers = {"Authorization": f"Bearer {token}"}
    removed = 0
    errors = 0
    # $search needs ConsistencyLevel: eventual.
    search_headers = {**headers, "ConsistencyLevel": "eventual"}
    query = subject.replace('"', "").strip()[:120]
    for mbx in mailboxes:
        try:
            r = requests.get(
                f"{GRAPH}/users/{mbx}/messages",
                headers=search_headers,
                params={"$search": f'"subject:{query}"', "$top": 25, "$select": "id,from,subject"},
                timeout=10,
            )
            if not r.ok:
                errors += 1
                continue
            for msg in r.json().get("value", []):
                addr = (((msg.get("from") or {}).get("emailAddress") or {}).get("address") or "").lower()
                if sender and sender.lower() not in addr:
                    continue
                d = requests.delete(f"{GRAPH}/users/{mbx}/messages/{msg['id']}", headers=headers, timeout=10)
                if d.ok:
                    removed += 1
                else:
                    errors += 1
        except Exception as e:
            logger.warning(f"M365 clawback error for {mbx}: {e}")
            errors += 1
    status = "sent" if removed and not errors else ("partial" if removed else "failed")
    return {"provider": "m365", "status": status, "removed": removed, "errors": errors, "mailboxes": len(mailboxes)}


# ----------------------------------------------------------------- Google Workspace
def google_clawback(cfg: dict, sender: str, subject: str) -> dict[str, Any] | None:
    """Trash matching messages across the configured Gmail mailboxes. None if not configured."""
    sa_json = cfg.get("google_sa_json")
    mailboxes = [m.strip() for m in (cfg.get("google_mailboxes") or "").split(",") if m.strip()]
    if not (sa_json and mailboxes):
        return None
    try:
        from google.oauth2 import service_account  # type: ignore
        from googleapiclient.discovery import build  # type: ignore
    except Exception:
        return {"provider": "google", "status": "failed", "detail": "google client libraries not installed"}

    try:
        info = json.loads(sa_json) if isinstance(sa_json, str) else sa_json
    except Exception:
        return {"provider": "google", "status": "failed", "detail": "invalid service-account JSON"}

    removed = 0
    errors = 0
    q = f'from:{sender} subject:"{subject[:120]}"' if sender else f'subject:"{subject[:120]}"'
    for mbx in mailboxes:
        try:
            creds = service_account.Credentials.from_service_account_info(
                info, scopes=["https://www.googleapis.com/auth/gmail.modify"], subject=mbx,
            )
            svc = build("gmail", "v1", credentials=creds, cache_discovery=False)
            listing = svc.users().messages().list(userId="me", q=q, maxResults=25).execute()
            for m in listing.get("messages", []):
                svc.users().messages().trash(userId="me", id=m["id"]).execute()
                removed += 1
        except Exception as e:
            logger.warning(f"Google clawback error for {mbx}: {e}")
            errors += 1
    status = "sent" if removed and not errors else ("partial" if removed else "failed")
    return {"provider": "google", "status": status, "removed": removed, "errors": errors, "mailboxes": len(mailboxes)}


def clawback(cfg: dict, sender: str, subject: str) -> dict[str, Any] | None:
    """Try each configured provider in turn. Returns None if none are configured."""
    for fn in (m365_clawback, google_clawback):
        result = fn(cfg, sender, subject)
        if result is not None:
            return result
    return None
