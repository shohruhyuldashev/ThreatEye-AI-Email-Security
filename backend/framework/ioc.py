from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from urlextract import URLExtract

from db import get_db_connection


DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")
IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
HASH_RE = re.compile(r"\b(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b")


def extract_iocs(email_text: str, attachments: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    attachments = attachments or []
    extractor = URLExtract()
    urls = extractor.find_urls(email_text or "")
    iocs: list[dict[str, Any]] = []

    for url in urls:
        iocs.append({"type": "url", "value": url, "source": "body", "confidence": 85})

    for domain in DOMAIN_RE.findall(email_text or ""):
        if "@" not in domain:
            iocs.append({"type": "domain", "value": domain.lower(), "source": "body", "confidence": 70})

    for ip in IP_RE.findall(email_text or ""):
        iocs.append({"type": "ip", "value": ip, "source": "body", "confidence": 80})

    for email in EMAIL_RE.findall(email_text or ""):
        iocs.append({"type": "email", "value": email.lower(), "source": "body", "confidence": 75})

    for digest in HASH_RE.findall(email_text or ""):
        hash_type = {32: "md5", 40: "sha1", 64: "sha256"}.get(len(digest), "hash")
        iocs.append({"type": hash_type, "value": digest.lower(), "source": "body", "confidence": 90})

    for attachment in attachments:
        filename = str(attachment.get("filename", "")).strip()
        if filename:
            iocs.append({"type": "filename", "value": filename, "source": "attachment", "confidence": 65})
        payload = attachment.get("payload")
        if payload:
            if isinstance(payload, str):
                payload = payload.encode()
            iocs.append({"type": "sha256", "value": hashlib.sha256(payload).hexdigest(), "source": "attachment", "confidence": 95})

    return _dedupe(iocs)


def persist_iocs(email_id: int, iocs: list[dict[str, Any]], cursor=None):
    if not iocs:
        return
    conn = None
    if cursor is None:
        conn = get_db_connection()
        cursor = conn.cursor()
    for ioc in iocs:
        cursor.execute('''
            INSERT INTO iocs (email_id, type, value, source, confidence, tags_json)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(email_id, type, value) DO NOTHING
        ''', (
            email_id,
            ioc["type"],
            ioc["value"],
            ioc.get("source", "unknown"),
            int(ioc.get("confidence", 60)),
            json.dumps(ioc.get("tags", [])),
        ))
    if conn:
        conn.commit()
        conn.close()


def _dedupe(iocs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen = set()
    unique = []
    for ioc in iocs:
        key = (ioc["type"], ioc["value"])
        if key in seen:
            continue
        seen.add(key)
        unique.append(ioc)
    return unique
