"""
Threat-intelligence enrichment.

Matches extracted IOCs against a per-tenant blocklist/allowlist so the detector can
short-circuit known-bad senders/URLs and suppress known-good ones. Fully offline
(local DB); external feeds (VirusTotal/URLhaus/etc.) can be layered on later behind
the same `enrich` interface without changing callers.
"""
from __future__ import annotations

from typing import Any

from db import get_db_connection


def _norm(value: str) -> str:
    return (value or "").strip().lower()


def enrich(organization_id: int, iocs: list[dict[str, Any]], cursor=None) -> dict[str, Any]:
    """
    Return an intel verdict for a set of IOCs.

    Result:
      {
        "verdict": "block" | "allow" | "suspicious" | "unknown",
        "score": 0..100,            # risk contribution
        "matches": [ {type, value, verdict, source} ],
        "block": bool, "allow": bool,
      }
    """
    result = {"verdict": "unknown", "score": 0, "matches": [], "block": False, "allow": False}
    if not iocs:
        return result

    values = {_norm(i.get("value", "")) for i in iocs if i.get("value")}
    if not values:
        return result

    owns_conn = cursor is None
    conn = get_db_connection() if owns_conn else None
    c = conn.cursor() if owns_conn else cursor

    placeholders = ",".join(["?"] * len(values))
    c.execute(
        f'''
        SELECT id, type, value, verdict, source, confidence
        FROM intel_indicators
        WHERE organization_id = ?
          AND LOWER(value) IN ({placeholders})
          AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)
        ''',
        (organization_id, *values),
    )
    rows = [dict(r) for r in c.fetchall()]

    matched_ids = []
    for row in rows:
        verdict = (row["verdict"] or "block").lower()
        result["matches"].append({
            "type": row["type"], "value": row["value"],
            "verdict": verdict, "source": row["source"],
        })
        matched_ids.append(row["id"])
        if verdict == "block":
            result["block"] = True
            result["score"] = max(result["score"], int(row.get("confidence") or 90))
        elif verdict == "allow":
            result["allow"] = True
        elif verdict == "suspicious":
            result["score"] = max(result["score"], min(60, int(row.get("confidence") or 50)))

    if result["block"]:
        result["verdict"] = "block"
    elif result["allow"]:
        result["verdict"] = "allow"
    elif result["matches"]:
        result["verdict"] = "suspicious"

    # Count a hit on matched indicators for intel usefulness stats.
    if matched_ids:
        id_placeholders = ",".join(["?"] * len(matched_ids))
        c.execute(
            f"UPDATE intel_indicators SET hits = hits + 1 WHERE id IN ({id_placeholders})",
            tuple(matched_ids),
        )

    if owns_conn:
        conn.commit()
        conn.close()
    return result


def add_indicator(organization_id: int, indicator: dict[str, Any], cursor=None) -> int | None:
    """Upsert a single indicator. Returns its id (or None on conflict-noop)."""
    owns_conn = cursor is None
    conn = get_db_connection() if owns_conn else None
    c = conn.cursor() if owns_conn else cursor
    c.execute(
        '''
        INSERT INTO intel_indicators (organization_id, type, value, verdict, source, description, confidence, created_by)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT (organization_id, type, value) DO UPDATE SET
            verdict = excluded.verdict,
            source = excluded.source,
            description = excluded.description,
            confidence = excluded.confidence
        ''',
        (
            organization_id,
            _norm(indicator.get("type", "domain")),
            _norm(indicator.get("value", "")),
            (indicator.get("verdict") or "block").lower(),
            indicator.get("source", "manual"),
            indicator.get("description", ""),
            int(indicator.get("confidence", 80)),
            indicator.get("created_by", "system"),
        ),
    )
    new_id = c.lastrowid
    if owns_conn:
        conn.commit()
        conn.close()
    return new_id


def auto_block_iocs(organization_id: int, email_id: int, created_by: str = "analyst") -> int:
    """
    Promote all IOCs of a confirmed-phishing email into the blocklist.
    Returns the number of indicators added/updated.
    """
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT type, value FROM iocs WHERE email_id = ?", (email_id,))
    iocs = [dict(r) for r in c.fetchall()]
    count = 0
    for ioc in iocs:
        if ioc["type"] in ("url", "domain", "ip", "sha256", "md5", "email"):
            add_indicator(
                organization_id,
                {
                    "type": ioc["type"], "value": ioc["value"], "verdict": "block",
                    "source": f"confirmed-phishing:email#{email_id}", "confidence": 90,
                    "created_by": created_by,
                },
                cursor=c,
            )
            count += 1
    conn.commit()
    conn.close()
    return count
