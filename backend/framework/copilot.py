"""
AI SOC copilot.

Two capabilities, both grounded in the tenant's own data and offline-safe (a
structured fallback is returned when the LLM is unavailable):
  - `investigate_email`: an analyst-ready investigation narrative for one email.
  - `ask`: a natural-language Q&A over recent detections (read-only, tenant-scoped).
"""
from __future__ import annotations

import json
import re
from typing import Any

from db import get_db_connection
from framework.model_provider import get_llm_client, get_model_name

_TOKEN = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}|[A-Za-z0-9-]+\.[A-Za-z]{2,}")
_STOP = {"the", "and", "from", "with", "show", "list", "what", "which", "email", "emails",
         "this", "that", "have", "were", "past", "last", "week", "today", "give", "find", "any"}


def _llm_text(system: str, user: str) -> str | None:
    try:
        client = get_llm_client()
        resp = client.chat.completions.create(
            model=get_model_name(),
            messages=[{"role": "system", "content": system}, {"role": "user", "content": user}],
        )
        return (resp.choices[0].message.content or "").strip()
    except Exception:
        return None


# --------------------------------------------------------------------------- investigate
def investigate_email(organization_id: int, email_id: int) -> dict[str, Any]:
    conn = get_db_connection()
    c = conn.cursor()
    c.execute(
        "SELECT id, sender, subject, risk_score, url_threat_score, threat_type, status, "
        "confidence_score, recommended_action, ai_analysis_log, evidence_json, urls_found "
        "FROM emails WHERE id = ? AND organization_id = ?",
        (email_id, organization_id),
    )
    email = c.fetchone()
    if not email:
        conn.close()
        return {"error": "Email not found"}
    email = dict(email)

    c.execute("SELECT type, value, confidence FROM iocs WHERE email_id = ? LIMIT 30", (email_id,))
    iocs = [dict(r) for r in c.fetchall()]
    c.execute("SELECT technique_id, technique, tactic FROM mitre_mappings WHERE email_id = ?", (email_id,))
    mitre = [dict(r) for r in c.fetchall()]
    c.execute("SELECT event_type, details, created_at FROM email_timeline WHERE email_id = ? ORDER BY id ASC", (email_id,))
    timeline = [dict(r) for r in c.fetchall()]
    c.execute("SELECT filename, verdict, risk_score FROM attachments WHERE email_id = ?", (email_id,))
    attachments = [dict(r) for r in c.fetchall()]
    conn.close()

    try:
        evidence = json.loads(email.get("evidence_json") or "{}")
    except Exception:
        evidence = {}

    context = {
        "email": {k: email.get(k) for k in ("sender", "subject", "risk_score", "threat_type", "status", "confidence_score", "recommended_action")},
        "signals": evidence.get("signals", []),
        "iocs": iocs,
        "mitre": mitre,
        "attachments": attachments,
        "timeline": [f"{t['event_type']}: {t['details']}" for t in timeline],
    }

    system = ("You are a senior SOC analyst. Write a concise investigation for the email below using ONLY the "
              "provided evidence. Structure: Verdict, Why (key signals), Impact, Recommended next steps. Do not invent facts.")
    narrative = _llm_text(system, json.dumps(context, indent=2, default=str))

    if not narrative:
        # Deterministic fallback.
        lines = [
            f"Verdict: {email.get('threat_type', 'Unknown')} — risk {email.get('risk_score', 0)}/100 ({email.get('status')}).",
            f"Sender: {email.get('sender')} · Subject: {email.get('subject')}",
        ]
        if context["signals"]:
            lines.append("Key signals: " + "; ".join(str(s) for s in context["signals"][:6]))
        if iocs:
            lines.append("IOCs: " + ", ".join(f"{i['type']}:{i['value']}" for i in iocs[:6]))
        if mitre:
            lines.append("ATT&CK: " + ", ".join(f"{m['technique_id']} {m['technique']}" for m in mitre))
        if attachments:
            lines.append("Attachments: " + ", ".join(f"{a['filename']} ({a['verdict']})" for a in attachments))
        lines.append(f"Recommended: {email.get('recommended_action') or 'Review and contain if confirmed.'}")
        narrative = "\n".join(lines)

    return {"email_id": email_id, "narrative": narrative, "context": context, "llm": bool(narrative)}


# --------------------------------------------------------------------------- ask
def _search_term(question: str) -> str | None:
    m = _TOKEN.search(question or "")
    if m:
        return m.group(0).lower()
    words = [w.lower() for w in re.findall(r"[A-Za-z]{4,}", question or "") if w.lower() not in _STOP]
    return words[0] if words else None


def _gather_context(organization_id: int, question: str) -> dict[str, Any]:
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM emails WHERE organization_id = ?", (organization_id,))
    total = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM emails WHERE organization_id = ? AND status = 'Quarantined'", (organization_id,))
    quarantined = c.fetchone()[0]
    c.execute(
        "SELECT sender, subject, risk_score, threat_type, status FROM emails "
        "WHERE organization_id = ? ORDER BY risk_score DESC, timestamp DESC LIMIT 8",
        (organization_id,),
    )
    top = [dict(r) for r in c.fetchall()]

    term = _search_term(question)
    matches = []
    if term:
        like = f"%{term}%"
        c.execute(
            "SELECT sender, subject, risk_score, threat_type, status, timestamp FROM emails "
            "WHERE organization_id = ? AND (LOWER(sender) LIKE ? OR LOWER(subject) LIKE ?) "
            "ORDER BY timestamp DESC LIMIT 12",
            (organization_id, like, like),
        )
        matches = [dict(r) for r in c.fetchall()]
    conn.close()
    return {"totals": {"emails": total, "quarantined": quarantined}, "top_risk": top, "search_term": term, "matches": matches}


def ask(organization_id: int, question: str) -> dict[str, Any]:
    context = _gather_context(organization_id, question)
    system = ("You are a SOC assistant for an email-security platform. Answer the user's question using ONLY the JSON "
              "context (counts and email records for this tenant). Be concise. If the context lacks the answer, say so "
              "and suggest what to look at. Never invent emails or numbers.")
    user = f"Question: {question}\n\nContext:\n{json.dumps(context, indent=2, default=str)}"
    answer = _llm_text(system, user)

    if not answer:
        t = context["totals"]
        parts = [f"{t['emails']} emails analysed, {t['quarantined']} quarantined for this tenant."]
        if context["matches"]:
            parts.append(f"{len(context['matches'])} match '{context['search_term']}':")
            parts += [f"- {m['subject']} — {m['sender']} ({m['risk_score']}%, {m['status']})" for m in context["matches"][:6]]
        elif context["search_term"]:
            parts.append(f"No emails matched '{context['search_term']}'.")
        answer = "\n".join(parts)

    return {"answer": answer, "matches": context["matches"], "search_term": context["search_term"]}
