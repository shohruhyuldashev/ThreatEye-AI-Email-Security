"""
Phishing-technique corpus: matching + prompt grounding.

`data/phishing_corpus.json` holds ~1200 concrete phishing patterns, each anchored on a
real MITRE ATT&CK technique and described along five axes (lure, brand, evasion,
delivery, target role). This module turns that library into two things the detector
can actually use:

  1. **Deterministic matching** — score an email against the corpus without asking the
     model anything. A lure pretext plus an impersonated brand plus an observed evasion
     is a named, pre-rated technique, so this keeps working when the LLM is slow, wrong
     or offline.
  2. **Prompt grounding** — the top matches are injected into the analyst prompt, so the
     model reasons about *this* pattern with its known severity instead of guessing from
     scratch.

The corpus is loaded once and indexed by (lure, brand, evasion); matching is dictionary
lookups over a handful of detected tokens, not a scan of 1200 entries.
"""
from __future__ import annotations

import json
import logging
import os
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Mounted into the backend container; falls back to the repo layout for local runs.
CORPUS_PATHS = [
    os.getenv("PHISH_CORPUS_PATH", ""),
    "/data/phishing_corpus.json",
    str(Path(__file__).resolve().parents[2] / "data" / "phishing_corpus.json"),
]

# Pretext -> the words that actually appear in a message using it. Kept here rather
# than in the corpus file because this is detection logic, not knowledge.
LURE_KEYWORDS: dict[str, list[str]] = {
    "password_expiry": ["password expire", "password will expire", "reset your password", "password reset", "re-enter your password", "credentials expire"],
    "mfa_reenrollment": ["re-enroll", "reenroll", "re-register", "mfa", "two-factor", "2fa", "authenticator"],
    "mfa_fatigue": ["approve the request", "approve this sign-in", "authentication request", "push notification"],
    "security_alert": ["unusual sign-in", "suspicious sign-in", "unusual activity", "account locked", "account suspended", "security alert", "unauthorized access"],
    "storage_quota": ["mailbox full", "storage full", "quota exceeded", "out of space", "storage limit"],
    "shared_document": ["shared a document", "shared a file", "has shared", "view document", "shared folder"],
    "esign_request": ["signature required", "sign the document", "awaiting your signature", "please sign", "esign", "e-sign"],
    "contract_review": ["contract", "nda", "agreement attached", "for your review"],
    "invoice_due": ["invoice", "overdue", "unpaid", "past due", "outstanding balance", "remittance"],
    "purchase_order": ["purchase order", "p.o.", "order confirmation"],
    "vendor_bank_change": ["bank details", "banking details", "change of bank", "new account details", "update payment details", "remittance details"],
    "wire_transfer": ["wire transfer", "wire the", "urgent payment", "transfer funds", "process this payment"],
    "gift_card": ["gift card", "gift cards", "itunes card", "steam card"],
    "payroll_change": ["direct deposit", "payroll", "salary account", "update your bank"],
    "benefits_enrollment": ["open enrollment", "benefits enrollment", "enrollment deadline"],
    "hr_policy": ["new policy", "policy update", "acknowledge the policy", "employee handbook"],
    "performance_review": ["performance review", "your review is ready", "appraisal"],
    "tax_document": ["w-2", "w2", "tax form", "tax document", "1099"],
    "package_delivery": ["delivery failed", "package could not", "reschedule delivery", "parcel", "shipment", "tracking number"],
    "customs_fee": ["customs", "duty payment", "import fee", "clearance fee"],
    "helpdesk_ticket": ["ticket #", "helpdesk", "service desk", "support ticket", "it request"],
    "vpn_reset": ["vpn", "remote access", "anyconnect"],
    "software_update": ["update required", "install the update", "new version available", "upgrade your"],
    "voicemail": ["voicemail", "voice message", "missed call"],
    "missed_meeting": ["missed meeting", "you missed", "join the meeting", "meeting recording"],
    "calendar_invite": ["calendar invite", "meeting invitation", "accept the invite"],
    "job_offer": ["job opportunity", "recruiter", "career opportunity", "your resume", "job offer"],
    "subscription_renewal": ["subscription", "auto-renew", "renewal", "will be charged", "cancel your"],
    "legal_subpoena": ["subpoena", "legal notice", "court", "lawsuit", "litigation"],
    "bonus_announcement": ["bonus", "salary adjustment", "raise", "incentive payment"],
    "printer_scan": ["scanned document", "scan from", "document scanned", "printer", "scanner"],
    "expense_report": ["expense report", "expense claim", "reimbursement"],
    "cloud_bill": ["payment failed", "billing", "payment method", "invoice unpaid", "service will be suspended"],
    "domain_renewal": ["domain expire", "domain renewal", "ssl certificate", "certificate expire"],
    "repo_security_alert": ["security alert", "vulnerability", "repository", "dependency", "commit"],
    "banking_otp": ["one-time code", "otp", "verification code", "security code"],
    "refund_notice": ["refund", "you are owed", "claim your", "overpayment"],
    "insurance_claim": ["insurance", "claim", "coverage", "policy number"],
    "survey_request": ["survey", "questionnaire", "feedback form"],
    "conference_invite": ["conference", "webinar", "register for", "event invitation"],
}

# Brand -> tokens that betray impersonation, in the sender domain, body or URLs.
BRAND_TOKENS: dict[str, list[str]] = {
    "microsoft365": ["microsoft", "office365", "office 365", "o365", "m365", "microsoft 365"],
    "outlook": ["outlook"], "google": ["google", "gmail", "g suite", "workspace"],
    "okta": ["okta"], "duo": ["duo security"], "sharepoint": ["sharepoint"],
    "onedrive": ["onedrive", "one drive"], "dropbox": ["dropbox"],
    "docusign": ["docusign", "docu sign"], "adobe": ["adobe", "acrobat"],
    "quickbooks": ["quickbooks", "intuit"], "sage": ["sage"],
    "workday": ["workday"], "adp": ["adp"], "irs": ["irs", "hmrc", "tax office"],
    "dhl": ["dhl"], "fedex": ["fedex"], "ups": ["ups "], "usps": ["usps"],
    "cisco": ["cisco", "anyconnect"], "zoom": ["zoom"], "teams": ["microsoft teams", "ms teams"],
    "linkedin": ["linkedin"], "paypal": ["paypal"], "netflix": ["netflix"], "apple": ["apple", "icloud"],
    "xerox": ["xerox", "printer", "scanner"], "concur": ["concur"],
    "aws": ["aws", "amazon web services"], "azure": ["azure"], "godaddy": ["godaddy"],
    "github": ["github"], "gitlab": ["gitlab"], "chase": ["chase bank", "chase"], "hsbc": ["hsbc"],
}


# Pretexts where the request itself is the fraud, independent of any brand or
# technical evasion — the BEC family. These match on the pretext alone.
HIGH_VALUE_LURES = {
    "vendor_bank_change", "wire_transfer", "payroll_change", "gift_card", "banking_otp",
}
# Deliberately below the quarantine bar: on its own this is "verify out of band",
# not "block". The detector escalates it when authentication also fails.
HIGH_VALUE_BASE_SCORE = 65


@lru_cache(maxsize=1)
def load_corpus() -> dict[str, Any]:
    """Load and index the corpus once. Returns an empty index if the file is absent."""
    for path in CORPUS_PATHS:
        if path and os.path.exists(path):
            try:
                data = json.load(open(path))
            except Exception as e:
                logger.error("phish corpus at %s is unreadable: %s", path, e)
                continue
            index: dict[tuple[str, str, str], dict] = {}
            by_lure: dict[str, list[dict]] = {}
            for t in data.get("techniques", []):
                index[(t["lure"], t["brand"], t["evasion"])] = t
                by_lure.setdefault(t["lure"], []).append(t)
            logger.info("phish corpus loaded: %d techniques from %s", len(index), path)
            return {"path": path, "index": index, "by_lure": by_lure,
                    "techniques": data.get("techniques", []),
                    "attack": data.get("attack_techniques", [])}
    logger.warning("phish corpus not found; corpus matching disabled")
    return {"path": None, "index": {}, "by_lure": {}, "techniques": [], "attack": []}


def _detect_lures(text: str) -> list[str]:
    return [lure for lure, words in LURE_KEYWORDS.items() if any(w in text for w in words)]


def _detect_brands(text: str) -> list[str]:
    return [brand for brand, tokens in BRAND_TOKENS.items() if any(t in text for t in tokens)]


def _detect_evasions(features: dict[str, Any], attachments: list[dict] | None) -> list[str]:
    """Map already-computed detector features onto corpus evasion names."""
    found: list[str] = []
    if features.get("typosquatting_target") or features.get("typosquatting"):
        found += ["lookalike_domain", "homoglyph"]
    if features.get("shortened_url"):
        found.append("url_shortener")
    age = features.get("domain_age_days")
    if isinstance(age, int) and 0 <= age < 30:
        found.append("new_domain")
    if features.get("reply_to_mismatch"):
        found.append("reply_to_mismatch")
    if features.get("display_name_spoof"):
        found.append("display_name_spoof")
    for a in attachments or []:
        scan = a.get("scan", {})
        sigs = " ".join(scan.get("signals", [])).lower()
        name = (a.get("filename") or "").lower()
        if "macro" in sigs:
            found.append("macro_document")
        if "double extension" in sigs or re.search(r"\.(pdf|doc|xls|jpg)\.(exe|scr|js|vbs|bat)$", name):
            found.append("double_extension")
        if "encrypted" in sigs or "password" in sigs:
            found.append("encrypted_archive")
        if name.endswith((".html", ".htm")):
            found.append("html_smuggling")
    return found


def match_email(text: str, sender: str = "", urls: list[str] | None = None,
                features: dict[str, Any] | None = None,
                attachments: list[dict] | None = None, limit: int = 5) -> dict[str, Any]:
    """
    Match a message against the corpus.

    Returns the best-rated matching techniques plus a corpus score. A match needs a
    recognised pretext *and* either an impersonated brand or an observed evasion —
    a lure phrase on its own is far too common in ordinary mail to mean anything.
    """
    corpus = load_corpus()
    if not corpus["index"]:
        return {"matches": [], "score": 0, "lures": [], "brands": [], "evasions": [], "high_value": False}

    features = features or {}
    haystack = " ".join([text or "", sender or "", " ".join(urls or [])]).lower()

    lures = _detect_lures(haystack)
    brands = _detect_brands(haystack)
    evasions = _detect_evasions(features, attachments)

    high_value = [l for l in lures if l in HIGH_VALUE_LURES]

    if not lures or not (brands or evasions or high_value):
        return {"matches": [], "score": 0, "lures": lures, "brands": brands,
                "evasions": evasions, "high_value": False}

    if high_value and not (brands or evasions):
        # Payment-instruction fraud is the one family where a *clean* message is the
        # attack: no lookalike domain, no attachment, no brand to impersonate — just
        # "our bank details have changed" from a plausible address. Requiring a brand
        # or an evasion here would miss BEC entirely. Rated moderately on its own so
        # a genuine vendor notice lands in review rather than quarantine; the caller
        # escalates when authentication also fails.
        best = max((t for t in corpus["by_lure"].get(high_value[0], [])),
                   key=lambda t: t["severity"], default=None)
        if best:
            return {"matches": [best], "score": HIGH_VALUE_BASE_SCORE, "lures": lures,
                    "brands": brands, "evasions": evasions, "high_value": True}

    hits: list[dict] = []
    for lure in lures:
        for brand in (brands or ["generic_vendor"]):
            for evasion in (evasions or []):
                t = corpus["index"].get((lure, brand, evasion))
                if t:
                    hits.append(t)
        if not evasions:
            # Brand + pretext with no observed evasion: still a known pattern, rated
            # by whatever variant exists, but it should not carry evasion weight.
            for candidate in corpus["by_lure"].get(lure, []):
                if candidate["brand"] in brands:
                    hits.append(candidate)
                    break

    if not hits:
        return {"matches": [], "score": 0, "lures": lures, "brands": brands,
                "evasions": evasions, "high_value": bool(high_value)}

    seen, unique = set(), []
    for h in sorted(hits, key=lambda x: -x["severity"]):
        if h["id"] in seen:
            continue
        seen.add(h["id"])
        unique.append(h)

    top = unique[:limit]
    return {
        "matches": top,
        "score": top[0]["severity"] if top else 0,
        "lures": lures,
        "brands": brands,
        "evasions": evasions,
        "high_value": bool(high_value),
    }


def prompt_context(match: dict[str, Any], limit: int = 3) -> str:
    """Render matched techniques for injection into the analyst prompt."""
    matches = (match or {}).get("matches", [])[:limit]
    if not matches:
        return ""
    lines = ["Known phishing techniques matching this message (ThreatEye corpus, MITRE-anchored):"]
    for m in matches:
        lines.append(f"- [{m['id']} / {m['attack_id']}] {m['name']} (severity {m['severity']}/100)")
        lines.append(f"  {m['explanation']}")
    return "\n".join(lines)


def corpus_stats() -> dict[str, Any]:
    """Summary for the API/UI so operators can see what knowledge is loaded."""
    c = load_corpus()
    techniques = c["techniques"]
    return {
        "loaded": bool(techniques),
        "path": c["path"],
        "techniques": len(techniques),
        "attack_techniques": len(c["attack"]),
        "lures": len({t["lure"] for t in techniques}),
        "brands": len({t["brand"] for t in techniques}),
        "evasions": len({t["evasion"] for t in techniques}),
    }
