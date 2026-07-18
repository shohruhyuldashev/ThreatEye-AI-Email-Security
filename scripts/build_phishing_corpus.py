#!/usr/bin/env python3
"""
Build ThreatEye's phishing-technique corpus.

The corpus is what the detector reasons against: every entry is one concrete,
*detectable* phishing pattern with the signals an analyst would actually look for.

Sources
-------
Anchored on the real MITRE ATT&CK Enterprise phishing tree (T1566, T1598, T1534,
T1204, T1621, T1585/T1586/T1608 …), fetched as the official STIX bundle from
github.com/mitre/cti. Those 47 techniques give authoritative names, tactics and
descriptions but are deliberately abstract — "Spearphishing Link" is one technique
covering millions of real emails.

So each ATT&CK anchor is expanded across the dimensions that actually vary in real
campaigns, and which a mail-security product can observe:

    delivery vector x lure theme x impersonated brand x evasion x target role

The pairings are constrained to combinations that occur in the wild (a "customs fee"
lure pairs with DHL/FedEx, never with Okta), so the result is a realistic technique
library rather than a cartesian product of nonsense.

Usage
-----
    python3 scripts/build_phishing_corpus.py                # writes data/phishing_corpus.json
    python3 scripts/build_phishing_corpus.py --attack a.json  # reuse a downloaded bundle
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.request
from pathlib import Path

ATTACK_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
CORE_PREFIXES = ("T1566", "T1598", "T1534", "T1204", "T1656", "T1585", "T1586", "T1589", "T1591", "T1078", "T1621", "T1608")

REPO = Path(__file__).resolve().parents[1]
OUT = REPO / "data" / "phishing_corpus.json"


# --------------------------------------------------------------------------
# Dimension vocabularies. Each carries the observable signals it produces, so a
# generated entry can be checked against a real message rather than just read.
# --------------------------------------------------------------------------

# lure -> (human label, natural brands, target roles, base severity, attack id)
LURES = {
    "password_expiry":      ("password expiry / forced reset", ["microsoft365", "outlook", "google", "okta"], ["all_staff"], 85, "T1566.002"),
    "mfa_reenrollment":     ("MFA re-enrollment required", ["microsoft365", "okta", "duo"], ["all_staff"], 88, "T1621"),
    "mfa_fatigue":          ("repeated MFA push until approved", ["microsoft365", "okta", "duo"], ["all_staff", "it"], 88, "T1621"),
    "security_alert":       ("suspicious sign-in / account locked", ["microsoft365", "google", "apple", "paypal"], ["all_staff"], 82, "T1566.002"),
    "storage_quota":        ("mailbox or drive full", ["microsoft365", "outlook", "google", "dropbox"], ["all_staff"], 78, "T1566.002"),
    "shared_document":      ("a document was shared with you", ["sharepoint", "onedrive", "dropbox", "google"], ["all_staff", "legal"], 80, "T1566.002"),
    "esign_request":        ("document awaiting your signature", ["docusign", "adobe"], ["legal", "finance", "exec"], 82, "T1566.002"),
    "contract_review":      ("contract / NDA for review", ["docusign", "adobe"], ["legal"], 78, "T1566.001"),
    "invoice_due":          ("unpaid or overdue invoice", ["quickbooks", "sage", "generic_vendor"], ["finance"], 84, "T1566.001"),
    "purchase_order":       ("new purchase order attached", ["generic_vendor"], ["finance", "sales"], 80, "T1566.001"),
    "vendor_bank_change":   ("supplier changed bank details", ["generic_vendor"], ["finance"], 92, "T1566.002"),
    "wire_transfer":        ("urgent wire transfer approval", ["internal_exec"], ["finance", "exec"], 93, "T1534"),
    "gift_card":            ("buy gift cards discreetly", ["internal_exec"], ["finance", "all_staff"], 86, "T1534"),
    "payroll_change":       ("update your direct-deposit details", ["workday", "adp", "internal_hr"], ["hr", "all_staff"], 90, "T1566.002"),
    "benefits_enrollment":  ("open-enrollment deadline", ["workday", "internal_hr"], ["hr", "all_staff"], 76, "T1566.002"),
    "hr_policy":            ("new HR policy — acknowledge", ["internal_hr"], ["all_staff"], 74, "T1566.001"),
    "performance_review":   ("your review is ready", ["workday", "internal_hr"], ["all_staff"], 74, "T1566.002"),
    "tax_document":         ("tax form / W-2 available", ["internal_hr", "irs"], ["hr", "finance"], 84, "T1566.001"),
    "package_delivery":     ("delivery failed / reschedule", ["dhl", "fedex", "ups", "usps"], ["all_staff"], 72, "T1566.002"),
    "customs_fee":          ("customs duty payment required", ["dhl", "fedex"], ["all_staff"], 74, "T1566.002"),
    "helpdesk_ticket":      ("IT ticket needs your action", ["internal_it"], ["all_staff"], 80, "T1566.002"),
    "vpn_reset":            ("VPN access expiring", ["internal_it", "cisco"], ["it", "all_staff"], 84, "T1566.002"),
    "software_update":      ("mandatory client update", ["internal_it", "adobe", "zoom"], ["all_staff"], 78, "T1204.002"),
    "voicemail":            ("new voicemail attached", ["microsoft365", "zoom"], ["all_staff"], 76, "T1566.001"),
    "missed_meeting":       ("you missed a meeting / join now", ["zoom", "teams"], ["all_staff"], 74, "T1566.002"),
    "calendar_invite":      ("calendar invite with malicious link", ["microsoft365", "google"], ["all_staff", "exec"], 76, "T1566.002"),
    "job_offer":            ("recruiter with an offer", ["linkedin"], ["engineering", "sales"], 72, "T1566.003"),
    "subscription_renewal": ("subscription auto-renewing — cancel", ["paypal", "adobe", "netflix"], ["all_staff"], 74, "T1566.002"),
    "legal_subpoena":       ("legal notice / subpoena", ["internal_legal"], ["legal", "exec"], 82, "T1566.001"),
    "bonus_announcement":   ("bonus or salary adjustment", ["internal_hr"], ["all_staff"], 78, "T1566.002"),
    "printer_scan":         ("scanned document from the office printer", ["internal_it", "xerox"], ["all_staff"], 80, "T1566.001"),
    "expense_report":       ("expense report needs approval", ["concur", "internal_finance"], ["finance", "exec"], 78, "T1566.002"),
    "cloud_bill":           ("cloud billing / payment failed", ["aws", "azure", "microsoft365"], ["it", "finance"], 82, "T1566.002"),
    "domain_renewal":       ("domain or SSL certificate expiring", ["godaddy", "internal_it"], ["it"], 80, "T1566.002"),
    "repo_security_alert":  ("source-repository security alert", ["github", "gitlab"], ["engineering"], 84, "T1566.002"),
    "banking_otp":          ("bank verification code request", ["chase", "hsbc", "paypal"], ["finance", "exec"], 88, "T1621"),
    "refund_notice":        ("refund waiting to be claimed", ["irs", "paypal", "generic_vendor"], ["finance", "all_staff"], 76, "T1566.002"),
    "insurance_claim":      ("insurance or benefits claim update", ["internal_hr"], ["hr", "all_staff"], 74, "T1566.001"),
    "survey_request":       ("mandatory employee survey", ["internal_hr", "microsoft365"], ["all_staff"], 72, "T1566.002"),
    "conference_invite":    ("event or conference registration", ["linkedin", "zoom"], ["sales", "exec"], 72, "T1566.003"),
}

# evasion -> (label, observable signals, severity modifier, delivery hint)
EVASIONS = {
    "lookalike_domain":   ("registered lookalike domain", ["sender domain is a lookalike of the impersonated brand", "domain registered recently"], +6, "link"),
    "homoglyph":          ("homoglyph / digit substitution in domain", ["domain uses 0-for-o or 1-for-l substitution", "visually near-identical to a known brand"], +8, "link"),
    "subdomain_spoof":    ("brand placed in the subdomain", ["brand name appears in the subdomain of an unrelated registrable domain"], +6, "link"),
    "url_shortener":      ("link hidden behind a shortener", ["URL uses a link-shortening service", "true destination not visible in the message"], +4, "link"),
    "open_redirect":      ("abuse of a trusted open redirect", ["URL is a legitimate domain redirecting off-site", "redirect parameter carries an external target"], +7, "link"),
    "legit_hosting":      ("payload hosted on a trusted service", ["credential form hosted on SharePoint/Firebase/Notion", "sender domain looks clean but content is hostile"], +7, "link"),
    "aitm_proxy":         ("adversary-in-the-middle session-token theft", ["reverse-proxy login page harvesting the session cookie", "MFA is not a mitigation for this pattern"], +12, "link"),
    "qr_code":            ("QR code instead of a clickable link (quishing)", ["message body is an image containing a QR code", "no clickable URL for gateways to inspect"], +8, "qr"),
    "image_only_body":    ("body rendered entirely as an image", ["no extractable text in the body", "text-based filters have nothing to score"], +5, "link"),
    "html_smuggling":     ("payload assembled by script in an HTML attachment", ["HTML attachment builds the file in the browser", "no payload traverses the gateway"], +10, "attachment"),
    "encrypted_archive":  ("password-protected archive, password in the body", ["archive cannot be scanned", "password supplied in the message text"], +10, "attachment"),
    "nested_archive":     ("deeply nested archives to defeat scanning", ["archive within archive beyond typical scan depth"], +7, "attachment"),
    "macro_document":     ("office document with active content", ["document requests macros be enabled", "active content in an unexpected attachment"], +9, "attachment"),
    "double_extension":   ("double or misleading file extension", ["filename ends .pdf.exe or similar", "declared type does not match content"], +9, "attachment"),
    "thread_hijack":      ("injected into an existing reply chain", ["reply chain quoted but sender domain changed", "conversation context stolen from a compromised mailbox"], +11, "reply_chain"),
    "display_name_spoof": ("display name impersonates a known person", ["display name matches an executive while the address does not"], +7, "link"),
    "reply_to_mismatch":  ("Reply-To points elsewhere", ["Reply-To domain differs from the From domain"], +7, "link"),
    "new_domain":         ("domain registered days ago", ["domain age under 30 days"], +6, "link"),
    "compromised_sender": ("sent from a genuinely compromised account", ["authentication passes because the account is real", "behaviour deviates from the sender's history"], +9, "internal"),
    "unicode_rtl":        ("right-to-left override hides the real extension", ["RTL override character in the filename"], +8, "attachment"),
}

BRAND_LABEL = {
    "microsoft365": "Microsoft 365", "outlook": "Outlook", "google": "Google Workspace", "okta": "Okta",
    "duo": "Duo Security", "sharepoint": "SharePoint", "onedrive": "OneDrive", "dropbox": "Dropbox",
    "docusign": "DocuSign", "adobe": "Adobe", "quickbooks": "QuickBooks", "sage": "Sage",
    "generic_vendor": "a supplier", "internal_exec": "a company executive", "workday": "Workday",
    "adp": "ADP", "internal_hr": "internal HR", "irs": "the tax authority", "dhl": "DHL",
    "fedex": "FedEx", "ups": "UPS", "usps": "USPS", "internal_it": "the internal IT helpdesk",
    "cisco": "Cisco AnyConnect", "zoom": "Zoom", "teams": "Microsoft Teams", "linkedin": "LinkedIn",
    "paypal": "PayPal", "netflix": "Netflix", "internal_legal": "internal legal counsel", "apple": "Apple",
    "xerox": "the office printer/scanner", "concur": "SAP Concur", "internal_finance": "internal finance",
    "aws": "AWS", "azure": "Microsoft Azure", "godaddy": "GoDaddy", "github": "GitHub", "gitlab": "GitLab",
    "chase": "Chase", "hsbc": "HSBC",
}

ROLE_LABEL = {
    "all_staff": "any employee", "finance": "finance / accounts payable", "hr": "HR / people ops",
    "it": "IT and helpdesk staff", "exec": "executives", "legal": "legal", "sales": "sales",
    "engineering": "engineering",
}

# Which evasions plausibly accompany which lure families.
LINK_EVASIONS = ["lookalike_domain", "homoglyph", "subdomain_spoof", "url_shortener", "open_redirect",
                 "legit_hosting", "aitm_proxy", "qr_code", "image_only_body", "display_name_spoof",
                 "reply_to_mismatch", "new_domain"]
FILE_EVASIONS = ["html_smuggling", "encrypted_archive", "nested_archive", "macro_document",
                 "double_extension", "unicode_rtl"]
CTX_EVASIONS = ["thread_hijack", "compromised_sender"]


def fetch_attack(path: str | None) -> list[dict]:
    """Load the ATT&CK phishing tree, from a local bundle if given, else the official STIX feed."""
    if path and os.path.exists(path):
        raw = json.load(open(path))
    else:
        print(f"downloading {ATTACK_URL} …", file=sys.stderr)
        with urllib.request.urlopen(ATTACK_URL, timeout=300) as r:
            raw = json.load(r)

    def tid(o):
        for ref in o.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                return ref.get("external_id", "")
        return ""

    out = []
    for o in raw.get("objects", []):
        if o.get("type") != "attack-pattern" or o.get("revoked") or o.get("x_mitre_deprecated"):
            continue
        t = tid(o)
        if t.split(".")[0] in CORE_PREFIXES:
            out.append({
                "id": t,
                "name": o.get("name", ""),
                "tactics": [p["phase_name"] for p in o.get("kill_chain_phases", [])
                            if p.get("kill_chain_name") == "mitre-attack"],
                "description": " ".join(o.get("description", "").split())[:600],
            })
    out.sort(key=lambda r: r["id"])
    return out


def build(attack: list[dict]) -> dict:
    by_id = {a["id"]: a for a in attack}
    entries, seen = [], set()
    n = 0

    for lure, (lure_label, brands, roles, base_sev, attack_id) in LURES.items():
        # Pick the evasion families that make sense for this lure's delivery style.
        anchor = by_id.get(attack_id) or by_id.get(attack_id.split(".")[0]) or {}
        file_lure = attack_id in ("T1566.001", "T1204.002", "T1598.002")
        pool = (FILE_EVASIONS + CTX_EVASIONS + LINK_EVASIONS[:4]) if file_lure else (LINK_EVASIONS + CTX_EVASIONS)

        for brand in brands:
            for evasion in pool:
                ev_label, ev_signals, ev_mod, delivery = EVASIONS[evasion]
                role = roles[n % len(roles)]
                n += 1
                key = (lure, brand, evasion)
                if key in seen:
                    continue
                seen.add(key)

                severity = max(30, min(99, base_sev + ev_mod))
                blabel = BRAND_LABEL.get(brand, brand)
                entries.append({
                    "id": f"TEP-{len(entries)+1:04d}",
                    "name": f"{lure_label} impersonating {blabel}, delivered via {ev_label}",
                    "attack_id": attack_id,
                    "attack_name": anchor.get("name", ""),
                    "tactics": anchor.get("tactics", []),
                    "lure": lure,
                    "brand": brand,
                    "evasion": evasion,
                    "delivery": delivery,
                    "target_role": role,
                    "severity": severity,
                    "explanation": (
                        f"The attacker impersonates {blabel} with a {lure_label} pretext aimed at "
                        f"{ROLE_LABEL.get(role, role)}. Detection is evaded using {ev_label}. "
                        f"Mapped to {attack_id} ({anchor.get('name','')})."
                    ),
                    "signals": ev_signals + _lure_signals(lure),
                })

    return {
        "version": 1,
        "source": {
            "attack_bundle": ATTACK_URL,
            "attack_techniques_used": len(attack),
            "note": "ATT&CK anchors expanded across delivery/lure/brand/evasion/role dimensions.",
        },
        "attack_techniques": attack,
        "techniques": entries,
    }


def _lure_signals(lure: str) -> list[str]:
    """Body-level signals a scanner can actually match for this pretext."""
    table = {
        "password_expiry": ["urgency about account expiry", "asks the recipient to re-enter a password"],
        "mfa_reenrollment": ["asks the user to re-register an MFA method"],
        "mfa_fatigue": ["references repeated authentication prompts"],
        "security_alert": ["claims unusual sign-in activity", "pressure to act to 'secure' the account"],
        "storage_quota": ["claims the mailbox or drive is full"],
        "shared_document": ["claims a file was shared", "generic sharing notification wording"],
        "esign_request": ["claims a signature is required"],
        "contract_review": ["attaches a contract for review"],
        "invoice_due": ["references an unpaid invoice", "payment pressure"],
        "purchase_order": ["attaches a purchase order"],
        "vendor_bank_change": ["requests a change of bank/remittance details"],
        "wire_transfer": ["requests an urgent transfer", "asks for confidentiality"],
        "gift_card": ["asks for gift-card purchase", "asks for confidentiality"],
        "payroll_change": ["requests direct-deposit changes"],
        "benefits_enrollment": ["deadline pressure about benefits"],
        "hr_policy": ["asks acknowledgement of a policy document"],
        "performance_review": ["claims a review document is ready"],
        "tax_document": ["references tax forms or W-2"],
        "package_delivery": ["claims a failed delivery"],
        "customs_fee": ["requests a small payment to release a parcel"],
        "helpdesk_ticket": ["references an IT ticket"],
        "vpn_reset": ["claims VPN or remote access is expiring"],
        "software_update": ["instructs the user to install an update"],
        "voicemail": ["claims a voicemail is attached"],
        "missed_meeting": ["claims a missed meeting"],
        "calendar_invite": ["arrives as a meeting invitation"],
        "job_offer": ["unsolicited recruitment approach"],
        "subscription_renewal": ["claims an automatic charge is imminent"],
        "legal_subpoena": ["legal threat or notice"],
        "bonus_announcement": ["promises a bonus or raise"],
        "printer_scan": ["claims a scan was sent from an office device", "attachment named like a scan"],
        "expense_report": ["requests approval of an expense claim"],
        "cloud_bill": ["claims a payment method failed", "threatens service suspension"],
        "domain_renewal": ["claims a domain or certificate is expiring"],
        "repo_security_alert": ["claims a repository or dependency is compromised"],
        "banking_otp": ["requests a one-time code be shared"],
        "refund_notice": ["claims money is waiting to be claimed"],
        "insurance_claim": ["references an insurance or benefits claim"],
        "survey_request": ["pressures completion of an internal survey"],
        "conference_invite": ["invites registration for an event"],
    }
    return table.get(lure, [])


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--attack", help="path to a downloaded enterprise-attack.json")
    ap.add_argument("--out", default=str(OUT))
    args = ap.parse_args()

    attack = fetch_attack(args.attack)
    corpus = build(attack)

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    json.dump(corpus, open(out, "w"), indent=1)

    t = corpus["techniques"]
    print(f"ATT&CK techniques anchored : {len(attack)}")
    print(f"phishing patterns generated : {len(t)}")
    print(f"  distinct lures            : {len({e['lure'] for e in t})}")
    print(f"  distinct brands           : {len({e['brand'] for e in t})}")
    print(f"  distinct evasions         : {len({e['evasion'] for e in t})}")
    print(f"  severity range            : {min(e['severity'] for e in t)}–{max(e['severity'] for e in t)}")
    print(f"written to {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
