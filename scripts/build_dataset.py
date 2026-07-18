#!/usr/bin/env python3
"""
Build the large labeled phishing/benign dataset used to train-ground and validate
the detector at scale.

Where the data comes from (all open sources, "found from everywhere")
--------------------------------------------------------------------
- Real phishing domains  : Phishing.Database (mitchellkrogza) ACTIVE list — hundreds
                           of thousands of domains seen in live campaigns.
- Real phishing URLs     : OpenPhish community feed.
- Real benign domains    : the top-100k most-visited domains (zer0h/top-1M).

Each real phishing domain is turned into a concrete labeled email sample: the
impersonated brand is inferred from the domain string, a plausible pretext is drawn
from the technique library, authentication is set the way phishing usually presents
(SPF/DKIM/DMARC failing), and an expected verdict is attached. Benign domains become
ordinary authenticated business mail. The result is a JSONL corpus of ~100k rows —
enough to measure precision *and* recall, not just eyeball a few examples.

This is a labeled *dataset* (for validation and grounding stats), distinct from
`data/phishing_corpus.json`, which is the smaller MITRE-anchored *reasoning* library.

Usage
-----
    python3 scripts/build_dataset.py --feeds <dir> --n 100000
"""
from __future__ import annotations

import argparse
import json
import random
import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
CORPUS = REPO / "data" / "phishing_corpus.json"
OUT = REPO / "data" / "phish_dataset.jsonl"
SAMPLE = REPO / "data" / "phish_dataset.sample.jsonl"
STATS = REPO / "data" / "phish_dataset.stats.json"

# Brand token -> the pretexts that plausibly accompany it (reused shape from the corpus).
BRAND_TOKENS = {
    "microsoft": ["password_expiry", "mfa_reenrollment", "storage_quota", "security_alert"],
    "office365": ["password_expiry", "mfa_reenrollment", "shared_document"],
    "outlook": ["password_expiry", "storage_quota", "voicemail"],
    "onedrive": ["shared_document", "storage_quota"],
    "sharepoint": ["shared_document"],
    "google": ["security_alert", "storage_quota", "shared_document"],
    "gmail": ["security_alert", "storage_quota"],
    "apple": ["security_alert", "subscription_renewal"],
    "icloud": ["security_alert", "storage_quota"],
    "paypal": ["security_alert", "refund_notice", "subscription_renewal"],
    "amazon": ["security_alert", "package_delivery", "refund_notice"],
    "netflix": ["subscription_renewal", "security_alert"],
    "facebook": ["security_alert"],
    "instagram": ["security_alert"],
    "linkedin": ["job_offer", "conference_invite"],
    "docusign": ["esign_request", "contract_review"],
    "adobe": ["esign_request", "software_update", "subscription_renewal"],
    "dropbox": ["shared_document", "storage_quota"],
    "dhl": ["package_delivery", "customs_fee"],
    "fedex": ["package_delivery", "customs_fee"],
    "ups": ["package_delivery"],
    "usps": ["package_delivery"],
    "okta": ["mfa_reenrollment", "password_expiry"],
    "wellsfargo": ["banking_otp", "security_alert"],
    "chase": ["banking_otp", "security_alert"],
    "hsbc": ["banking_otp"],
    "netflix": ["subscription_renewal"],
    "whatsapp": ["security_alert"],
    "coinbase": ["security_alert", "banking_otp"],
    "binance": ["security_alert", "banking_otp"],
}
GENERIC_LURES = ["invoice_due", "package_delivery", "security_alert", "shared_document",
                 "password_expiry", "voicemail", "refund_notice", "helpdesk_ticket"]

SUBJECTS = {
    "password_expiry": ["Action required: your password expires today", "Password reset needed", "Your credentials are about to expire"],
    "mfa_reenrollment": ["Re-enroll your multi-factor authentication", "Security: re-verify your account"],
    "storage_quota": ["Your mailbox is almost full", "Storage limit reached — action needed"],
    "security_alert": ["Unusual sign-in detected", "Your account has been locked", "Suspicious activity on your account"],
    "shared_document": ["A document was shared with you", "You have a new shared file"],
    "esign_request": ["Please sign this document", "Signature required"],
    "contract_review": ["Contract for your review", "Agreement attached"],
    "invoice_due": ["Overdue invoice — immediate action", "Unpaid invoice reminder"],
    "package_delivery": ["Delivery failed — reschedule", "Your parcel is waiting"],
    "customs_fee": ["Customs fee required to release your parcel"],
    "voicemail": ["You have a new voicemail", "Missed call — voice message attached"],
    "refund_notice": ["You have a refund waiting", "Claim your refund"],
    "subscription_renewal": ["Your subscription is renewing", "Payment required to keep your account"],
    "banking_otp": ["Your verification code", "Confirm this transaction"],
    "job_offer": ["A recruiter viewed your profile", "New opportunity for you"],
    "conference_invite": ["You are invited to register", "Event invitation"],
    "helpdesk_ticket": ["IT ticket requires your action", "Helpdesk: verify your account"],
    "software_update": ["Mandatory update required"],
}
BODIES = {
    "credential": "Please verify your account by signing in here: {url} — enter your password to confirm. Failure to act will suspend access.",
    "link": "Please review the details at {url} as soon as possible.",
    "attachment": "Please see the attached document and confirm at {url}.",
    "payment": "Please review the updated payment details and confirm at {url}.",
}


def infer_brand(domain: str):
    d = domain.lower()
    for brand in BRAND_TOKENS:
        # substring or homoglyph (0->o, 1->l) match
        norm = d.replace("0", "o").replace("1", "l")
        if brand in d or brand in norm:
            return brand
    return None


def load_lines(path: Path, limit: int | None = None) -> list[str]:
    out = []
    if not path.exists():
        return out
    with open(path, encoding="utf-8", errors="ignore") as f:
        for line in f:
            s = line.strip().lower()
            if not s or s.startswith("#") or " " in s:
                continue
            out.append(s)
            if limit and len(out) >= limit:
                break
    return out


def phishing_sample(domain: str, rnd: random.Random) -> dict:
    brand = infer_brand(domain)
    if brand and BRAND_TOKENS.get(brand):
        lure = rnd.choice(BRAND_TOKENS[brand])
    else:
        lure = rnd.choice(GENERIC_LURES)
    subject = rnd.choice(SUBJECTS.get(lure, ["Important account notice"]))
    path = rnd.choice(["login", "verify", "account", "secure", "reset", "confirm", "signin"])
    url = f"http://{domain}/{path}"
    body_kind = "credential" if lure in ("password_expiry", "mfa_reenrollment", "security_alert", "banking_otp") else "link"
    body = BODIES[body_kind].format(url=url)
    user = rnd.choice(["security", "no-reply", "support", "account", "service", "it", "billing"])
    # Phishing usually fails at least one of SPF/DKIM/DMARC; often all three.
    auth_profile = rnd.choices(
        [("fail", "fail", "fail"), ("fail", "none", "fail"), ("pass", "fail", "fail"), ("softfail", "none", "none")],
        weights=[50, 25, 15, 10],
    )[0]
    return {
        "label": "phishing",
        "sender": f"{user}@{domain}",
        "recipient": "employee@corp.local",
        "subject": subject,
        "body": body,
        "urls": [url],
        "spf": auth_profile[0], "dkim": auth_profile[1], "dmarc": auth_profile[2],
        "brand": brand or "",
        "lure": lure,
        "expected": "quarantine",
        "source": "phishing.database",
    }


BENIGN_SUBJECTS = [
    "Weekly product update", "Your monthly statement", "Meeting notes", "Team newsletter",
    "Release notes", "Order confirmation", "Welcome to our service", "Your receipt",
    "Project status update", "Upcoming maintenance window", "New feature announcement",
]
BENIGN_BODIES = [
    "Here is the update we discussed. Read more at {url}.",
    "Thanks for being a customer. View your statement at {url}.",
    "This month we shipped several improvements. Details at {url}.",
    "Please find the summary attached. More at {url}.",
]


def benign_sample(domain: str, rnd: random.Random) -> dict:
    url = f"https://{domain}/{rnd.choice(['blog','account','news','docs','update'])}"
    user = rnd.choice(["news", "hello", "team", "no-reply", "notifications", "support"])
    # Legit senders usually pass SPF; DKIM/DMARC vary for bulk mail.
    auth_profile = rnd.choices(
        [("pass", "pass", "pass"), ("pass", "pass", "none"), ("pass", "none", "none")],
        weights=[55, 30, 15],
    )[0]
    return {
        "label": "benign",
        "sender": f"{user}@{domain}",
        "recipient": "employee@corp.local",
        "subject": rnd.choice(BENIGN_SUBJECTS),
        "body": rnd.choice(BENIGN_BODIES).format(url=url),
        "urls": [url],
        "spf": auth_profile[0], "dkim": auth_profile[1], "dmarc": auth_profile[2],
        "brand": "", "lure": "",
        "expected": "allow",
        "source": "top-domains",
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--feeds", required=True, help="dir with phishing-domains-active.txt, legit-domains.txt")
    ap.add_argument("--n", type=int, default=100000, help="total samples")
    ap.add_argument("--phish-frac", type=float, default=0.6)
    ap.add_argument("--seed", type=int, default=1337)
    args = ap.parse_args()

    rnd = random.Random(args.seed)
    feeds = Path(args.feeds)

    n_phish = int(args.n * args.phish_frac)
    n_benign = args.n - n_phish

    print("loading feeds …")
    phish_domains = load_lines(feeds / "phishing-domains-active.txt")
    benign_domains = load_lines(feeds / "legit-domains.txt")
    # Fold in OpenPhish real URLs' hostnames too, for freshness.
    for u in load_lines(feeds / "openphish.txt"):
        m = re.match(r"https?://([^/]+)", u)
        if m:
            phish_domains.append(m.group(1))
    # URLhaus (abuse.ch) recent malware/phishing URLs — CSV, url column is quoted.
    uh = feeds / "urlhaus.csv"
    if uh.exists():
        for line in open(uh, encoding="utf-8", errors="ignore"):
            if line.startswith("#") or not line.strip():
                continue
            m = re.search(r'https?://([^/"]+)', line)
            if m:
                phish_domains.append(m.group(1).lower())
    print(f"  phishing domains: {len(phish_domains)}   benign domains: {len(benign_domains)}")
    if not phish_domains or not benign_domains:
        return "feeds missing — run the download step first"

    OUT.parent.mkdir(parents=True, exist_ok=True)
    labels = {"phishing": 0, "benign": 0}
    brands = {}
    with open(OUT, "w") as fout, open(SAMPLE, "w") as fsamp:
        for i in range(n_phish):
            d = phish_domains[rnd.randrange(len(phish_domains))]
            s = phishing_sample(d, rnd)
            fout.write(json.dumps(s) + "\n")
            if i < 500:
                fsamp.write(json.dumps(s) + "\n")
            labels["phishing"] += 1
            if s["brand"]:
                brands[s["brand"]] = brands.get(s["brand"], 0) + 1
        for i in range(n_benign):
            d = benign_domains[rnd.randrange(len(benign_domains))]
            s = benign_sample(d, rnd)
            fout.write(json.dumps(s) + "\n")
            if i < 500:
                fsamp.write(json.dumps(s) + "\n")
            labels["benign"] += 1

    stats = {
        "total": labels["phishing"] + labels["benign"],
        "phishing": labels["phishing"],
        "benign": labels["benign"],
        "brands_impersonated": len(brands),
        "top_brands": dict(sorted(brands.items(), key=lambda kv: -kv[1])[:15]),
        "sources": ["Phishing.Database ACTIVE", "OpenPhish", "URLhaus (abuse.ch)", "top-100k domains"],
        "phishing_domains_available": len(phish_domains),
    }
    json.dump(stats, open(STATS, "w"), indent=1)
    print(f"wrote {stats['total']} samples -> {OUT}")
    print(f"  phishing {stats['phishing']}  benign {stats['benign']}  brands {stats['brands_impersonated']}")
    print(f"  sample (500+500) -> {SAMPLE}")
    print(f"  stats -> {STATS}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
