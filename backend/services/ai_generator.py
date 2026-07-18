"""
Simulation lure generation.

Lures are grounded in the same MITRE-anchored corpus the detector uses, so a phishing
simulation exercises the exact techniques ThreatEye is built to catch — and each
campaign carries the ATT&CK id it is modelling, which is what makes the results
defensible ("we tested T1566.002 credential phishing against Finance", not "we sent a
scary email"). Selection is role-aware: Finance draws payment-fraud pretexts, IT draws
VPN/helpdesk, and so on.
"""
import json
import random

from framework.model_provider import get_llm_client, get_model_name
from framework.phish_corpus import load_corpus

# Map an employee department to the target roles the corpus uses.
DEPT_TO_ROLE = {
    "finance": "finance", "accounting": "finance", "accounts": "finance",
    "hr": "hr", "human resources": "hr", "people": "hr",
    "it": "it", "helpdesk": "it", "infrastructure": "it", "security": "it",
    "legal": "legal", "compliance": "legal",
    "sales": "sales", "marketing": "sales", "business development": "sales",
    "engineering": "engineering", "development": "engineering", "r&d": "engineering",
    "executive": "exec", "leadership": "exec", "c-suite": "exec", "management": "exec",
}


def pick_technique(department: str = "", theme: str = "") -> dict:
    """
    Choose a corpus technique appropriate to the department. Falls back to a
    broadly-applicable credential-phishing pattern if nothing role-specific fits.
    """
    corpus = load_corpus()
    techniques = corpus.get("techniques", [])
    if not techniques:
        return {}

    role = DEPT_TO_ROLE.get((department or "").strip().lower(), "all_staff")
    pool = [t for t in techniques if t.get("target_role") in (role, "all_staff")]

    # If a theme was given, prefer techniques whose lure name mentions it.
    if theme:
        themed = [t for t in pool if theme.lower() in t.get("name", "").lower()]
        if themed:
            pool = themed

    if not pool:
        pool = techniques
    # Weight toward higher-severity, more realistic patterns.
    pool.sort(key=lambda t: -t.get("severity", 0))
    top = pool[: max(8, len(pool) // 5)]
    return random.choice(top)


def generate_phishing_email(target_name: str, department: str, company: str, context: str = "") -> dict:
    """
    Generate a simulation lure grounded in a corpus technique.

    Returns the usual GoPhish fields plus the ATT&CK/technique metadata so the campaign
    can be reported against a named technique.
    """
    technique = pick_technique(department, context)
    tech_brief = ""
    if technique:
        tech_brief = (
            f"\n    Model this specific technique:\n"
            f"    - Technique: {technique['name']}\n"
            f"    - MITRE ATT&CK: {technique['attack_id']} ({technique.get('attack_name','')})\n"
            f"    - Pretext family: {technique['lure']}; evasion style: {technique['evasion']}\n"
            f"    - Impersonated brand: {technique['brand']}\n"
        )

    prompt = f"""
    You are a professional red teamer running an AUTHORIZED phishing simulation for
    security-awareness training. This is a controlled exercise against consenting
    employees, not a real attack.

    Create a convincing but clearly trainable phishing email for:
    Name: {target_name}
    Department: {department}
    Company: {company}
    Additional Context: {context}
    {tech_brief}
    Keep it professional with a plausible sense of urgency, and a single call-to-action
    link. Do NOT include real malware, real credentials, or working exploit content —
    the link is a tracking placeholder only.

    Return ONLY a JSON object with:
    "subject": the subject line.
    "body_text": plain-text body. Use {{.URL}} as the link placeholder.
    "body_html": HTML body. Use {{.URL}} as the link placeholder.
    """

    result: dict = {}
    try:
        client = get_llm_client()
        response = client.chat.completions.create(
            model=get_model_name(),
            messages=[{"role": "user", "content": prompt}],
            response_format={"type": "json_object"},
        )
        result = json.loads(response.choices[0].message.content)
    except Exception as e:
        print(f"Error generating email: {e}")
        result = _fallback_lure(target_name, company, department, technique)

    # Attach the technique metadata regardless of how the body was produced, so the
    # campaign is always attributable to an ATT&CK technique.
    if technique:
        result.setdefault("technique_id", technique["id"])
        result.setdefault("attack_id", technique["attack_id"])
        result.setdefault("attack_name", technique.get("attack_name", ""))
        result.setdefault("technique_name", technique["name"])
        result.setdefault("technique_severity", technique.get("severity"))

    # Generate the matching credential-capture landing page so the whole campaign —
    # lure email + fake sign-in page + click/submit tracking — is produced by the AI.
    result.setdefault("landing_html", generate_landing_page(technique, company))
    return result


def generate_landing_page(technique: dict, company: str = "your organization") -> str:
    """
    Generate the credential-capture landing page for a simulation.

    This is the page an employee lands on after clicking the lure — a fake sign-in
    form styled for the impersonated brand. GoPhish records who reaches it (click) and
    who submits it (data-entry), the Burp-Collaborator-style callback the user asked for:
    the tracking is native to GoPhish once `capture_credentials` is on, so the page only
    has to be a believable form. Submitted values are NOT stored as real credentials —
    this is a training exercise and GoPhish captures the *event*, then redirects.

    Falls back to a solid brand-styled template if the model is unavailable, so a
    campaign never launches with a broken page.
    """
    brand = (technique or {}).get("brand", "")
    blabel = {
        "microsoft365": "Microsoft 365", "outlook": "Outlook", "office365": "Office 365",
        "google": "Google", "okta": "Okta", "paypal": "PayPal", "docusign": "DocuSign",
        "dropbox": "Dropbox", "adobe": "Adobe",
    }.get(brand, "Secure Portal")

    prompt = f"""
    You are building a landing page for an AUTHORIZED phishing-simulation exercise
    (security-awareness training for consenting employees — not a real attack).

    Produce a single self-contained HTML sign-in page that imitates a generic
    {blabel} login screen for {company}. Requirements:
    - One <form method="post"> with an email/username field and a password field, and a
      sign-in button. GoPhish captures the submission event for training metrics.
    - After submit, the form must redirect to {{{{.URL}}}} (GoPhish placeholder) — do not
      submit anywhere else.
    - Inline CSS only, no external resources, no real logos or trademarked images, no
      JavaScript that exfiltrates data. Keep it clearly a training artifact.
    Return ONLY the raw HTML, no markdown fences.
    """
    try:
        client = get_llm_client()
        resp = client.chat.completions.create(
            model=get_model_name(),
            messages=[{"role": "user", "content": prompt}],
        )
        html = (resp.choices[0].message.content or "").strip()
        html = html.replace("```html", "").replace("```", "").strip()
        # Only trust it if it is a real form that redirects through GoPhish.
        if "<form" in html.lower() and "password" in html.lower():
            if "{{.URL}}" not in html:
                html = html.replace("</form>", '<input type="hidden" name="__redirect" value="{{.URL}}"></form>', 1)
            return html
    except Exception as e:
        print(f"Error generating landing page: {e}")
    return _fallback_landing_page(blabel, company)


def _fallback_landing_page(blabel: str, company: str) -> str:
    """Brand-styled credential-capture page used when the model is unavailable."""
    return f"""<!doctype html><html><head><meta charset="utf-8"><title>{blabel} — Sign in</title>
<style>
 body{{font-family:'Segoe UI',Arial,sans-serif;background:#f3f3f3;margin:0;display:flex;
   min-height:100vh;align-items:center;justify-content:center}}
 .card{{background:#fff;padding:40px 44px;border-radius:6px;box-shadow:0 2px 10px rgba(0,0,0,.12);width:340px}}
 h1{{font-size:20px;margin:0 0 6px;color:#1b1b1b}} p{{color:#666;font-size:13px;margin:0 0 22px}}
 label{{display:block;font-size:12px;color:#444;margin:14px 0 4px}}
 input{{width:100%;padding:10px;border:1px solid #ccc;border-radius:4px;box-sizing:border-box;font-size:14px}}
 button{{margin-top:22px;width:100%;padding:11px;border:0;border-radius:4px;background:#0067b8;color:#fff;
   font-size:15px;cursor:pointer}} .n{{font-size:11px;color:#999;margin-top:18px;text-align:center}}
</style></head><body>
 <div class="card">
  <h1>Sign in</h1><p>Use your {company} account to continue.</p>
  <form method="post" action="">
   <label>Email or username</label><input name="email" type="text" autocomplete="off" required>
   <label>Password</label><input name="password" type="password" required>
   <button type="submit">Sign in</button>
   <input type="hidden" name="__redirect" value="{{{{.URL}}}}">
  </form>
  <div class="n">Security-awareness simulation — {blabel}</div>
 </div></body></html>"""


def _fallback_lure(target_name: str, company: str, department: str, technique: dict) -> dict:
    """Offline template, still shaped by the chosen technique's pretext."""
    lure = (technique or {}).get("lure", "password_expiry")
    subjects = {
        "password_expiry": f"Action required: your {company} password expires today",
        "vendor_bank_change": f"{company}: updated remittance details for your review",
        "wire_transfer": "Urgent payment approval needed",
        "payroll_change": "Confirm your direct-deposit details",
        "mfa_reenrollment": f"Re-enroll your {company} multi-factor authentication",
        "shared_document": f"A document was shared with you on {company} drive",
        "vpn_reset": f"Your {company} VPN access is expiring",
    }
    subject = subjects.get(lure, f"Urgent: {company} account update")
    return {
        "subject": subject,
        "body_text": f"Hi {target_name},\n\nPlease review and confirm here: {{.URL}}\n\n{company} {department} team.",
        "body_html": f"<p>Hi {target_name},</p><p>Please review and confirm <a href='{{.URL}}'>here</a>.</p><p>{company} {department} team.</p>",
    }
