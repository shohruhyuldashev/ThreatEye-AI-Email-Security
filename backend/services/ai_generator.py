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
    return result


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
