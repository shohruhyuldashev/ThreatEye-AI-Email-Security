"""
GoPhish integration: launch real phishing-simulation campaigns (SMTP sending
profile + landing page + group + template + campaign) and read back per-employee /
per-department engagement (opened / clicked / submitted).

Everything degrades gracefully: if GoPhish isn't configured/reachable, functions
return an {"error": ...} dict instead of raising.
"""
import logging
import os
import random
from datetime import datetime

from gophish import Gophish
from gophish.models import SMTP, Page, Group, User, Template, Campaign
from dotenv import load_dotenv

from db import get_db_connection

load_dotenv()
logger = logging.getLogger(__name__)

SENDING_PROFILE_NAME = "ThreatEye Sim SMTP"
LANDING_PAGE_NAME = "ThreatEye Sim Landing"

DEFAULT_LANDING_HTML = (
    "<html><body style='font-family:sans-serif'>"
    "<h2>Session expired</h2>"
    "<p>Please sign in again to continue.</p>"
    "<form method='post' action=''>"
    "Email: <input name='email'/><br/>Password: <input name='password' type='password'/><br/>"
    "<button type='submit'>Sign in</button></form>"
    "</body></html>"
)

# GoPhish result status → engagement flags.
_OPENED = {"Email Opened", "Clicked Link", "Submitted Data"}
_CLICKED = {"Clicked Link", "Submitted Data"}
_SUBMITTED = {"Submitted Data"}


def _sim_config() -> dict:
    conn = get_db_connection()
    c = conn.cursor()
    keys = ("sim_smtp_host", "sim_smtp_from", "sim_phish_url", "sim_landing_html")
    placeholders = ",".join(["?"] * len(keys))
    c.execute(f"SELECT key, value FROM settings WHERE key IN ({placeholders})", keys)
    s = {row["key"]: row["value"] for row in c.fetchall()}
    conn.close()
    return {
        "smtp_host": s.get("sim_smtp_host") or os.getenv("SIM_SMTP_HOST", "mail_server:25"),
        "smtp_from": s.get("sim_smtp_from") or os.getenv("SIM_SMTP_FROM", "IT Security <it-security@example.com>"),
        "phish_url": s.get("sim_phish_url") or os.getenv("SIM_PHISH_URL", "http://localhost"),
        "landing_html": s.get("sim_landing_html") or DEFAULT_LANDING_HTML,
    }


def get_api():
    """Initialise the GoPhish API client from DB settings / env. Returns None if unconfigured."""
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT key, value FROM settings WHERE key IN ('sim_gophish_url', 'sim_gophish_api_key', 'gophish_url', 'gophish_key')")
    settings = {row["key"]: row["value"] for row in c.fetchall()}
    conn.close()

    gophish_url = settings.get("sim_gophish_url") or settings.get("gophish_url") or os.getenv("GOPHISH_URL", "http://gophish:3333")
    gophish_api_key = settings.get("sim_gophish_api_key") or settings.get("gophish_key") or os.getenv("GOPHISH_API_KEY", "")

    if not gophish_api_key:
        return None

    gophish_url = (gophish_url or "").strip()
    for suffix in ("/api/", "/api", "/"):
        if gophish_url.endswith(suffix):
            gophish_url = gophish_url[: -len(suffix)]
            break

    try:
        verify_tls = os.getenv("GOPHISH_VERIFY_TLS", "true").lower() in {"1", "true", "yes", "on"}
        return Gophish(gophish_api_key, host=gophish_url, verify=verify_tls)
    except Exception as e:
        logger.error(f"Failed to initialize GoPhish client: {e}")
        return None


def ensure_sending_profile(client, cfg: dict):
    """Find or create the reusable SMTP sending profile."""
    for prof in client.smtp.get():
        if prof.name == SENDING_PROFILE_NAME:
            return prof
    smtp = SMTP(name=SENDING_PROFILE_NAME)
    smtp.host = cfg["smtp_host"]
    smtp.from_address = cfg["smtp_from"]
    smtp.interface_type = "SMTP"
    smtp.ignore_cert_errors = True
    return client.smtp.post(smtp)


def ensure_landing_page(client, cfg: dict):
    """Find or create the credential-capture landing page."""
    for page in client.pages.get():
        if page.name == LANDING_PAGE_NAME:
            return page
    page = Page(
        name=LANDING_PAGE_NAME,
        html=cfg["landing_html"],
        capture_credentials=True,
        capture_passwords=True,
    )
    return client.pages.post(page)


def launch_campaign(targets: list, email_data: dict, campaign_name: str, cfg: dict | None = None) -> dict:
    """
    Launch a full GoPhish campaign against `targets`
    (each: {email, first_name, last_name, department}).
    """
    client = get_api()
    if not client:
        return {"error": "GoPhish API not configured or unreachable"}
    if not targets:
        return {"error": "No targets provided"}

    cfg = cfg or _sim_config()
    suffix = os.urandom(3).hex()
    try:
        smtp = ensure_sending_profile(client, cfg)
        page = ensure_landing_page(client, cfg)

        group = Group(name=f"{campaign_name}-grp-{suffix}")
        group.targets = [
            User(
                first_name=t.get("first_name", "") or t.get("email", "").split("@")[0],
                last_name=t.get("last_name", ""),
                email=t["email"],
                position=t.get("department", "General"),  # department carried in position
            )
            for t in targets if t.get("email")
        ]
        group = client.groups.post(group)

        html = email_data.get("body_html") or f"<p>{email_data.get('body_text', '')}</p>"
        if "{{.URL}}" not in html:
            html += '<p><a href="{{.URL}}">Click here</a></p>'
        template = Template(
            name=f"{campaign_name}-tpl-{suffix}",
            subject=email_data.get("subject", "Important Notice"),
            text=email_data.get("body_text", "Please review: {{.URL}}"),
            html=html,
        )
        template = client.templates.post(template)

        campaign = Campaign(
            name=f"{campaign_name}-{suffix}",
            groups=[Group(name=group.name)],
            page=Page(name=page.name),
            template=Template(name=template.name),
            smtp=SMTP(name=smtp.name),
            url=cfg["phish_url"],
        )
        campaign = client.campaigns.post(campaign)
        return {
            "status": "success",
            "campaign_id": campaign.id,
            "name": campaign.name,
            "targets": len(group.targets),
        }
    except Exception as e:
        logger.error(f"Campaign launch failed: {e}")
        return {"error": str(e)}


def get_results() -> dict:
    """
    Aggregate engagement across all campaigns:
      - per-campaign totals,
      - per-department open/click/submit rates,
      - the list of employees who clicked or submitted.
    """
    client = get_api()
    if not client:
        return {"campaigns": [], "departments": [], "employees": [], "error": "GoPhish not configured"}
    try:
        campaigns = client.campaigns.get()
    except Exception as e:
        logger.error(f"Failed to fetch campaigns: {e}")
        return {"campaigns": [], "departments": [], "employees": [], "error": str(e)}

    dept: dict[str, dict] = {}
    employees = []
    camp_list = []
    for camp in campaigns:
        c_total = c_open = c_click = c_sub = 0
        for r in getattr(camp, "results", []) or []:
            status = getattr(r, "status", "")
            d = getattr(r, "position", "") or "General"
            row = dept.setdefault(d, {"department": d, "total": 0, "opened": 0, "clicked": 0, "submitted": 0})
            row["total"] += 1
            c_total += 1
            if status in _OPENED:
                row["opened"] += 1; c_open += 1
            if status in _CLICKED:
                row["clicked"] += 1; c_click += 1
            if status in _SUBMITTED:
                row["submitted"] += 1; c_sub += 1
            if status in _CLICKED:
                employees.append({
                    "email": getattr(r, "email", ""),
                    "name": f"{getattr(r, 'first_name', '')} {getattr(r, 'last_name', '')}".strip(),
                    "department": d,
                    "status": status,
                    "campaign": camp.name,
                })
        camp_list.append({
            "id": camp.id, "name": camp.name, "status": camp.status,
            "launch_date": camp.launch_date,
            "total": c_total, "opened": c_open, "clicked": c_click, "submitted": c_sub,
            "click_rate": round((c_click / c_total) * 100, 1) if c_total else 0.0,
        })

    departments = sorted(dept.values(), key=lambda d: d["clicked"], reverse=True)
    return {"campaigns": camp_list, "departments": departments, "employees": employees}


def get_campaign_stats(campaign_id: int):
    client = get_api()
    if not client:
        return None
    try:
        return client.campaigns.get(campaign_id=campaign_id).results
    except Exception:
        return None


def trigger_ai_campaign(organization_id: int = 1, sample: int | None = None, theme: str = "") -> dict:
    """
    AI-automated campaign: pull the employee roster, have the LLM craft a lure, and
    launch a real GoPhish campaign against them.
    """
    from services.roster import get_targets
    from services.ai_generator import generate_phishing_email

    targets = get_targets(organization_id)
    if not targets:
        return {"error": "No employee roster found. Upload a CSV of target employees first."}
    if sample and sample < len(targets):
        targets = random.sample(targets, sample)

    email_data = generate_phishing_email(
        target_name="Team Member",
        department="All Staff",
        company="Current Organization",
        context=theme or "Routine security / IT notice with a call-to-action link.",
    )
    name = f"AI-{datetime.now():%Y%m%d-%H%M}"
    return launch_campaign(targets, email_data, campaign_name=name, cfg=_sim_config())


def _auto_enabled() -> bool:
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT value FROM settings WHERE key = 'sim_auto_enabled'")
    row = c.fetchone()
    conn.close()
    return bool(row) and str(row["value"]).lower() in {"1", "true", "yes", "on"}


def trigger_random_campaign():
    """
    Scheduler entrypoint — roster-driven AI automation, but only when the operator
    has explicitly enabled automated simulations (`sim_auto_enabled` setting).
    """
    if not _auto_enabled():
        logger.info("Automated simulations disabled (sim_auto_enabled off); skipping scheduled campaign.")
        return {"status": "skipped", "reason": "automation disabled"}
    result = trigger_ai_campaign(organization_id=1)
    logger.info(f"Scheduled AI campaign result: {result}")
    return result
