from fastapi import APIRouter, HTTPException, File, Form, UploadFile, Response, Depends, Query, Header, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from typing import Optional, List
import logging
import asyncio
import json
import os
import re
import secrets
import threading
import time
from db import get_db_connection
from datetime import datetime, timedelta
from services.ai_detector import analyze_email_hybrid
from services.report_generator import generate_analytics_pdf
from framework.audit import audit_log
from framework.security import (
    hash_password,
    verify_password,
    set_auth_cookies,
    VALID_ROLES,
    role_at_least,
    generate_api_key,
    hash_api_key,
)
from api.deps import require_auth, require_role, require_api_key

logger = logging.getLogger(__name__)
router = APIRouter()

# Keys that must never be echoed back through the settings API.
INTERNAL_SETTING_KEYS = {"admin_password", "auth_secret"}
SENSITIVE_SETTING_MARKERS = ("pass", "password", "key", "secret", "token", "sa_json", "credential")
MASKED_SECRET = "********"

# --- Brute-force protection for the login endpoint -------------------------------
LOGIN_MAX_ATTEMPTS = int(os.getenv("THREATEYE_LOGIN_MAX_ATTEMPTS", "8"))
LOGIN_WINDOW_SECONDS = int(os.getenv("THREATEYE_LOGIN_WINDOW_SECONDS", "300"))
_login_attempts: dict[str, list[float]] = {}
_login_lock = threading.Lock()


def _client_ip(request: Optional[Request]) -> str:
    if request is None:
        return "unknown"
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _check_login_rate_limit(key: str) -> None:
    # Prefer the shared Redis counter (correct across replicas); fall back to
    # the in-process sliding window when Redis is not configured. The Redis path
    # only READS here — failures are counted in _record_login_failure.
    from framework.cache import get_redis, rate_limit_get
    if get_redis() is not None:
        if rate_limit_get(f"login:{key}") >= LOGIN_MAX_ATTEMPTS:
            raise HTTPException(
                status_code=429,
                detail="Too many failed login attempts. Try again later.",
                headers={"Retry-After": str(LOGIN_WINDOW_SECONDS)},
            )
        return
    now = time.monotonic()
    with _login_lock:
        window = [ts for ts in _login_attempts.get(key, []) if now - ts < LOGIN_WINDOW_SECONDS]
        _login_attempts[key] = window
        if len(window) >= LOGIN_MAX_ATTEMPTS:
            retry_after = int(LOGIN_WINDOW_SECONDS - (now - window[0]))
            raise HTTPException(
                status_code=429,
                detail="Too many failed login attempts. Try again later.",
                headers={"Retry-After": str(max(retry_after, 1))},
            )


def _record_login_failure(key: str) -> None:
    # With Redis, the counter is incremented in _check_login_rate_limit (via INCR),
    # so only the in-process fallback needs to record here.
    from framework.cache import get_redis
    if get_redis() is not None:
        from framework.cache import rate_limit_hit
        rate_limit_hit(f"login:{key}", LOGIN_WINDOW_SECONDS)
        return
    with _login_lock:
        _login_attempts.setdefault(key, []).append(time.monotonic())


def _reset_login_attempts(key: str) -> None:
    from framework.cache import rate_limit_reset
    rate_limit_reset(f"login:{key}")
    with _login_lock:
        _login_attempts.pop(key, None)

class URLAnalyzeRequest(BaseModel):
    url: str
    mode: str = "AI"

class IMAPTestRequest(BaseModel):
    server: str = ""
    user: str = ""
    password: str = ""

class LoginRequest(BaseModel):
    username: str
    password: str

class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str

class ReviewRequest(BaseModel):
    verdict: str
    notes: str = ""

class PolicyRequest(BaseModel):
    name: str
    conditions: dict
    action: str
    severity: str = "Medium"
    enabled: bool = True

class CaseUpdateRequest(BaseModel):
    status: str
    assignee: str = ""
    notes: str = ""

class SimulationTriggerRequest(BaseModel):
    mode: str = "AI" # 'Manual' or 'AI'
    target_emails: str = "" # Comma separated list for Manual mode
    target_date: str = "" # Scheduled datetime for Manual mode
    delay_mode: bool = True

class UserCreateRequest(BaseModel):
    username: str
    password: str
    role: str = "viewer"
    email: str = ""
    full_name: str = ""

class UserUpdateRequest(BaseModel):
    role: Optional[str] = None
    active: Optional[bool] = None
    password: Optional[str] = None
    full_name: Optional[str] = None

class ApiKeyCreateRequest(BaseModel):
    name: str

class IngestEmailRequest(BaseModel):
    sender: str
    subject: str = ""
    body: str = ""
    recipient: str = "unknown"
    spf: str = "unknown"
    dkim: str = "unknown"
    dmarc: str = "unknown"

class IntelIndicatorRequest(BaseModel):
    type: str = "domain"
    value: str
    verdict: str = "block"
    source: str = "manual"
    description: str = ""
    confidence: int = 80

class RemediateRequest(BaseModel):
    actions: List[str] = ["notify"]

class ReportPhishingRequest(BaseModel):
    sender: str = "unknown"
    subject: str = ""
    body: str = ""
    reporter: str = ""
    notes: str = ""

class CopilotRequest(BaseModel):
    question: str

class AITestRequest(BaseModel):
    provider: str = ""
    api_key: str = ""
    base_url: str = ""
    model: str = ""

class PluginToggleRequest(BaseModel):
    enabled: bool = True

def _org_id(auth: dict) -> int:
    """Tenant id from a validated token payload (defaults to the primary org)."""
    try:
        return int(auth.get("org", 1))
    except (TypeError, ValueError):
        return 1

def _is_sensitive_key(key: str) -> bool:
    key_lower = key.lower()
    return any(marker in key_lower for marker in SENSITIVE_SETTING_MARKERS)

def _mask_settings(settings: dict) -> dict:
    masked = {}
    for key, value in settings.items():
        masked[key] = MASKED_SECRET if _is_sensitive_key(key) and value else value
    return masked

def _safe_upload_name(filename: str) -> str:
    base_name = os.path.basename(filename or "")
    safe_name = re.sub(r"[^A-Za-z0-9._-]", "_", base_name)
    if not safe_name or safe_name in {".", ".."}:
        raise HTTPException(status_code=400, detail="Invalid upload filename")
    if not safe_name.lower().endswith((".txt", ".csv")):
        raise HTTPException(status_code=400, detail="Only .txt and .csv target files are supported")
    return safe_name


@router.get("/stats")
def get_stats(days: int = Query(7, ge=1, le=365), _auth: dict = Depends(require_auth)):
    """Returns overall statistics for the dashboard."""
    conn = get_db_connection()
    c = conn.cursor()
    since = datetime.utcnow() - timedelta(days=days)
    org = _org_id(_auth)

    c.execute('SELECT COUNT(*) FROM emails WHERE organization_id = ?', (org,))
    total_emails = c.fetchone()[0]

    c.execute("SELECT COUNT(*) FROM emails WHERE organization_id = ? AND risk_score > 30 and risk_score <= 70", (org,))
    suspicious_emails = c.fetchone()[0]

    c.execute("SELECT COUNT(*) FROM quarantine q JOIN emails e ON q.email_id = e.id WHERE e.organization_id = ?", (org,))
    quarantined_emails = c.fetchone()[0]

    c.execute("SELECT COUNT(*) FROM simulations WHERE status = 'Running' AND organization_id = ?", (org,))
    active_sims = c.fetchone()[0]

    # Calculate a simplified average risk gauge over the selected period
    c.execute("SELECT AVG(risk_score) FROM emails WHERE organization_id = ? AND timestamp >= ?", (org, since))
    avg_risk = c.fetchone()[0] or 0

    # Check for recent critical activity
    c.execute("SELECT COUNT(*) FROM emails WHERE organization_id = ? AND risk_score > 70 AND timestamp >= ?", (org, since))
    critical_count = c.fetchone()[0] or 0
    has_critical_activity = critical_count > 0

    # Get trend based on selected days
    c.execute('''
        SELECT date(timestamp) as day, COUNT(*) as count
        FROM emails
        WHERE organization_id = ? AND risk_score > 50 AND timestamp >= ?
        GROUP BY date(timestamp)
        ORDER BY date(timestamp)
    ''', (org, since))
    trend_data = {str(row['day']): row['count'] for row in c.fetchall()}
    
    # Prepare last N days keys
    trend_labels = []
    trend_values = []
    
    # If the range is huge (like 365 days), maybe we still just show daily points, 
    # but for ChartJS daily is fine, it will auto-compress labels
    for i in range(days - 1, -1, -1):
        d = (datetime.now() - timedelta(days=i)).strftime('%Y-%m-%d')
        trend_labels.append(d)
        trend_values.append(trend_data.get(d, 0))

    conn.close()
    
    return {
        "total_emails_scanned": total_emails,
        "suspicious_emails": suspicious_emails,
        "quarantined_emails": quarantined_emails,
        "active_simulations": active_sims,
        "current_risk_level": int(avg_risk),
        "has_critical_activity": has_critical_activity,
        "trend_labels": trend_labels,
        "trend_values": trend_values
    }

@router.get("/emails")
def get_recent_emails(limit: int = Query(50, ge=1, le=200), _auth: dict = Depends(require_auth)):
    """Returns recent monitored emails for the Real-Time Monitor."""
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('SELECT * FROM emails WHERE organization_id = ? ORDER BY timestamp DESC LIMIT ?', (_org_id(_auth), limit))
    emails = [dict(row) for row in c.fetchall()]
    conn.close()
    return emails

async def event_stream(org_id: int):
    """Server-Sent Events stream generator for real-time, tenant-scoped updates."""
    last_id = 0

    # Get the current highest ID so we only send *new* items
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('SELECT MAX(id) FROM emails WHERE organization_id = ?', (org_id,))
    result = c.fetchone()[0]
    last_id = result if result else 0
    conn.close()

    while True:
        # Check for new emails belonging to this tenant
        conn = get_db_connection()
        c = conn.cursor()
        c.execute('SELECT * FROM emails WHERE organization_id = ? AND id > ? ORDER BY timestamp ASC', (org_id, last_id))
        new_emails = [dict(row) for row in c.fetchall()]

        # If new emails found, yield them and update last_id
        if new_emails:
            last_id = new_emails[-1]['id']
            # Send the new emails as a JSON string under the 'new_email' event type
            yield f"event: new_email\ndata: {json.dumps(new_emails)}\n\n"

            # Send a trigger to politely ask the frontend to refresh stats
            yield f"event: refresh_stats\ndata: true\n\n"

        conn.close()

        # Sleep before checking again
        await asyncio.sleep(2)

@router.get("/stream")
async def stream_updates(_auth: dict = Depends(require_auth)):
    """SSE endpoint for real-time dashboard updates."""
    return StreamingResponse(event_stream(_org_id(_auth)), media_type="text/event-stream")

@router.get("/quarantine")
def get_quarantined_items(_auth: dict = Depends(require_auth)):
    """Returns items currently in quarantine."""
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('''
        SELECT q.id as quarantine_id, q.recipient, q.ai_reason, q.quarantined_at, e.*
        FROM quarantine q
        JOIN emails e ON q.email_id = e.id
        WHERE e.organization_id = ?
        ORDER BY q.quarantined_at DESC
    ''', (_org_id(_auth),))
    quarantine_items = [dict(row) for row in c.fetchall()]
    conn.close()
    return quarantine_items

@router.get("/emails/{email_id}/timeline")
def get_email_timeline(email_id: int, _auth: dict = Depends(require_auth)):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('''
        SELECT event_type, details, created_at
        FROM email_timeline
        WHERE email_id = ?
        ORDER BY created_at ASC, id ASC
    ''', (email_id,))
    events = [dict(row) for row in c.fetchall()]
    conn.close()
    return events

@router.post("/analyze-url")
def analyze_url_endpoint(req: URLAnalyzeRequest, _auth: dict = Depends(require_auth)):
    """Deep scan a specific URL."""
    from services.ai_detector import analyze_email_hybrid, layer3_domain_intel

    if req.mode == "OpenSource":
        # Skip LLM, only run layer 3 domain intel (heuristics)
        d_score, d_features = layer3_domain_intel([req.url])
        explanation = "OpenSource Heuristics Check Completed (No AI Model Used)."
        if d_score > 50:
             explanation += f" High risk factors found: {d_features}"
        
        return {
            "llm_score": 0,
            "phishing_score": d_score,
            "url_threat_score": d_score,
            "threat_type": "Suspicious Link" if d_score > 50 else "Safe",
            "explanation": explanation,
            "features": d_features
        }
    else:
        # Full AI Hybrid pipeline
        # We wrap the URL in text to use the existing logic that extracts and evaluates URLs.
        result = analyze_email_hybrid(f"Check this link: {req.url}")
        return result

@router.get("/notifications")
def get_notifications(_auth: dict = Depends(require_auth)):
    """Returns top 5 latest high-risk alerts or quarantines for the bell dropdown."""
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('''
        SELECT 'quarantine' as type, q.quarantined_at as time, e.subject, q.ai_reason as details,
               e.id as email_id, e.status
        FROM quarantine q
        JOIN emails e ON q.email_id = e.id
        WHERE e.organization_id = ?
        ORDER BY q.quarantined_at DESC LIMIT 5
    ''', (_org_id(_auth),))
    notifications = [dict(row) for row in c.fetchall()]
    conn.close()
    return notifications

@router.get("/analytics")
def get_analytics(_auth: dict = Depends(require_auth)):
    """Returns data for the analytics risk charts and tables."""
    conn = get_db_connection()
    c = conn.cursor()
    
    # 1. Threat Distribution (reason text lives in ai_analysis_log; fall back to threat_type)
    c.execute("SELECT COALESCE(ai_analysis_log, threat_type, '') AS ai_reason FROM emails WHERE risk_score > 30 AND organization_id = ?", (_org_id(_auth),))
    reasons = c.fetchall()
    
    threat_counts = {
        "Credential Harvesting": 0,
        "Malware / Attachment": 0,
        "Urgency / Spear Phishing": 0,
        "Spam / Low Risk": 0
    }
    
    for row in reasons:
        reason = (row[0] or "").lower()
        if "credential" in reason or "login" in reason or "password" in reason:
            threat_counts["Credential Harvesting"] += 1
        elif "malware" in reason or "attachment" in reason or "macro" in reason or "payload" in reason:
            threat_counts["Malware / Attachment"] += 1
        elif "urgent" in reason or "immediate" in reason or "overdue" in reason or "wire" in reason:
            threat_counts["Urgency / Spear Phishing"] += 1
        else:
            threat_counts["Spam / Low Risk"] += 1
            
    # Default data if DB is completely empty to prevent empty charts
    if sum(threat_counts.values()) == 0:
        threat_counts = {"Credential Harvesting": 0, "Malware / Attachment": 0, "Urgency / Spear Phishing": 0, "Spam / Low Risk": 1}

    # 2. Department Vulnerability (recipient lives on the quarantine record)
    c.execute('''
        SELECT q.recipient AS recipient, COUNT(*) as incidents, AVG(e.risk_score) as avg_risk
        FROM emails e JOIN quarantine q ON q.email_id = e.id
        WHERE e.risk_score > 30 AND e.organization_id = ?
        GROUP BY q.recipient
    ''', (_org_id(_auth),))
    recipient_stats = c.fetchall()
    conn.close()
    
    departments = {"Sales": {"incidents": 0, "risk_sum": 0}, 
                   "Finance": {"incidents": 0, "risk_sum": 0}, 
                   "Engineering": {"incidents": 0, "risk_sum": 0},
                   "HR": {"incidents": 0, "risk_sum": 0},
                   "Executive": {"incidents": 0, "risk_sum": 0}}
                   
    for row in recipient_stats:
        rec = (row['recipient'] or "").lower()
        incidents = row['incidents']
        # Map recipient to department
        dept = "Engineering" # Default fallback
        if "sales" in rec or "marketing" in rec: dept = "Sales"
        elif "finance" in rec or "invoice" in rec or "billing" in rec: dept = "Finance"
        elif "hr" in rec or "career" in rec: dept = "HR"
        elif "ceo" in rec or "admin" in rec or "exec" in rec: dept = "Executive"
        
        departments[dept]["incidents"] += incidents
        departments[dept]["risk_sum"] += incidents * row['avg_risk']
        
    dept_list: list[dict[str, str | int | float]] = []
    for dept_name, stats in departments.items():
        if stats["incidents"] > 0:
            avg = float(stats["risk_sum"] / stats["incidents"])
            risk_level = "High" if avg > 70 else ("Med" if avg > 40 else "Low")
            dept_list.append({
                "name": str(dept_name),
                "incidents": int(stats["incidents"]),
                "risk_level": str(risk_level),
                "avg_risk": avg # for sorting
            })
            
    # Sort by risk (High -> Low) then incidents
    dept_list.sort(key=lambda x: (float(x["avg_risk"]), int(x["incidents"])), reverse=True)
    
    # Keep top 4
    top_depts = dept_list[:4]
    
    # Fallback if no data
    if not top_depts:
        top_depts = [
            {"name": "No Data Yet", "incidents": 0, "risk_level": "Low", "avg_risk": 0.0}
        ]

    return {
        "threat_distribution": {
            "labels": list(threat_counts.keys()),
            "data": list(threat_counts.values())
        },
        "departments": top_depts
    }

@router.get("/analytics/report/pdf")
def get_pdf_report(_auth: dict = Depends(require_auth)):
    """Generates and returns a detailed PDF report of phishing activity."""
    from services.gophish_client import get_api
    from services.report_generator import generate_analytics_pdf
    
    # 1. Get General Stats
    stats = get_stats(days=7, _auth=_auth)
    
    # 2. Get Simulation Results
    api = get_api()
    campaign_results = []
    
    if api:
        try:
            campaigns = api.campaigns.get()
            for camp in campaigns:
                # We only want results for campaigns that have finished or are active
                results_summary = {
                    "name": camp.name,
                    "status": camp.status,
                    "launch_date": camp.launch_date,
                    "results": {
                        "total": len(camp.results),
                        "clicked": sum(1 for r in camp.results if r.status in ["Clicked Link", "Submitted Data"])
                    },
                    "victims": []
                }
                
                # Identify specifically who fell for it
                for r in camp.results:
                    if r.status in ["Clicked Link", "Submitted Data"]:
                        results_summary["victims"].append({
                            "email": r.email,
                            "first_name": r.first_name,
                            "last_name": r.last_name
                        })
                
                campaign_results.append(results_summary)
        except Exception as e:
            logger.error(f"Error fetching campaign data for PDF: {e}")

    # 3. Generate PDF
    pdf_content = generate_analytics_pdf(stats, campaign_results)
    
    return Response(
        content=pdf_content,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=threat_report_{datetime.now().strftime('%Y%m%d')}.pdf"}
    )

@router.post("/emails/{email_id}/release")
def release_email(email_id: int, _auth: dict = Depends(require_role("analyst"))):
    """Releases an email from quarantine."""
    conn = get_db_connection()
    c = conn.cursor()
    # Delete from quarantine
    c.execute('DELETE FROM quarantine WHERE email_id = ?', (email_id,))
    # Update email status to 'Allowed' (simulating releasing to inbox)
    c.execute("UPDATE emails SET status = 'Allowed', review_status = 'Released' WHERE id = ?", (email_id,))
    c.execute('''
        INSERT INTO email_timeline (email_id, event_type, details)
        VALUES (?, 'released', 'Admin released message from quarantine')
    ''', (email_id,))
    c.execute('''
        INSERT INTO audit_log (actor, action, target_type, target_id, details)
        VALUES ('admin', 'email_released', 'email', ?, 'Released from quarantine')
    ''', (email_id,))
    conn.commit()
    conn.close()
    return {"status": "success", "message": f"Item {email_id} released"}

@router.delete("/emails/{email_id}")
def delete_email(email_id: int, _auth: dict = Depends(require_role("analyst"))):
    """Permanently deletes an email and its quarantine record."""
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('''
        INSERT INTO email_timeline (email_id, event_type, details)
        VALUES (?, 'deleted', 'Admin permanently deleted message')
    ''', (email_id,))
    c.execute('''
        INSERT INTO audit_log (actor, action, target_type, target_id, details)
        VALUES ('admin', 'email_deleted', 'email', ?, 'Permanently deleted')
    ''', (email_id,))
    c.execute('DELETE FROM quarantine WHERE email_id = ?', (email_id,))
    c.execute('DELETE FROM emails WHERE id = ?', (email_id,))
    conn.commit()
    conn.close()
    return {"status": "success", "message": f"Item {email_id} deleted"}

@router.post("/emails/{email_id}/review")
def review_email(email_id: int, req: ReviewRequest, _auth: dict = Depends(require_role("analyst"))):
    allowed = {
        "safe": "Marked Safe",
        "phishing": "Confirmed Phishing",
        "review": "Needs Review"
    }
    verdict_key = req.verdict.strip().lower()
    if verdict_key not in allowed:
        raise HTTPException(status_code=400, detail="Verdict must be one of: safe, phishing, review")

    review_status = allowed[verdict_key]
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT id FROM emails WHERE id = ?", (email_id,))
    if not c.fetchone():
        conn.close()
        raise HTTPException(status_code=404, detail="Email not found")

    c.execute("UPDATE emails SET review_status = ? WHERE id = ?", (review_status, email_id))
    c.execute('''
        INSERT INTO email_feedback (email_id, verdict, notes)
        VALUES (?, ?, ?)
    ''', (email_id, review_status, req.notes.strip()))
    c.execute('''
        INSERT INTO email_timeline (email_id, event_type, details)
        VALUES (?, 'reviewed', ?)
    ''', (email_id, f"{review_status}: {req.notes.strip()}" if req.notes.strip() else review_status))
    c.execute('''
        INSERT INTO audit_log (actor, action, target_type, target_id, details)
        VALUES (?, 'email_reviewed', 'email', ?, ?)
    ''', (_auth.get("sub", "analyst"), email_id, review_status))
    conn.commit()
    conn.close()

    # Feedback loop: teach the reputation model from this verdict.
    learned = {}
    try:
        from framework.learning import learn_from_verdict
        learned = learn_from_verdict(_org_id(_auth), email_id, review_status, _auth.get("sub", "analyst"))
    except Exception as e:
        logger.error(f"Learning from verdict failed: {e}")
    return {"status": "success", "review_status": review_status, "learned": learned}

@router.delete("/quarantine/empty/all")
def empty_quarantine(_auth: dict = Depends(require_role("analyst"))):
    """Permanently deletes all quarantined emails."""
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('DELETE FROM quarantine')
    conn.commit()
    conn.close()
    return {"status": "success", "message": "All quarantine items deleted"}

@router.post("/simulations/config")
def save_simulation_config(config: dict, _auth: dict = Depends(require_role("admin"))):
    """Saves simulation settings to the database."""
    conn = get_db_connection()
    c = conn.cursor()
    
    for key, value in config.items():
        # Prefix keys to avoid collision with main settings
        db_key = f"sim_{key}"
        c.execute('''
            INSERT INTO settings (key, value) 
            VALUES (?, ?) 
            ON CONFLICT(key) DO UPDATE SET value=excluded.value
        ''', (db_key, str(value)))
        
    conn.commit()
    conn.close()
    return {"status": "success", "message": "Simulation configuration saved"}

@router.get("/simulations/config")
def get_simulation_config(_auth: dict = Depends(require_auth)):
    """Retrieves saved simulation settings + whether GoPhish is wired up."""
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT key, value FROM settings WHERE key LIKE 'sim_%' OR key IN ('gophish_url', 'gophish_key')")
    settings_rows = c.fetchall()
    conn.close()

    settings_dict = {}
    gophish_url = ""
    gophish_key = ""
    for row in settings_rows:
        k, v = row["key"], row["value"]
        if k == "gophish_key":
            gophish_key = v or ""
        elif k == "gophish_url":
            gophish_url = v or ""
        else:
            settings_dict[k.replace("sim_", "")] = v
    # Report configured state without leaking the key (env fallback counts too).
    configured = bool(gophish_key or os.getenv("GOPHISH_API_KEY", ""))
    settings_dict["gophish_url"] = gophish_url or os.getenv("GOPHISH_URL", "")
    settings_dict["gophish_configured"] = configured
    settings_dict["gophish_api_key"] = "********" if configured else ""
    return settings_dict

@router.post("/simulations/targets/upload")
def upload_targets(file: UploadFile = File(...), _auth: dict = Depends(require_role("analyst"))):
    """Upload a CSV/TXT of employees (email, name, department) into the phishing roster."""
    from services.roster import parse_targets, store_targets, roster_summary
    _safe_upload_name(file.filename)  # validates extension (.txt/.csv)
    content_bytes = file.file.read(2 * 1024 * 1024 + 1)
    if len(content_bytes) > 2 * 1024 * 1024:
        raise HTTPException(status_code=400, detail="Upload too large. Maximum size is 2MB.")
    content = content_bytes.decode("utf-8", errors="ignore")
    targets = parse_targets(content)
    if not targets:
        raise HTTPException(status_code=400, detail="No valid email addresses found in the file.")
    org = _org_id(_auth)
    stored = store_targets(org, targets)
    audit_log("roster_uploaded", _auth.get("sub", "analyst"), "sim_targets", str(org), f"{stored} targets", organization_id=_org_id(_auth))
    return {
        "status": "success",
        "imported": stored,
        "summary": roster_summary(org),
        "preview": targets[:10],
    }

@router.get("/simulations/targets")
def list_targets(department: Optional[str] = Query(None), _auth: dict = Depends(require_auth)):
    """Returns the employee roster and a per-department summary."""
    from services.roster import get_targets, roster_summary
    org = _org_id(_auth)
    return {"summary": roster_summary(org), "targets": get_targets(org, department)}

@router.delete("/simulations/targets")
def clear_target_roster(_auth: dict = Depends(require_role("admin"))):
    from services.roster import clear_targets
    clear_targets(_org_id(_auth))
    return {"status": "success", "message": "Roster cleared"}

@router.get("/simulations/history")
def get_simulation_history(_auth: dict = Depends(require_auth)):
    """Returns launched campaigns with click stats (from GoPhish)."""
    from services.gophish_client import get_results
    data = get_results()
    return data.get("campaigns", [])

@router.get("/simulations/results")
def get_simulation_results(_auth: dict = Depends(require_auth)):
    """Full engagement breakdown: campaigns, per-department rates, and caught employees."""
    from services.gophish_client import get_results
    return get_results()

@router.post("/simulations/trigger")
def trigger_simulation(
    mode: str = Form("AI"),
    department: Optional[str] = Form(""),
    sample: Optional[int] = Form(0),
    theme: Optional[str] = Form(""),
    file: Optional[UploadFile] = File(None),
    _auth: dict = Depends(require_role("analyst"))
):
    """
    Launch a phishing simulation.
      - AI mode: LLM crafts the lure; targets come from the stored roster (optionally a department, optional random `sample`).
      - Manual mode: targets come from an uploaded CSV (also saved to the roster) or the stored roster/department.
    """
    from services.gophish_client import get_api, launch_campaign, _sim_config
    from services.roster import parse_targets, store_targets, get_targets
    from services.ai_generator import generate_phishing_email

    if not get_api():
        raise HTTPException(status_code=400, detail="GoPhish API is not configured. Set the GoPhish URL and API key in Settings.")

    org = _org_id(_auth)

    # Resolve the target list.
    targets = []
    if file is not None and file.filename:
        _safe_upload_name(file.filename)
        content_bytes = file.file.read(2 * 1024 * 1024 + 1)
        if len(content_bytes) > 2 * 1024 * 1024:
            raise HTTPException(status_code=400, detail="Upload too large. Maximum size is 2MB.")
        targets = parse_targets(content_bytes.decode("utf-8", errors="ignore"))
        if targets:
            store_targets(org, targets)  # persist the roster for reuse
    else:
        targets = get_targets(org, department or None)

    if not targets:
        raise HTTPException(status_code=400, detail="No targets. Upload a CSV of employees or add them to the roster first.")

    if mode == "AI" and sample and sample > 0 and sample < len(targets):
        import random as _random
        targets = _random.sample(targets, sample)

    # Craft the lure. AI mode always generates; Manual generates a neutral IT-notice lure.
    email_data = generate_phishing_email(
        target_name="Team Member",
        department=department or "All Staff",
        company="Current Organization",
        context=theme or ("AI-selected security awareness lure" if mode == "AI" else "IT security notice"),
    )

    name = f"{'AI' if mode == 'AI' else 'Manual'}-{datetime.now():%Y%m%d-%H%M}"
    result = launch_campaign(targets, email_data, campaign_name=name, cfg=_sim_config())
    if result.get("error"):
        raise HTTPException(status_code=502, detail=f"GoPhish campaign failed: {result['error']}")

    # Register the launched campaign locally.
    conn = get_db_connection()
    c = conn.cursor()
    c.execute(
        '''
        INSERT INTO sim_campaigns (organization_id, gophish_campaign_id, name, mode, theme, status, target_count, created_by)
        VALUES (?, ?, ?, ?, ?, 'Launched', ?, ?)
        ''',
        (org, result.get("campaign_id"), result.get("name", name), mode, theme or "", result.get("targets", len(targets)), _auth.get("sub", "analyst")),
    )
    conn.commit()
    conn.close()
    audit_log("simulation_launched", _auth.get("sub", "analyst"), "sim_campaign", str(result.get("campaign_id")), f"{mode}, {result.get('targets', len(targets))} targets", organization_id=_org_id(_auth))

    return {
        "status": "success",
        "message": f"{mode} simulation launched against {result.get('targets', len(targets))} targets",
        "campaign_id": result.get("campaign_id"),
        "name": result.get("name"),
    }

@router.post("/auth/login")
def login(req: LoginRequest, response: Response, request: Request = None):
    rate_key = _client_ip(request)
    _check_login_rate_limit(rate_key)

    # Same generic error + rate-limit accounting for bad username and bad password,
    # so the endpoint does not leak which of the two was wrong.
    def _reject():
        _record_login_failure(rate_key)
        try:
            audit_log("login_failed", rate_key, "auth", req.username, "Invalid credentials")
        except Exception:
            pass
        raise HTTPException(status_code=401, detail="Invalid credentials")

    conn = get_db_connection()
    c = conn.cursor()
    c.execute(
        "SELECT id, organization_id, username, password_hash, role, active "
        "FROM users WHERE LOWER(username) = LOWER(?)",
        (req.username.strip(),),
    )
    user = c.fetchone()
    conn.close()

    if not user or not user["active"] or not verify_password(req.password, user["password_hash"]):
        _reject()

    _reset_login_attempts(rate_key)
    identity = dict(user)
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("UPDATE users SET last_login_at = CURRENT_TIMESTAMP WHERE id = ?", (user["id"],))
    conn.commit()
    conn.close()
    try:
        audit_log("login_success", req.username, "auth", str(user["id"]), f"role={user['role']}")
    except Exception:
        pass

    # Establish the session via httpOnly access + refresh cookies (+ readable CSRF token).
    csrf = set_auth_cookies(response, identity)
    return {
        "message": "Login successful",
        "csrf_token": csrf,
        "user": {"username": user["username"], "role": user["role"], "organization_id": user["organization_id"]},
    }

@router.post("/auth/refresh")
def refresh_session(request: Request, response: Response):
    """Rotate the session: validate the refresh cookie, issue fresh access+refresh cookies."""
    from framework.security import decode_token, refresh_is_valid, revoke_refresh
    import jwt as _jwt
    rt = request.cookies.get("refresh_token")
    if not rt:
        raise HTTPException(status_code=401, detail="No refresh token")
    try:
        payload = decode_token(rt, expected_type="refresh")
    except _jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid refresh token")
    if not refresh_is_valid(payload.get("jti", "")):
        # Token already used/revoked (possible reuse) — force re-login.
        raise HTTPException(status_code=401, detail="Refresh token expired or revoked")
    revoke_refresh(payload["jti"])  # one-time use: rotate

    # Re-read the user so role/active changes take effect on refresh.
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT id, organization_id, username, role, active FROM users WHERE id = ?", (payload.get("uid"),))
    user = c.fetchone()
    conn.close()
    if not user or not user["active"]:
        raise HTTPException(status_code=401, detail="Account inactive")
    csrf = set_auth_cookies(response, dict(user))
    return {"message": "refreshed", "csrf_token": csrf,
            "user": {"username": user["username"], "role": user["role"], "organization_id": user["organization_id"]}}

@router.post("/auth/logout")
def logout(request: Request, response: Response):
    """End the session: revoke the refresh token and clear all auth cookies."""
    from framework.security import decode_token, revoke_refresh, clear_auth_cookies
    rt = request.cookies.get("refresh_token")
    if rt:
        try:
            revoke_refresh(decode_token(rt).get("jti", ""))
        except Exception:
            pass
    clear_auth_cookies(response)
    return {"message": "Logged out"}

@router.get("/auth/me")
def whoami(_auth: dict = Depends(require_auth)):
    """Return the current identity so the frontend can gate UI by role."""
    return {
        "username": _auth.get("sub"),
        "user_id": _auth.get("uid"),
        "organization_id": _org_id(_auth),
        "role": _auth.get("role", "viewer"),
    }

@router.post("/auth/change-password")
def change_password(req: ChangePasswordRequest, _auth: dict = Depends(require_auth)):
    user_id = _auth.get("uid")
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT password_hash FROM users WHERE id = ?", (user_id,))
    row = c.fetchone()
    if not row or not verify_password(req.current_password, row["password_hash"]):
        conn.close()
        raise HTTPException(status_code=401, detail="Incorrect current password")
    if len(req.new_password) < 8:
        conn.close()
        raise HTTPException(status_code=400, detail="New password must be at least 8 characters")
    c.execute("UPDATE users SET password_hash = ? WHERE id = ?", (hash_password(req.new_password), user_id))
    c.execute('''
        INSERT INTO audit_log (actor, action, target_type, target_id, details)
        VALUES (?, 'password_changed', 'user', ?, 'Self-service password change')
    ''', (_auth.get("sub", "user"), str(user_id)))
    conn.commit()
    conn.close()
    return {"message": "Password updated successfully"}

# ------------------------------- User management --------------------------------
@router.get("/users")
def list_users(_auth: dict = Depends(require_role("admin"))):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute(
        "SELECT id, username, email, full_name, role, active, created_at, last_login_at "
        "FROM users WHERE organization_id = ? ORDER BY id ASC",
        (_org_id(_auth),),
    )
    rows = [dict(row) for row in c.fetchall()]
    conn.close()
    return rows

@router.post("/users")
def create_user(req: UserCreateRequest, _auth: dict = Depends(require_role("admin"))):
    username = req.username.strip().lower()
    if not username or len(req.password) < 8:
        raise HTTPException(status_code=400, detail="Username required and password must be at least 8 characters")
    if req.role not in VALID_ROLES:
        raise HTTPException(status_code=400, detail=f"Role must be one of: {', '.join(sorted(VALID_ROLES))}")
    # Only an owner may mint another owner.
    if req.role == "owner" and _auth.get("role") != "owner":
        raise HTTPException(status_code=403, detail="Only an owner can create another owner")
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT 1 FROM users WHERE LOWER(username) = ?", (username,))
    if c.fetchone():
        conn.close()
        raise HTTPException(status_code=409, detail="Username already exists")
    c.execute('''
        INSERT INTO users (organization_id, username, email, full_name, password_hash, role)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (_org_id(_auth), username, req.email.strip(), req.full_name.strip(), hash_password(req.password), req.role))
    new_id = c.lastrowid
    c.execute('''
        INSERT INTO audit_log (actor, action, target_type, target_id, details)
        VALUES (?, 'user_created', 'user', ?, ?)
    ''', (_auth.get("sub", "admin"), str(new_id), f"{username} ({req.role})"))
    conn.commit()
    conn.close()
    return {"status": "success", "id": new_id, "username": username, "role": req.role}

@router.post("/users/{user_id}")
def update_user(user_id: int, req: UserUpdateRequest, _auth: dict = Depends(require_role("admin"))):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT id, username, role FROM users WHERE id = ? AND organization_id = ?", (user_id, _org_id(_auth)))
    target = c.fetchone()
    if not target:
        conn.close()
        raise HTTPException(status_code=404, detail="User not found")

    if req.role is not None:
        if req.role not in VALID_ROLES:
            conn.close()
            raise HTTPException(status_code=400, detail="Invalid role")
        if req.role == "owner" and _auth.get("role") != "owner":
            conn.close()
            raise HTTPException(status_code=403, detail="Only an owner can grant owner")
        c.execute("UPDATE users SET role = ? WHERE id = ?", (req.role, user_id))
    if req.active is not None:
        if not req.active and target["id"] == _auth.get("uid"):
            conn.close()
            raise HTTPException(status_code=400, detail="You cannot deactivate your own account")
        c.execute("UPDATE users SET active = ? WHERE id = ?", (req.active, user_id))
    if req.full_name is not None:
        c.execute("UPDATE users SET full_name = ? WHERE id = ?", (req.full_name.strip(), user_id))
    if req.password is not None:
        if len(req.password) < 8:
            conn.close()
            raise HTTPException(status_code=400, detail="Password must be at least 8 characters")
        c.execute("UPDATE users SET password_hash = ? WHERE id = ?", (hash_password(req.password), user_id))

    c.execute('''
        INSERT INTO audit_log (actor, action, target_type, target_id, details)
        VALUES (?, 'user_updated', 'user', ?, ?)
    ''', (_auth.get("sub", "admin"), str(user_id), target["username"]))
    conn.commit()
    conn.close()
    return {"status": "success"}

@router.delete("/users/{user_id}")
def delete_user(user_id: int, _auth: dict = Depends(require_role("admin"))):
    if user_id == _auth.get("uid"):
        raise HTTPException(status_code=400, detail="You cannot delete your own account")
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT username, role FROM users WHERE id = ? AND organization_id = ?", (user_id, _org_id(_auth)))
    target = c.fetchone()
    if not target:
        conn.close()
        raise HTTPException(status_code=404, detail="User not found")
    # Never allow removing the last owner of a tenant.
    if target["role"] == "owner":
        c.execute("SELECT COUNT(*) FROM users WHERE organization_id = ? AND role = 'owner' AND active = TRUE", (_org_id(_auth),))
        if c.fetchone()[0] <= 1:
            conn.close()
            raise HTTPException(status_code=400, detail="Cannot delete the last owner")
    c.execute("DELETE FROM users WHERE id = ?", (user_id,))
    c.execute('''
        INSERT INTO audit_log (actor, action, target_type, target_id, details)
        VALUES (?, 'user_deleted', 'user', ?, ?)
    ''', (_auth.get("sub", "admin"), str(user_id), target["username"]))
    conn.commit()
    conn.close()
    return {"status": "success"}

# ------------------------------- API key management -----------------------------
@router.get("/keys")
def list_api_keys(_auth: dict = Depends(require_role("admin"))):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute(
        "SELECT id, name, active, created_at, last_used_at, created_by "
        "FROM api_keys WHERE organization_id = ? ORDER BY id DESC",
        (_org_id(_auth),),
    )
    rows = [dict(row) for row in c.fetchall()]
    conn.close()
    return rows

@router.post("/keys")
def create_api_key(req: ApiKeyCreateRequest, _auth: dict = Depends(require_role("admin"))):
    if not req.name.strip():
        raise HTTPException(status_code=400, detail="Key name is required")
    plaintext = generate_api_key()
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('''
        INSERT INTO api_keys (organization_id, name, key_hash, active, created_by)
        VALUES (?, ?, ?, TRUE, ?)
    ''', (_org_id(_auth), req.name.strip(), hash_api_key(plaintext), _auth.get("sub", "admin")))
    key_id = c.lastrowid
    c.execute('''
        INSERT INTO audit_log (actor, action, target_type, target_id, details)
        VALUES (?, 'api_key_created', 'api_key', ?, ?)
    ''', (_auth.get("sub", "admin"), str(key_id), req.name.strip()))
    conn.commit()
    conn.close()
    # The plaintext key is shown exactly once.
    return {"status": "success", "id": key_id, "name": req.name.strip(), "api_key": plaintext}

@router.delete("/keys/{key_id}")
def revoke_api_key(key_id: int, _auth: dict = Depends(require_role("admin"))):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("UPDATE api_keys SET active = FALSE WHERE id = ? AND organization_id = ?", (key_id, _org_id(_auth)))
    c.execute('''
        INSERT INTO audit_log (actor, action, target_type, target_id, details)
        VALUES (?, 'api_key_revoked', 'api_key', ?, 'Key revoked')
    ''', (_auth.get("sub", "admin"), str(key_id)))
    conn.commit()
    conn.close()
    return {"status": "success", "message": f"Key {key_id} revoked"}

# ------------------------------- Machine ingestion API --------------------------
@router.post("/v1/emails")
def ingest_email(req: IngestEmailRequest, _key: dict = Depends(require_api_key)):
    """
    Programmatic email ingestion for gateways/connectors, authenticated by API key
    and scoped to the key's tenant. Runs the full hybrid detection pipeline.
    """
    from services.ingest import persist_detection

    content = f"Subject: {req.subject}\nBody: {req.body}"
    metadata = {"spf": req.spf, "dkim": req.dkim, "dmarc": req.dmarc}
    analysis = analyze_email_hybrid(content, metadata)

    conn = get_db_connection()
    c = conn.cursor()
    try:
        result = persist_detection(
            c,
            organization_id=_key["organization_id"],
            sender=req.sender,
            subject=req.subject,
            recipient=req.recipient,
            content=content,
            analysis=analysis,
            attachments=[],
            source=f"api:{_key.get('api_key_name', 'key')}",
        )
        conn.commit()
    except Exception as e:
        conn.rollback()
        conn.close()
        logger.error(f"Ingestion failed: {e}")
        raise HTTPException(status_code=500, detail="Ingestion failed")
    conn.close()
    return {
        "status": "success",
        "email_id": result["email_id"],
        "verdict": result["status"],
        "threat_type": result["threat_type"],
        "risk_score": result["phishing_score"],
        "is_threat": result["is_threat"],
        "recommended_action": result["recommended_action"],
    }

@router.get("/settings")
def get_settings(_auth: dict = Depends(require_auth)):
    """Returns the current settings from the database."""
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('SELECT key, value FROM settings')
    settings_rows = c.fetchall()
    conn.close()

    settings_dict = {row['key']: row['value'] for row in settings_rows if row['key'] not in INTERNAL_SETTING_KEYS}
    return _mask_settings(settings_dict)

@router.post("/settings")
def update_settings(settings: dict, _auth: dict = Depends(require_role("admin"))):
    """Updates settings in the database dynamically."""
    conn = get_db_connection()
    c = conn.cursor()
    
    for key, value in settings.items():
        if key in INTERNAL_SETTING_KEYS:
            continue
        if _is_sensitive_key(key) and str(value) == MASKED_SECRET:
            continue
        from framework.secretbox import encrypt_setting
        c.execute('''
            INSERT INTO settings (key, value)
            VALUES (?, ?)
            ON CONFLICT(key) DO UPDATE SET value=excluded.value
        ''', (key, encrypt_setting(key, str(value))))

    c.execute('''
        INSERT INTO audit_log (actor, action, target_type, target_id, details)
        VALUES ('admin', 'settings_updated', 'settings', 'global', ?)
    ''', (", ".join(sorted(settings.keys())),))
        
    conn.commit()
    conn.close()
    
    return {"status": "success", "message": "Settings saved successfully."}

@router.get("/framework/status")
def framework_status(_auth: dict = Depends(require_auth)):
    conn = get_db_connection()
    c = conn.cursor()
    counts = {}
    for table in ["policies", "cases", "audit_log", "domain_intel_cache", "attachments", "iocs", "siem_events", "playbooks", "detection_rules"]:
        c.execute(f"SELECT COUNT(*) FROM {table}")
        counts[table] = c.fetchone()[0]
    conn.close()
    return {
        "status": "ready",
        "modules": ["policy_engine", "plugin_detection_engines", "case_management", "audit_log", "domain_intel_cache", "attachment_metadata", "ioc_extraction", "mitre_mapping", "siem_export", "soar_playbooks", "detection_as_code"],
        "counts": counts
    }

@router.get("/policies")
def list_policies(_auth: dict = Depends(require_auth)):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM policies ORDER BY id ASC")
    policies = [dict(row) for row in c.fetchall()]
    conn.close()
    for policy in policies:
        try:
            policy["conditions"] = json.loads(policy.pop("conditions_json") or "{}")
        except Exception:
            policy["conditions"] = {}
    return policies

@router.post("/policies")
def create_policy(req: PolicyRequest, _auth: dict = Depends(require_role("admin"))):
    if req.action not in {"allow", "quarantine", "hold_for_review"}:
        raise HTTPException(status_code=400, detail="Action must be allow, quarantine, or hold_for_review")
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('''
        INSERT INTO policies (organization_id, name, conditions_json, action, severity, enabled)
        VALUES (1, ?, ?, ?, ?, ?)
    ''', (req.name, json.dumps(req.conditions), req.action, req.severity, req.enabled))
    policy_id = c.lastrowid
    c.execute('''
        INSERT INTO audit_log (actor, action, target_type, target_id, details)
        VALUES ('admin', 'policy_created', 'policy', ?, ?)
    ''', (policy_id, req.name))
    conn.commit()
    conn.close()
    return {"status": "success", "id": policy_id}

@router.get("/cases")
def list_cases(_auth: dict = Depends(require_auth)):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('''
        SELECT c.*, e.sender, e.subject, e.risk_score
        FROM cases c
        LEFT JOIN emails e ON c.email_id = e.id
        WHERE c.organization_id = ?
        ORDER BY c.created_at DESC
    ''', (_org_id(_auth),))
    cases = [dict(row) for row in c.fetchall()]
    conn.close()
    return cases

@router.post("/cases/{case_id}")
def update_case(case_id: int, req: CaseUpdateRequest, _auth: dict = Depends(require_role("analyst"))):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('''
        UPDATE cases
        SET status = ?, assignee = ?, updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
    ''', (req.status, req.assignee, case_id))
    # SLA tracking: stamp first response on first move off 'Open', and resolution on close.
    c.execute(
        "UPDATE cases SET first_response_at = CURRENT_TIMESTAMP "
        "WHERE id = ? AND first_response_at IS NULL AND status <> 'Open'",
        (case_id,),
    )
    if req.status in ("Closed", "Resolved"):
        c.execute(
            "UPDATE cases SET resolved_at = CURRENT_TIMESTAMP WHERE id = ? AND resolved_at IS NULL",
            (case_id,),
        )
    c.execute('''
        INSERT INTO case_events (case_id, event_type, details)
        VALUES (?, 'updated', ?)
    ''', (case_id, req.notes or f"Status changed to {req.status}"))
    c.execute('''
        INSERT INTO audit_log (actor, action, target_type, target_id, details)
        VALUES (?, 'case_updated', 'case', ?, ?)
    ''', (_auth.get("sub", "analyst"), case_id, req.status))
    conn.commit()
    conn.close()
    return {"status": "success"}

@router.get("/audit-log")
def get_audit_log(limit: int = Query(100, ge=1, le=500), _auth: dict = Depends(require_auth)):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM audit_log WHERE organization_id = ? ORDER BY created_at DESC LIMIT ?", (_org_id(_auth), limit))
    rows = [dict(row) for row in c.fetchall()]
    conn.close()
    return rows

@router.get("/iocs")
def list_iocs(limit: int = Query(200, ge=1, le=1000), _auth: dict = Depends(require_auth)):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('''
        SELECT i.*, e.subject, e.sender
        FROM iocs i
        JOIN emails e ON i.email_id = e.id
        WHERE e.organization_id = ?
        ORDER BY i.created_at DESC
        LIMIT ?
    ''', (_org_id(_auth), limit))
    rows = [dict(row) for row in c.fetchall()]
    conn.close()
    return rows

@router.get("/mitre-mappings")
def list_mitre_mappings(limit: int = Query(200, ge=1, le=1000), _auth: dict = Depends(require_auth)):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('''
        SELECT m.*, e.subject, e.sender, e.risk_score
        FROM mitre_mappings m
        JOIN emails e ON m.email_id = e.id
        WHERE e.organization_id = ?
        ORDER BY m.created_at DESC
        LIMIT ?
    ''', (_org_id(_auth), limit))
    rows = [dict(row) for row in c.fetchall()]
    conn.close()
    return rows

@router.get("/siem-events")
def list_siem_events(limit: int = Query(100, ge=1, le=500), _auth: dict = Depends(require_auth)):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM siem_events WHERE organization_id = ? ORDER BY created_at DESC LIMIT ?", (_org_id(_auth), limit))
    rows = [dict(row) for row in c.fetchall()]
    conn.close()
    return rows

@router.post("/siem-events/replay")
def replay_siem_events(limit: int = Query(50, ge=1, le=500), _auth: dict = Depends(require_role("admin"))):
    """Re-dispatch alerts that ultimately failed to reach the SIEM."""
    from framework.siem import replay_failed
    return replay_failed(limit)

@router.get("/playbooks")
def list_playbooks(_auth: dict = Depends(require_auth)):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM playbooks ORDER BY id ASC")
    rows = [dict(row) for row in c.fetchall()]
    conn.close()
    for row in rows:
        try:
            row["steps"] = json.loads(row.pop("steps_json") or "[]")
        except Exception:
            row["steps"] = []
    return rows

@router.get("/detection-rules")
def list_detection_rules(_auth: dict = Depends(require_auth)):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM detection_rules ORDER BY severity DESC, rule_id ASC")
    rows = [dict(row) for row in c.fetchall()]
    conn.close()
    for row in rows:
        try:
            row["conditions"] = json.loads(row.pop("conditions_json") or "{}")
        except Exception:
            row["conditions"] = {}
    return rows

# ------------------------------- SOC operations ---------------------------------
@router.get("/soc/metrics")
def soc_metrics(_auth: dict = Depends(require_auth)):
    """SLA / MTTD / MTTR and open-case metrics for the SOC dashboard."""
    from framework.soc_metrics import get_metrics
    return get_metrics(_org_id(_auth))

@router.get("/triage")
def triage_queue(limit: int = Query(50, ge=1, le=200), _auth: dict = Depends(require_auth)):
    """Prioritised analyst worklist of emails needing attention."""
    from framework.soc_metrics import get_triage_queue
    return get_triage_queue(_org_id(_auth), limit)

@router.get("/attack/coverage")
def attack_coverage(_auth: dict = Depends(require_auth)):
    """MITRE ATT&CK coverage: defended (by rules) vs observed (in traffic)."""
    from framework.attack import get_coverage
    return get_coverage(_org_id(_auth))

# ------------------------------- Phishing corpus --------------------------------
@router.get("/corpus/stats")
def corpus_statistics(_auth: dict = Depends(require_auth)):
    """What phishing knowledge the detector currently has loaded."""
    from framework.phish_corpus import corpus_stats
    return corpus_stats()

@router.get("/corpus/techniques")
def corpus_techniques(
    lure: str = Query("", description="filter by pretext family"),
    role: str = Query("", description="filter by target role"),
    limit: int = Query(100, ge=1, le=500),
    _auth: dict = Depends(require_auth),
):
    """Browse the phishing-technique library (used by Simulations to pick a lure)."""
    from framework.phish_corpus import load_corpus
    techniques = load_corpus().get("techniques", [])
    if lure:
        techniques = [t for t in techniques if t["lure"] == lure]
    if role:
        techniques = [t for t in techniques if t.get("target_role") == role]
    techniques = sorted(techniques, key=lambda t: -t.get("severity", 0))[:limit]
    return {
        "count": len(techniques),
        "lures": sorted({t["lure"] for t in load_corpus().get("techniques", [])}),
        "techniques": techniques,
    }

# ------------------------------- Threat intelligence ----------------------------
@router.get("/intel/indicators")
def list_intel(limit: int = Query(200, ge=1, le=1000), _auth: dict = Depends(require_auth)):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute(
        "SELECT id, type, value, verdict, source, description, confidence, hits, expires_at, created_by, created_at "
        "FROM intel_indicators WHERE organization_id = ? ORDER BY created_at DESC LIMIT ?",
        (_org_id(_auth), limit),
    )
    rows = [dict(row) for row in c.fetchall()]
    conn.close()
    return rows

@router.post("/intel/indicators")
def add_intel(req: IntelIndicatorRequest, _auth: dict = Depends(require_role("analyst"))):
    from framework.threat_intel import add_indicator
    if not req.value.strip():
        raise HTTPException(status_code=400, detail="Indicator value is required")
    if req.verdict not in {"block", "allow", "suspicious"}:
        raise HTTPException(status_code=400, detail="verdict must be block, allow, or suspicious")
    new_id = add_indicator(_org_id(_auth), {
        "type": req.type, "value": req.value, "verdict": req.verdict,
        "source": req.source or "manual", "description": req.description,
        "confidence": req.confidence, "created_by": _auth.get("sub", "analyst"),
    })
    audit_log("intel_added", _auth.get("sub", "analyst"), "intel", str(new_id), f"{req.verdict}:{req.value}", organization_id=_org_id(_auth))
    return {"status": "success", "id": new_id}

@router.delete("/intel/indicators/{indicator_id}")
def delete_intel(indicator_id: int, _auth: dict = Depends(require_role("admin"))):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("DELETE FROM intel_indicators WHERE id = ? AND organization_id = ?", (indicator_id, _org_id(_auth)))
    conn.commit()
    conn.close()
    return {"status": "success"}

# ------------------------------- Remediation / response -------------------------
@router.post("/emails/{email_id}/remediate")
def remediate_email(email_id: int, req: RemediateRequest, _auth: dict = Depends(require_role("analyst"))):
    """Run response actions (notify / ticket / clawback / block_ioc) for an email."""
    from framework.integrations import run_remediation
    allowed = {"notify", "ticket", "clawback", "block_ioc"}
    actions = [a for a in req.actions if a in allowed]
    if not actions:
        raise HTTPException(status_code=400, detail=f"actions must be a subset of {sorted(allowed)}")

    org = _org_id(_auth)
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT sender, subject, risk_score, threat_type, recommended_action FROM emails WHERE id = ? AND organization_id = ?", (email_id, org))
    row = c.fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="Email not found")

    context = {
        "sender": row["sender"], "subject": row["subject"], "risk_score": row["risk_score"],
        "threat_type": row["threat_type"], "recommended_action": row["recommended_action"],
    }
    results = run_remediation(org, email_id, actions, context, created_by=_auth.get("sub", "analyst"))
    audit_log("email_remediated", _auth.get("sub", "analyst"), "email", str(email_id), ",".join(actions), organization_id=_org_id(_auth))
    return {"status": "success", "results": results}

@router.get("/remediation")
def list_remediation(limit: int = Query(100, ge=1, le=500), _auth: dict = Depends(require_auth)):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute(
        "SELECT * FROM remediation_actions WHERE organization_id = ? ORDER BY created_at DESC LIMIT ?",
        (_org_id(_auth), limit),
    )
    rows = [dict(row) for row in c.fetchall()]
    conn.close()
    return rows

# ------------------------------- User-reported phishing -------------------------
@router.post("/report-phishing")
def report_phishing(req: ReportPhishingRequest, _auth: dict = Depends(require_auth)):
    """Intake a user-reported suspicious email: analyse, store, and open a report."""
    from services.ingest import persist_detection
    org = _org_id(_auth)
    content = f"Subject: {req.subject}\nBody: {req.body}"
    analysis = analyze_email_hybrid(content, {})

    conn = get_db_connection()
    c = conn.cursor()
    try:
        result = persist_detection(
            c, organization_id=org, sender=req.sender, subject=req.subject,
            recipient=req.reporter or "unknown", content=content, analysis=analysis,
            attachments=[], source="user_report",
        )
        c.execute(
            '''
            INSERT INTO phishing_reports (organization_id, email_id, reporter, notes, verdict, risk_score, status)
            VALUES (?, ?, ?, ?, ?, ?, 'New')
            ''',
            (org, result["email_id"], req.reporter or _auth.get("sub", ""), req.notes,
             result["threat_type"], result["phishing_score"]),
        )
        conn.commit()
    except Exception as e:
        conn.rollback()
        conn.close()
        logger.error(f"Report intake failed: {e}")
        raise HTTPException(status_code=500, detail="Report intake failed")
    conn.close()
    return {
        "status": "success",
        "email_id": result["email_id"],
        "verdict": result["threat_type"],
        "risk_score": result["phishing_score"],
        "is_threat": result["is_threat"],
    }

@router.get("/reports")
def list_reports(limit: int = Query(100, ge=1, le=500), _auth: dict = Depends(require_auth)):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute(
        '''
        SELECT r.*, e.sender, e.subject, e.status AS email_status
        FROM phishing_reports r LEFT JOIN emails e ON r.email_id = e.id
        WHERE r.organization_id = ? ORDER BY r.created_at DESC LIMIT ?
        ''',
        (_org_id(_auth), limit),
    )
    rows = [dict(row) for row in c.fetchall()]
    conn.close()
    return rows

# ------------------------------- Campaign clustering ----------------------------
@router.get("/campaigns/clusters")
def campaign_clusters(days: int = Query(14, ge=1, le=90), _auth: dict = Depends(require_auth)):
    """Group recent inbound threats into likely campaigns."""
    from framework.clustering import cluster_emails
    return cluster_emails(_org_id(_auth), days=days)

# ------------------------------- AI SOC copilot ---------------------------------
@router.post("/copilot")
def copilot_ask(req: CopilotRequest, _auth: dict = Depends(require_auth)):
    """Natural-language Q&A grounded in this tenant's detections."""
    from framework.copilot import ask
    if not req.question.strip():
        raise HTTPException(status_code=400, detail="Question is required")
    return ask(_org_id(_auth), req.question.strip())

@router.get("/emails/{email_id}/investigate")
def investigate(email_id: int, _auth: dict = Depends(require_auth)):
    """AI-written investigation narrative for a single email."""
    from framework.copilot import investigate_email
    result = investigate_email(_org_id(_auth), email_id)
    if result.get("error"):
        raise HTTPException(status_code=404, detail=result["error"])
    return result

# ------------------------------- Adaptive learning -----------------------------
@router.get("/learning/summary")
def learning_summary_endpoint(_auth: dict = Depends(require_auth)):
    """Feedback-loop health: false positives, confirmed phishing, learned reputation, repeat clickers."""
    from framework.learning import learning_summary
    return learning_summary(_org_id(_auth))

@router.get("/learning/reputation")
def learning_reputation(limit: int = Query(100, ge=1, le=1000), _auth: dict = Depends(require_auth)):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute(
        "SELECT id, kind, value, score, confirmed_count, safe_count, updated_at FROM reputation "
        "WHERE organization_id = ? ORDER BY ABS(score) DESC LIMIT ?",
        (_org_id(_auth), limit),
    )
    rows = [dict(row) for row in c.fetchall()]
    conn.close()
    return rows

@router.post("/simulations/sync-behavior")
def sync_sim_behavior_endpoint(_auth: dict = Depends(require_role("analyst"))):
    """Fold GoPhish click/submit outcomes into employee behavioural risk (raises future scrutiny)."""
    from framework.learning import sync_sim_behavior
    result = sync_sim_behavior(_org_id(_auth))
    audit_log("sim_behavior_synced", _auth.get("sub", "analyst"), "user_profiles", str(_org_id(_auth)), str(result), organization_id=_org_id(_auth))
    return result

# ------------------------------- Plugins (.tap) ---------------------------------
@router.get("/plugins")
def list_plugins_endpoint(_auth: dict = Depends(require_auth)):
    from framework.plugins import list_plugins
    return list_plugins(_org_id(_auth))

@router.post("/plugins/upload")
def upload_plugin(file: UploadFile = File(...), _auth: dict = Depends(require_role("admin"))):
    """Upload and install a .tap plugin (declarative detection content — no code execution)."""
    from framework.plugins import parse_tap, install_plugin, PluginError
    name = (file.filename or "").lower()
    if not name.endswith(".tap") and not name.endswith(".json"):
        raise HTTPException(status_code=400, detail="Plugin file must have a .tap extension")
    raw = file.file.read(2 * 1024 * 1024 + 1)
    if len(raw) > 2 * 1024 * 1024:
        raise HTTPException(status_code=400, detail="Plugin too large (max 2MB)")
    try:
        tap = parse_tap(raw)
        result = install_plugin(_org_id(_auth), tap, installed_by=_auth.get("sub", "admin"))
    except PluginError as e:
        raise HTTPException(status_code=400, detail=f"Invalid plugin: {e}")
    except Exception as e:
        logger.error(f"Plugin install failed: {e}")
        raise HTTPException(status_code=500, detail="Plugin install failed")
    audit_log("plugin_installed", _auth.get("sub", "admin"), "plugin", result["plugin_id"],
              f"{result['name']} signed={result['signed']}")
    return {"status": "success", **result}

@router.post("/plugins/{plugin_id}/toggle")
def toggle_plugin(plugin_id: str, req: PluginToggleRequest, _auth: dict = Depends(require_role("admin"))):
    from framework.plugins import set_enabled
    if not set_enabled(_org_id(_auth), plugin_id, req.enabled):
        raise HTTPException(status_code=404, detail="Plugin not found")
    audit_log("plugin_toggled", _auth.get("sub", "admin"), "plugin", plugin_id, f"enabled={req.enabled}")
    return {"status": "success", "enabled": req.enabled}

@router.delete("/plugins/{plugin_id}")
def delete_plugin(plugin_id: str, _auth: dict = Depends(require_role("admin"))):
    from framework.plugins import remove_plugin
    if not remove_plugin(_org_id(_auth), plugin_id):
        raise HTTPException(status_code=404, detail="Plugin not found")
    audit_log("plugin_removed", _auth.get("sub", "admin"), "plugin", plugin_id, "uninstalled")
    return {"status": "success", "message": f"Plugin {plugin_id} removed"}


def _saved_settings(keys: tuple) -> dict:
    conn = get_db_connection()
    c = conn.cursor()
    placeholders = ",".join(["?"] * len(keys))
    c.execute(f"SELECT key, value FROM settings WHERE key IN ({placeholders})", keys)
    from framework.secretbox import decrypt_setting
    rows = {row["key"]: decrypt_setting(row["key"], row["value"]) for row in c.fetchall()}
    conn.close()
    return rows


@router.post("/settings/test-siem")
def test_siem_connection(_auth: dict = Depends(require_role("admin"))):
    """Send a synthetic alert to the configured SIEM and report delivery status."""
    from framework.siem import siem_config, send_to_siem
    cfg = siem_config()
    if not cfg["webhook_url"]:
        raise HTTPException(status_code=400, detail="No SIEM webhook URL configured. Save the SIEM settings first.")
    result = send_to_siem("threateye.connectivity_test", {
        "email_id": 0,
        "organization_id": _org_id(_auth),
        "sender": "test@threateye.local",
        "recipient": "soc@corp.local",
        "subject": "ThreatEye SIEM connectivity test",
        "risk_score": 0,
        "threat_type": "Test",
        "policy": {}, "mitre": {}, "iocs": [], "rule_matches": [],
    }, cfg)
    if result["status"] != "sent":
        raise HTTPException(
            status_code=400,
            detail=f"SIEM test failed (HTTP {result.get('response_code')}): {result.get('error') or result['status']}",
        )
    return {"status": "success", "response_code": result["response_code"],
            "destination": cfg["webhook_url"], "format": cfg["format"]}


@router.post("/settings/test-imap")
def test_imap_connection(req: IMAPTestRequest, _auth: dict = Depends(require_role("admin"))):
    """
    Test IMAP credentials. Blank or masked fields fall back to the saved settings,
    so the button works on an already-saved config without re-typing the password.
    """
    server, user, password = req.server.strip(), req.user.strip(), req.password
    if not server or not user or not password or password == MASKED_SECRET:
        saved = _saved_settings(("imap_server", "imap_user", "imap_pass"))
        server = server or saved.get("imap_server", "")
        user = user or saved.get("imap_user", "")
        if not password or password == MASKED_SECRET:
            password = saved.get("imap_pass", "")

    if not (server and user and password):
        raise HTTPException(status_code=400, detail="Provide IMAP server, username and password (or save them first).")

    try:
        from imap_tools import MailBoxUnencrypted, MailBox
        # Try unencrypted first for local labs, fallback to SSL.
        try:
            with MailBoxUnencrypted(server).login(user, password) as mailbox:
                mailbox.folder.status('INBOX')
        except Exception:
            with MailBox(server).login(user, password) as mailbox:
                mailbox.folder.status('INBOX')
        return {"status": "success", "message": f"Successfully connected to {server} as {user}."}
    except Exception as e:
        logger.error(f"IMAP Test failed: {e}")
        raise HTTPException(status_code=400, detail=f"Connection failed: {str(e)[:300]}")


@router.post("/settings/test-ai")
def test_ai_connection(req: AITestRequest, _auth: dict = Depends(require_role("admin"))):
    """
    Test the AI provider/model. Uses the posted values (falling back to saved settings
    for anything blank/masked) to do a tiny live completion.
    """
    import time
    from openai import OpenAI
    from framework.model_provider import resolve_ai_config, PROVIDER_PRESETS, LLM_TIMEOUT

    saved = resolve_ai_config()
    provider = (req.provider or saved["provider"]).lower()
    preset = PROVIDER_PRESETS.get(provider, {})
    # If the caller chose a provider, prefer its preset base URL unless they gave one.
    base_url = req.base_url.strip() or (preset.get("base_url") if req.provider else saved["base_url"]) or saved["base_url"]
    api_key = req.api_key if (req.api_key and req.api_key != MASKED_SECRET) else saved["api_key"]
    if not api_key:
        api_key = "ollama" if provider == "ollama" else "not-needed"
    model = req.model.strip() or (preset.get("default_model") if req.provider else saved["model"]) or saved["model"]

    try:
        client = OpenAI(api_key=api_key, base_url=base_url, timeout=LLM_TIMEOUT, max_retries=1)
        started = time.time()
        resp = client.chat.completions.create(
            model=model,
            messages=[{"role": "user", "content": "Reply with the single word: OK"}],
            max_tokens=5,
        )
        latency = round((time.time() - started) * 1000)
        reply = (resp.choices[0].message.content or "").strip()
        return {
            "status": "success", "provider": provider, "model": model,
            "base_url": base_url, "latency_ms": latency, "reply": reply[:80],
        }
    except Exception as e:
        logger.error(f"AI Test failed: {e}")
        raise HTTPException(status_code=400, detail=f"AI connection failed: {str(e)[:300]}")
