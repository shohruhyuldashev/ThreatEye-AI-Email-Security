from fastapi import APIRouter, HTTPException, File, Form, UploadFile
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from typing import Optional
import logging
import asyncio
import json
from db import get_db_connection
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)
router = APIRouter()

class URLAnalyzeRequest(BaseModel):
    url: str
    mode: str = "AI"

class IMAPTestRequest(BaseModel):
    server: str
    user: str
    password: str

class LoginRequest(BaseModel):
    username: str
    password: str

class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str

class SimulationTriggerRequest(BaseModel):
    mode: str = "AI" # 'Manual' or 'AI'
    target_emails: str = "" # Comma separated list for Manual mode
    target_date: str = "" # Scheduled datetime for Manual mode
    delay_mode: bool = True


@router.get("/stats")
def get_stats(days: int = 7):
    """Returns overall statistics for the dashboard."""
    conn = get_db_connection()
    c = conn.cursor()
    
    c.execute('SELECT COUNT(*) FROM emails')
    total_emails = c.fetchone()[0]
    
    c.execute("SELECT COUNT(*) FROM emails WHERE risk_score > 30 and risk_score <= 70")
    suspicious_emails = c.fetchone()[0]
    
    c.execute("SELECT COUNT(*) FROM quarantine")
    quarantined_emails = c.fetchone()[0]
    
    c.execute("SELECT COUNT(*) FROM simulations WHERE status = 'Running'")
    active_sims = c.fetchone()[0]
    
    # Calculate a simplified average risk gauge over the selected period
    c.execute(f"SELECT AVG(risk_score) FROM emails WHERE timestamp >= datetime('now', '-{days} days')")
    avg_risk = c.fetchone()[0] or 0
    
    # Check for recent critical activity
    c.execute(f"SELECT COUNT(*) FROM emails WHERE risk_score > 70 AND timestamp >= datetime('now', '-{days} days')")
    critical_count = c.fetchone()[0] or 0
    has_critical_activity = critical_count > 0
    
    # Get trend based on selected days
    c.execute(f'''
        SELECT date(timestamp) as day, COUNT(*) as count 
        FROM emails 
        WHERE risk_score > 50 AND timestamp >= datetime('now', '-{days} days')
        GROUP BY date(timestamp)
        ORDER BY date(timestamp)
    ''')
    trend_data = dict(c.fetchall())
    
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
def get_recent_emails(limit: int = 50):
    """Returns recent monitored emails for the Real-Time Monitor."""
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('SELECT * FROM emails ORDER BY timestamp DESC LIMIT ?', (limit,))
    emails = [dict(row) for row in c.fetchall()]
    conn.close()
    return emails

async def event_stream():
    """Server-Sent Events stream generator for real-time updates."""
    last_id = 0
    
    # Get the current highest ID so we only send *new* items
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('SELECT MAX(id) FROM emails')
    result = c.fetchone()[0]
    last_id = result if result else 0
    conn.close()

    while True:
        # Check for new emails
        conn = get_db_connection()
        c = conn.cursor()
        c.execute('SELECT * FROM emails WHERE id > ? ORDER BY timestamp ASC', (last_id,))
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
async def stream_updates():
    """SSE endpoint for real-time dashboard updates."""
    return StreamingResponse(event_stream(), media_type="text/event-stream")

@router.get("/quarantine")
def get_quarantined_items():
    """Returns items currently in quarantine."""
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('''
        SELECT q.id as quarantine_id, q.recipient, q.ai_reason, q.quarantined_at, e.* 
        FROM quarantine q
        JOIN emails e ON q.email_id = e.id
        ORDER BY q.quarantined_at DESC
    ''')
    quarantine_items = [dict(row) for row in c.fetchall()]
    conn.close()
    return quarantine_items

@router.post("/analyze-url")
def analyze_url_endpoint(req: URLAnalyzeRequest):
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
def get_notifications():
    """Returns top 5 latest high-risk alerts or quarantines for the bell dropdown."""
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('''
        SELECT 'quarantine' as type, q.quarantined_at as time, e.subject, q.ai_reason as details 
        FROM quarantine q 
        JOIN emails e ON q.email_id = e.id 
        ORDER BY q.quarantined_at DESC LIMIT 5
    ''')
    notifications = [dict(row) for row in c.fetchall()]
    conn.close()
    return notifications

@router.get("/analytics")
def get_analytics():
    """Returns data for the analytics risk charts and tables."""
    conn = get_db_connection()
    c = conn.cursor()
    
    # 1. Threat Distribution
    c.execute("SELECT ai_reason FROM emails WHERE risk_score > 30")
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

    # 2. Department Vulnerability
    c.execute('''
        SELECT recipient, COUNT(*) as incidents, AVG(risk_score) as avg_risk 
        FROM emails 
        WHERE risk_score > 30 
        GROUP BY recipient
    ''')
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

@router.post("/emails/{email_id}/release")
def release_email(email_id: int):
    """Releases an email from quarantine."""
    conn = get_db_connection()
    c = conn.cursor()
    # Delete from quarantine
    c.execute('DELETE FROM quarantine WHERE email_id = ?', (email_id,))
    # Update email status to 'Allowed' (simulating releasing to inbox)
    c.execute("UPDATE emails SET status = 'Allowed' WHERE id = ?", (email_id,))
    conn.commit()
    conn.close()
    return {"status": "success", "message": f"Item {email_id} released"}

@router.delete("/emails/{email_id}")
def delete_email(email_id: int):
    """Permanently deletes an email and its quarantine record."""
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('DELETE FROM quarantine WHERE email_id = ?', (email_id,))
    c.execute('DELETE FROM emails WHERE id = ?', (email_id,))
    conn.commit()
    conn.close()
    return {"status": "success", "message": f"Item {email_id} deleted"}

@router.delete("/quarantine/empty/all")
def empty_quarantine():
    """Permanently deletes all quarantined emails."""
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('DELETE FROM quarantine')
    conn.commit()
    conn.close()
    return {"status": "success", "message": "All quarantine items deleted"}

@router.post("/simulations/config")
def save_simulation_config(config: dict):
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
def get_simulation_config():
    """Retrieves saved simulation settings."""
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT key, value FROM settings WHERE key LIKE 'sim_%'")
    settings_rows = c.fetchall()
    conn.close()
    
    settings_dict = {row['key'].replace('sim_', ''): row['value'] for row in settings_rows}
    return settings_dict

@router.post("/simulations/trigger")
def trigger_simulation(
    mode: str = Form("AI"),
    target_date: Optional[str] = Form(""),
    delay_mode: Optional[bool] = Form(True),
    file: Optional[UploadFile] = File(None)
):
    """Manually triggers a new phishing simulation, supporting Manual targeting via file upload and AI automatic targeting."""
    try:
        from services.scheduler import trigger_random_campaign
        from services.gophish_client import create_campaign_with_generated_email, api
        import os
        import re
        
        if not api:
            raise Exception("GoPhish API is not configured or reachable.")

        if mode == "Manual":
            emails_list = []
            if file:
                os.makedirs("/app/uploads", exist_ok=True)
                file_path = f"/app/uploads/{file.filename}"
                with open(file_path, "wb") as f:
                    f.write(file.file.read())
                    
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                    
                emails_list = [e.strip() for e in re.split(r'[,\n\r]+', content) if '@' in e.strip()]
            
            if not emails_list:
                raise Exception("Manual mode requires a valid .txt or .csv file with target emails to be uploaded.")
            
            # Simulated: If an exact date is provided, we would ideally schedule it via APScheduler.
            # For this MVP, we immediately send to the explicitly requested targets using our basic payload generator
            from services.ai_generator import generate_phishing_email
            
            email_data = generate_phishing_email(
                target_name="Manual User", 
                department="General", 
                company="Current Organization"
            )
            
            results = []
            for email in emails_list:
                dummy_target = {"name": email.split('@')[0], "email": email, "department": "General", "company": "Current Organization"}
                res = create_campaign_with_generated_email(target_info=dummy_target, generated_email=email_data)
                results.append(res)
                
            return {"status": "success", "message": f"Manual simulation triggered for {len(emails_list)} targets", "details": results}

        else:
            # AI (Randomized) mode uses the existing random targeting logic
            trigger_random_campaign()
            return {"status": "success", "message": "AI Automated simulation triggered successfully via Gophish"}
            
    except Exception as e:
        logger.error(f"Error triggering simulation: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/auth/login")
def login(req: LoginRequest):
    if req.username != "admin":
        raise HTTPException(status_code=401, detail="Invalid username")
        
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT value FROM settings WHERE key='admin_password'")
    row = c.fetchone()
    conn.close()
    
    saved_password = row['value'] if row and row['value'] else "admin" # Default password
    
    if req.password == saved_password:
        return {"message": "Login successful"}
    else:
        raise HTTPException(status_code=401, detail="Invalid password")

@router.post("/auth/change-password")
def change_password(req: ChangePasswordRequest):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT value FROM settings WHERE key='admin_password'")
    row = c.fetchone()
    
    saved_password = row['value'] if row and row['value'] else "admin" # Default password
    
    if req.current_password != saved_password:
        conn.close()
        raise HTTPException(status_code=401, detail="Incorrect current password")
        
    c.execute('''
        INSERT INTO settings (key, value) 
        VALUES ('admin_password', ?) 
        ON CONFLICT(key) DO UPDATE SET value=excluded.value
    ''', (req.new_password,))
    conn.commit()
    conn.close()
    return {"message": "Password updated successfully"}

@router.get("/settings")
def get_settings():
    """Returns the current settings from the database."""
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('SELECT key, value FROM settings')
    settings_rows = c.fetchall()
    conn.close()
    
    settings_dict = {row['key']: row['value'] for row in settings_rows}
    return settings_dict

@router.post("/settings")
def update_settings(settings: dict):
    """Updates settings in the database dynamically."""
    conn = get_db_connection()
    c = conn.cursor()
    
    for key, value in settings.items():
        c.execute('''
            INSERT INTO settings (key, value) 
            VALUES (?, ?) 
            ON CONFLICT(key) DO UPDATE SET value=excluded.value
        ''', (key, str(value)))
        
    conn.commit()
    conn.close()
    
    return {"status": "success", "message": "Settings saved successfully."}

@router.post("/settings/test-imap")
def test_imap_connection(req: IMAPTestRequest):
    """Tests the provided IMAP credentials against the target server."""
    try:
        from imap_tools import MailBoxUnencrypted, MailBox
        # Try unencrypted first for local labs, fallback to SSL
        try:
            with MailBoxUnencrypted(req.server).login(req.user, req.password) as mailbox:
                mailbox.folder.status('INBOX')
        except:
            with MailBox(req.server).login(req.user, req.password) as mailbox:
                mailbox.folder.status('INBOX')
        return {"status": "success", "message": f"Successfully connected to {req.server} as {req.user}."}
    except Exception as e:
        error_msg = str(e)
        logger.error(f"IMAP Test failed: {error_msg}")
        raise HTTPException(status_code=400, detail=f"Connection failed: {error_msg}")
