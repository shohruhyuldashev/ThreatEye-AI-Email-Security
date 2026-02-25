import os
import logging
import json
from db import get_db_connection

logger = logging.getLogger(__name__)

def start_email_watcher():
    """
    Checks the configured email inbox for new messages and routes them through the AI detector.
    If phishing is detected, it moves the email to quarantine.
    """
    # NOTE: Since the user hasn't specified an explicit provider yet,
    # we implement a generic IMAP polling structure here using imap-tools.
    
    import time
    from imap_tools import MailBoxUnencrypted, MailBox, A
    from services.ai_detector import analyze_email_text, analyze_email_hybrid
    
    while True:
        try:
            conn = get_db_connection()
            c = conn.cursor()
            
            # Load dynamic settings instead of ENV
            c.execute("SELECT key, value FROM settings WHERE key IN ('imap_server', 'imap_user', 'imap_pass')")
            settings = {row['key']: row['value'] for row in c.fetchall()}
            conn.close()
            
            IMAP_SERVER = settings.get("imap_server", "")
            IMAP_USER = settings.get("imap_user", "")
            IMAP_PASS = settings.get("imap_pass", "")
            QUARANTINE_FOLDER = "Quarantine_AI"

            if not all([IMAP_SERVER, IMAP_USER, IMAP_PASS]):
                logger.warning("IMAP credentials not fully configured in settings. Skipping email watcher IDLE loop. Retrying in 60s...")
                time.sleep(60)
                continue

            try:
                mailbox_conn = MailBoxUnencrypted(IMAP_SERVER).login(IMAP_USER, IMAP_PASS)
            except:
                mailbox_conn = MailBox(IMAP_SERVER).login(IMAP_USER, IMAP_PASS)

            with mailbox_conn as mailbox:
                folders_supported = True
                try:
                    if not mailbox.folder.exists(QUARANTINE_FOLDER):
                        mailbox.folder.create(QUARANTINE_FOLDER)
                except Exception as e:
                    logger.debug(f"IMAP Folders not supported by this server: {e}")
                    folders_supported = False

                logger.info(f"IMAP IDLE connected to {IMAP_SERVER}. Waiting for new emails...")
                
                while True:
                    # Process current messages
                    conn = get_db_connection()
                    try:
                        c = conn.cursor()
                        for msg in mailbox.fetch(A(seen=False)):
                            logger.info(f"Analyzing new email: {msg.subject} from {msg.from_}")
                            content_to_analyze = f"Subject: {msg.subject}\nBody: {msg.text or msg.html}"
                            
                            spf_header = msg.headers.get("received-spf", ["pass"])[0].lower()
                            metadata = {
                                "spf": "pass" if "pass" in spf_header else "fail",
                                "dkim": "pass"
                            }
                            recipient = msg.to[0] if msg.to else "unknown"
                            
                            c.execute('SELECT role, behavioral_risk_score, failed_simulations_count, typical_topics FROM user_profiles WHERE email = ?', (recipient,))
                            u_profile = c.fetchone()
                            user_context = dict(u_profile) if u_profile else {"role": "Unknown", "behavioral_risk_score": 0, "failed_simulations_count": 0, "typical_topics": "Anything"}
                            
                            analysis = analyze_email_hybrid(content_to_analyze, metadata, user_context)
                            phishing_score = analysis.get("final_risk_score", 0)
                            url_threat_score = analysis.get("heuristic_score", 0)
                            ai_reason = analysis.get("explanation", "No reason provided")
                            urls_list_str = json.dumps(analysis.get("urls_found", []))
                            
                            is_threat = phishing_score > 70 or url_threat_score > 70
                            status = "Quarantined" if is_threat else "Allowed"

                            c.execute('''
                                INSERT INTO emails (sender, subject, risk_score, url_threat_score, urls_found, status)
                                VALUES (?, ?, ?, ?, ?, ?)
                            ''', (msg.from_, msg.subject, phishing_score, url_threat_score, urls_list_str, status))
                            email_id = c.lastrowid
                            
                            if is_threat:
                                logger.warning(f"PHISHING DETECTED! Moving email '{msg.subject}' to {QUARANTINE_FOLDER}...")
                                c.execute('''
                                    INSERT INTO quarantine (email_id, recipient, ai_reason)
                                    VALUES (?, ?, ?)
                                ''', (email_id, recipient, ai_reason))

                                if folders_supported:
                                    try:
                                        mailbox.move(msg.uid, QUARANTINE_FOLDER)
                                    except Exception as e:
                                        logger.error(f"Failed to move email to quarantine folder: {e}")
                                        mailbox.flag(msg.uid, '\\Seen', True)
                                else:
                                    mailbox.flag(msg.uid, '\\Seen', True)
                            else:
                                logger.info(f"Email '{msg.subject}' is clean. Phishing Score: {phishing_score}")
                                mailbox.flag(msg.uid, '\\Seen', True)

                        conn.commit()
                    finally:
                        conn.close()

                    # IDLE wait until server pushes a notification
                    responses = mailbox.idle.wait(timeout=60)
                    if not responses:
                        # Timeout reached, loop back to fetch again to keep connection alive
                        pass

        except Exception as e:
            logger.error(f"IMAP watcher IDLE loop encountered an error: {e}")
            logger.info("Attempting to reconnect in 10 seconds...")
            time.sleep(10)
