import os
import re
import logging
from db import get_db_connection
from services.ingest import persist_detection

logger = logging.getLogger(__name__)


def _header_first(headers: dict, name: str, default: str = "") -> str:
    value = headers.get(name)
    if not value:
        return default
    if isinstance(value, (list, tuple)):
        return str(value[0]) if value else default
    return str(value)


def _extract_auth_metadata(msg) -> dict:
    """
    Derive SPF / DKIM / DMARC verdicts and a reply-to mismatch flag from the
    message headers so the detector scores on real authentication signals
    instead of an optimistic 'pass' default.
    """
    headers = getattr(msg, "headers", {}) or {}
    auth_results = " ".join([
        _header_first(headers, "authentication-results"),
        _header_first(headers, "received-spf"),
        _header_first(headers, "arc-authentication-results"),
    ]).lower()

    def verdict(mechanism: str) -> str:
        m = re.search(rf"{mechanism}=(\w+)", auth_results)
        if m:
            return "pass" if m.group(1) == "pass" else "fail"
        # No signal present: treat SPF/DKIM as unknown->pass (avoid false alarms on
        # local lab mail), but never fabricate a DMARC pass.
        return "pass" if mechanism in {"spf", "dkim"} else "unknown"

    from_addr = (getattr(msg, "from_", "") or "").lower()
    reply_to_values = getattr(msg, "reply_to", ()) or ()
    reply_to = (reply_to_values[0] if reply_to_values else "").lower()

    def _domain(addr: str) -> str:
        return addr.split("@")[-1].strip(" <>") if "@" in addr else ""

    reply_to_mismatch = bool(reply_to) and _domain(reply_to) != _domain(from_addr)

    return {
        "spf": verdict("spf"),
        "dkim": verdict("dkim"),
        "dmarc": verdict("dmarc"),
        "reply_to_mismatch": reply_to_mismatch,
    }


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
            from framework.secretbox import decrypt_setting
            settings = {row['key']: decrypt_setting(row['key'], row['value']) for row in c.fetchall()}
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
                            
                            metadata = _extract_auth_metadata(msg)
                            recipient = msg.to[0] if msg.to else "unknown"
                            
                            c.execute('SELECT role, behavioral_risk_score, failed_simulations_count, typical_topics FROM user_profiles WHERE email = ?', (recipient,))
                            u_profile = c.fetchone()
                            user_context = dict(u_profile) if u_profile else {"role": "Unknown", "behavioral_risk_score": 0, "failed_simulations_count": 0, "typical_topics": "Anything"}
                            
                            attachments = []
                            for attachment in getattr(msg, "attachments", []) or []:
                                payload = getattr(attachment, "payload", b"") or b""
                                attachments.append({
                                    "filename": getattr(attachment, "filename", ""),
                                    "content_type": getattr(attachment, "content_type", ""),
                                    "size_bytes": len(payload),
                                    "payload": payload,  # bytes, consumed by the attachment scanner
                                })

                            analysis = analyze_email_hybrid(content_to_analyze, metadata, user_context)
                            result = persist_detection(
                                c,
                                organization_id=1,
                                sender=msg.from_,
                                subject=msg.subject,
                                recipient=recipient,
                                content=content_to_analyze,
                                analysis=analysis,
                                attachments=attachments,
                                source="imap_watcher",
                            )

                            if result["is_threat"]:
                                logger.warning(f"PHISHING DETECTED! Moving email '{msg.subject}' to {QUARANTINE_FOLDER}...")
                                if folders_supported:
                                    try:
                                        mailbox.move(msg.uid, QUARANTINE_FOLDER)
                                    except Exception as e:
                                        logger.error(f"Failed to move email to quarantine folder: {e}")
                                        mailbox.flag(msg.uid, '\\Seen', True)
                                else:
                                    mailbox.flag(msg.uid, '\\Seen', True)
                            else:
                                logger.info(f"Email '{msg.subject}' is clean. Phishing Score: {result['phishing_score']}")
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
