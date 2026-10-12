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
        "sender": from_addr,
        "reply_to": reply_to,
    }


def _watch_mailbox(IMAP_SERVER, IMAP_USER, IMAP_PASS, organization_id=1):
    """
    Watch ONE mailbox over IMAP IDLE and route new mail through the AI detector,
    quarantining phishing. Reconnects on error. Runs in its own daemon thread so
    many employee mailboxes can be protected in parallel.
    """
    import os
    import time
    from imap_tools import MailBoxUnencrypted, MailBox, A
    from services.ai_detector import analyze_email_hybrid

    QUARANTINE_FOLDER = "Quarantine_AI"
    # Production is TLS-only. Plaintext IMAP (which sends the password in the clear)
    # is used ONLY when explicitly opted in for a local lab mail server.
    allow_insecure = os.getenv("IMAP_ALLOW_INSECURE", "0").lower() in ("1", "true", "yes", "on")
    while True:
        try:
            # Always try an encrypted (IMAPS/TLS) connection first.
            try:
                mailbox_conn = MailBox(IMAP_SERVER).login(IMAP_USER, IMAP_PASS)
            except Exception as tls_err:
                if not allow_insecure:
                    # Never silently downgrade to cleartext in production.
                    raise RuntimeError(
                        f"TLS IMAP connection to {IMAP_SERVER} failed and insecure fallback "
                        f"is disabled (set IMAP_ALLOW_INSECURE=1 only for a local lab): {tls_err}"
                    )
                logger.warning("TLS IMAP failed for %s; falling back to UNENCRYPTED (lab only): %s",
                               IMAP_USER, tls_err)
                mailbox_conn = MailBoxUnencrypted(IMAP_SERVER).login(IMAP_USER, IMAP_PASS)

            with mailbox_conn as mailbox:
                folders_supported = True
                try:
                    if not mailbox.folder.exists(QUARANTINE_FOLDER):
                        mailbox.folder.create(QUARANTINE_FOLDER)
                except Exception as e:
                    logger.debug(f"IMAP Folders not supported by this server: {e}")
                    folders_supported = False

                logger.info(f"IMAP IDLE connected: {IMAP_USER}@{IMAP_SERVER}. Watching for new mail...")
                
                while True:
                    # Process current messages
                    conn = get_db_connection()
                    try:
                        c = conn.cursor()
                        for msg in mailbox.fetch(A(seen=False)):
                            # Skip ONLY our own phishing-simulation mail, and ONLY when it
                            # carries a VALID signed token under the secret, per-deployment
                            # header name. The cryptographic proof is REQUIRED: without a
                            # valid header the email is always analysed — so an attacker who
                            # merely guesses an active campaign's subject cannot bypass the
                            # detector. (The server-side registry additionally confirms the
                            # send, but is never sufficient on its own to skip.)
                            from framework.security import verify_sim_token, sim_header_name
                            _hdrs = getattr(msg, "headers", {}) or {}
                            _sig = _header_first(_hdrs, sim_header_name().lower())
                            if _sig and verify_sim_token(_sig):
                                try:
                                    from framework.sim_registry import is_simulation
                                    _registered = is_simulation(
                                        msg.to[0] if msg.to else "unknown", msg.subject,
                                        msg.text or msg.html or "")
                                except Exception:
                                    _registered = True  # registry optional; header already proved it
                                if _registered:
                                    logger.info(f"Verified simulation (signed header + registry) — skipping detection: {msg.subject}")
                                    continue
                                logger.warning(f"Valid sim header but no registry match — analysing anyway: {msg.subject}")
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
                                organization_id=organization_id,
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
            logger.error(f"IMAP watcher ({IMAP_USER}) error: {e}; reconnecting in 10s...")
            time.sleep(10)


def _load_mailboxes():
    """
    Mailboxes to protect. An `imap_accounts` setting (JSON list of
    {"user","pass"[,"server"]}) watches many employee mailboxes at once; otherwise
    it falls back to the single imap_user/imap_pass.
    """
    import json
    from framework.secretbox import decrypt_setting
    conn = get_db_connection()
    try:
        c = conn.cursor()
        c.execute("SELECT key, value FROM settings WHERE key IN "
                  "('imap_server','imap_user','imap_pass','imap_accounts')")
        s = {row['key']: decrypt_setting(row['key'], row['value']) for row in c.fetchall()}
    finally:
        conn.close()
    server = s.get("imap_server", "")
    accounts = []
    raw = s.get("imap_accounts", "")
    if raw:
        try:
            for a in json.loads(raw):
                if a.get("user") and a.get("pass"):
                    accounts.append((a.get("server") or server, a["user"], a["pass"], int(a.get("org", 1) or 1)))
        except Exception as e:
            logger.error("Invalid imap_accounts JSON: %s", e)
    if not accounts and s.get("imap_user") and s.get("imap_pass"):
        accounts.append((server, s["imap_user"], s["imap_pass"], 1))
    return accounts


def _acquire_single_watcher_slot():
    """
    Ensure ONLY ONE process runs the watcher, even with multiple Uvicorn workers or
    replicas, so mail is never fetched/analysed/quarantined twice. Uses a Redis lock
    when available (covers multiple hosts); otherwise an OS file lock (covers multiple
    workers on one host). Returns a keep-alive handle, or None if another process
    already holds the slot.
    """
    import os
    import socket
    owner = f"{socket.gethostname()}:{os.getpid()}"
    # 1) Redis lock (multi-host safe), refreshed by a daemon thread.
    try:
        from framework.cache import get_redis
        r = get_redis()
        if r is not None and r.set("threateye:watcher:lock", owner, nx=True, ex=45):
            import threading
            def _refresh():
                import time as _t
                while True:
                    _t.sleep(15)
                    try:
                        r.expire("threateye:watcher:lock", 45)
                    except Exception:
                        return
            threading.Thread(target=_refresh, daemon=True, name="WatcherLockRefresh").start()
            logger.info("Acquired watcher slot via Redis lock (%s).", owner)
            return "redis"
        if r is not None:
            return None  # another process holds the Redis lock
    except Exception as e:
        logger.debug("Redis watcher lock unavailable (%s); trying file lock.", e)
    # 2) File lock (single-host, multi-worker safe).
    try:
        import fcntl
        f = open("/tmp/threateye_watcher.lock", "w")
        fcntl.flock(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        f.write(owner); f.flush()
        logger.info("Acquired watcher slot via file lock (%s).", owner)
        return f  # keep the handle alive to hold the lock
    except Exception:
        return None


def start_email_watcher():
    """
    Dispatcher: spawn one IMAP IDLE watcher thread per configured mailbox so every
    employee's inbox is protected, not just one. Runs in only ONE process (lock),
    so multiple workers/replicas don't double-process mail.
    """
    import os
    import time
    import threading

    if os.getenv("RUN_EMAIL_WATCHER", "1").lower() in ("0", "false", "no", "off"):
        logger.info("RUN_EMAIL_WATCHER disabled; this process will not watch mail.")
        return
    # Keep trying to acquire the single-watcher slot: a worker that loses the race
    # waits and takes over automatically if the current holder dies (its lock expires).
    _slot = None
    _logged_wait = False
    while _slot is None:
        _slot = _acquire_single_watcher_slot()
        if _slot is None:
            if not _logged_wait:
                logger.info("Another process holds the watcher slot; standing by to take over.")
                _logged_wait = True
            time.sleep(20)

    # This process owns the single-watcher slot: also run the cloud mail connectors
    # (Microsoft 365 / Google Workspace) here, so cloud mailboxes are protected too
    # and never double-processed.
    try:
        from services.mail_connectors import run_mail_connectors
        threading.Thread(target=run_mail_connectors, daemon=True, name="CloudMailConnectors").start()
    except Exception as e:
        logger.warning("Could not start cloud mail connectors: %s", e)

    started = set()
    while True:
        try:
            accounts = _load_mailboxes()
        except Exception as e:
            logger.error("Watcher config read failed: %s", e)
            accounts = []
        if not accounts:
            logger.warning("No IMAP mailboxes configured yet; retrying in 60s...")
            time.sleep(60)
            continue
        for acct in accounts:
            srv, user, pw = acct[0], acct[1], acct[2]
            org = acct[3] if len(acct) > 3 else 1
            if user in started:
                continue
            threading.Thread(target=_watch_mailbox, args=(srv, user, pw, org),
                             daemon=True, name=f"IMAP_{user}").start()
            started.add(user)
            logger.info("Started IMAP watcher for mailbox: %s (org %s)", user, org)
        # Re-check periodically so newly-added mailboxes start without a full restart.
        time.sleep(120)
