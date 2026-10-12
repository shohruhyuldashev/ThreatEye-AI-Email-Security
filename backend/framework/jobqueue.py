"""
Lightweight Redis-backed ingestion queue.

The hybrid detector runs the LLM inline (~1-3 min/email on CPU), so a gateway that
POSTs to /api/v1/emails should not block on it. When INGEST_ASYNC is on and Redis
is reachable, the endpoint enqueues the email and returns 202 immediately; a
consumer thread in the single-watcher process runs detection + persistence and
stores the verdict under the job id (pollable for a short window). If Redis is
unavailable the caller falls back to synchronous processing, so nothing is lost.

No extra broker/worker container is needed — it reuses the existing Redis and the
single-watcher process (same lock, so jobs are processed exactly once).
"""
from __future__ import annotations

import json
import logging
import os
import time
import uuid

logger = logging.getLogger(__name__)

QUEUE_KEY = "threateye:ingest:queue"
RESULT_PREFIX = "threateye:ingest:result:"
RESULT_TTL = int(os.getenv("INGEST_RESULT_TTL_SECONDS", "3600"))


def async_enabled() -> bool:
    return os.getenv("INGEST_ASYNC", "0").lower() in ("1", "true", "yes", "on")


def _redis():
    try:
        from framework.cache import get_redis
        return get_redis()
    except Exception:
        return None


def enqueue_email(payload: dict) -> str | None:
    """Push an ingestion job. Returns a job id, or None if the queue is unavailable."""
    r = _redis()
    if r is None:
        return None
    job_id = uuid.uuid4().hex
    job = {"job_id": job_id, "payload": payload, "enqueued_at": time.time()}
    try:
        r.rpush(QUEUE_KEY, json.dumps(job))
        r.setex(RESULT_PREFIX + job_id, RESULT_TTL, json.dumps({"status": "queued"}))
        return job_id
    except Exception as e:
        logger.warning("enqueue failed: %s", e)
        return None


def get_result(job_id: str) -> dict | None:
    r = _redis()
    if r is None:
        return None
    try:
        raw = r.get(RESULT_PREFIX + job_id)
        return json.loads(raw) if raw else None
    except Exception:
        return None


def process_email_payload(payload: dict) -> dict:
    """Run the full detection + persistence for one ingestion payload. Shared by the
    synchronous endpoint and the async consumer."""
    from services.ai_detector import analyze_email_hybrid
    from services.ingest import persist_detection
    from db import get_db_connection

    org = int(payload.get("organization_id", 1) or 1)
    sender = payload.get("sender", "")
    subject = payload.get("subject", "")
    body = payload.get("body", "")
    content = f"Subject: {subject}\nBody: {body}"
    metadata = {"spf": payload.get("spf", "unknown"), "dkim": payload.get("dkim", "unknown"),
                "dmarc": payload.get("dmarc", "unknown"), "sender": sender,
                "subject": subject, "reply_to": payload.get("reply_to", "")}
    analysis = analyze_email_hybrid(content, metadata)

    conn = get_db_connection()
    c = conn.cursor()
    try:
        result = persist_detection(
            c, organization_id=org, sender=sender, subject=subject,
            recipient=payload.get("recipient", "unknown"), content=content,
            analysis=analysis, attachments=[], source=payload.get("source", "api"),
        )
        conn.commit()
    finally:
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


def _blocking_redis():
    """A dedicated Redis client whose socket timeout exceeds the BLPOP block time,
    so blocking pops don't raise (and lose items) the way the shared 2s-timeout
    client would."""
    try:
        import redis
        url = os.getenv("REDIS_URL", "redis://redis:6379/0")
        return redis.Redis.from_url(url, socket_connect_timeout=5, socket_timeout=20,
                                    decode_responses=True)
    except Exception:
        return None


def consume_ingest_queue():
    """Blocking consumer loop — runs in the single-watcher process."""
    r = _blocking_redis()
    if r is None:
        logger.info("Ingest queue consumer: Redis unavailable; async ingestion disabled.")
        return
    logger.info("Ingest queue consumer started.")
    while True:
        try:
            item = r.blpop(QUEUE_KEY, timeout=5)
            if not item:
                continue
            job = json.loads(item[1])
            job_id = job.get("job_id")
            try:
                r.setex(RESULT_PREFIX + job_id, RESULT_TTL, json.dumps({"status": "processing"}))
            except Exception:
                pass
            try:
                result = process_email_payload(job.get("payload", {}))
            except Exception as e:
                logger.error("ingest job %s failed: %s", job_id, e)
                result = {"status": "failed", "error": "processing error"}
            try:
                r.setex(RESULT_PREFIX + job_id, RESULT_TTL, json.dumps(result))
            except Exception:
                pass
        except Exception as e:
            logger.error("ingest consumer error: %s", e)
            time.sleep(2)
