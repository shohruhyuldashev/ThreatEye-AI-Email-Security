"""
Optional Redis cache/coordination layer.

Used for state that must be shared across backend replicas (e.g. the login
rate-limiter). If REDIS_URL is unset or Redis is unreachable, every call degrades
to a safe no-op / local behaviour, so a single-process dev run needs nothing.
"""
from __future__ import annotations

import logging
import os

logger = logging.getLogger(__name__)

_client = None
_initialised = False


def get_redis():
    global _client, _initialised
    if _initialised:
        return _client
    _initialised = True
    url = os.getenv("REDIS_URL", "").strip()
    if not url:
        return None
    try:
        import redis  # type: ignore

        client = redis.Redis.from_url(url, socket_connect_timeout=2, socket_timeout=2, decode_responses=True)
        client.ping()
        _client = client
        logger.info("Connected to Redis for shared state.")
    except Exception as e:
        logger.warning(f"Redis unavailable ({e}); using in-process state.")
        _client = None
    return _client


def rate_limit_hit(key: str, window_seconds: int) -> int:
    """
    Increment a windowed counter for `key` and return the current count.
    Returns 0 when Redis is unavailable (caller then falls back to local logic).
    """
    client = get_redis()
    if client is None:
        return 0
    try:
        redis_key = f"rl:{key}"
        pipe = client.pipeline()
        pipe.incr(redis_key)
        pipe.expire(redis_key, window_seconds)
        count, _ = pipe.execute()
        return int(count)
    except Exception:
        return 0


def rate_limit_get(key: str) -> int:
    """Read the current windowed counter without incrementing (0 if none/unavailable)."""
    client = get_redis()
    if client is None:
        return 0
    try:
        val = client.get(f"rl:{key}")
        return int(val) if val is not None else 0
    except Exception:
        return 0


def rate_limit_reset(key: str) -> None:
    client = get_redis()
    if client is None:
        return
    try:
        client.delete(f"rl:{key}")
    except Exception:
        pass
