"""
Shared authentication / authorization primitives for ThreatEye.

Centralises password hashing, session-token signing, the RBAC role model, and
API-key hashing so the router, the DB seeding, and the ingestion API all agree.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
from datetime import datetime, timedelta

from db import get_db_connection

logger = logging.getLogger(__name__)

TOKEN_TTL_SECONDS = int(os.getenv("THREATEYE_TOKEN_TTL_SECONDS", "43200"))

# --- RBAC -----------------------------------------------------------------------
# Higher number = more privilege. `owner` is the tenant super-user.
ROLE_ORDER = {"viewer": 1, "analyst": 2, "admin": 3, "owner": 4}
VALID_ROLES = set(ROLE_ORDER)
DEFAULT_ROLE = "viewer"


def role_at_least(role: str, minimum: str) -> bool:
    return ROLE_ORDER.get(role or "", 0) >= ROLE_ORDER.get(minimum, 99)


# --- base64url helpers ----------------------------------------------------------
def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def b64url_decode(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


# --- password hashing (PBKDF2-HMAC-SHA256) --------------------------------------
_PBKDF2_ITERATIONS = 200_000


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, _PBKDF2_ITERATIONS)
    return f"pbkdf2_sha256${_PBKDF2_ITERATIONS}${b64url(salt)}${b64url(digest)}"


def verify_password(password: str, saved_password: str) -> bool:
    if not saved_password:
        saved_password = "admin"
    if not saved_password.startswith("pbkdf2_sha256$"):
        # Legacy/plaintext value — constant-time compare.
        return hmac.compare_digest(password, saved_password)
    try:
        _, iterations, salt_b64, digest_b64 = saved_password.split("$", 3)
        digest = hashlib.pbkdf2_hmac("sha256", password.encode(), b64url_decode(salt_b64), int(iterations))
        return hmac.compare_digest(b64url(digest), digest_b64)
    except Exception:
        return False


# --- API keys -------------------------------------------------------------------
API_KEY_PREFIX = "tek_"  # ThreatEye Key


def generate_api_key() -> str:
    return API_KEY_PREFIX + secrets.token_urlsafe(32)


def hash_api_key(key: str) -> str:
    """Deterministic SHA-256 hash so we can look keys up by value without storing them."""
    return hashlib.sha256(key.encode()).hexdigest()


# --- token signing secret -------------------------------------------------------
def load_auth_secret() -> str:
    env_secret = os.getenv("THREATEYE_AUTH_SECRET", "").strip()
    if env_secret and env_secret != "change-me-in-production":
        return env_secret
    try:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT value FROM settings WHERE key = 'auth_secret'")
        row = c.fetchone()
        if row and row["value"]:
            conn.close()
            return row["value"]
        generated = secrets.token_urlsafe(48)
        c.execute(
            "INSERT INTO settings (key, value) VALUES ('auth_secret', ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (generated,),
        )
        conn.commit()
        conn.close()
        logger.warning(
            "THREATEYE_AUTH_SECRET not set; generated and persisted a random signing secret."
        )
        return generated
    except Exception:
        return secrets.token_urlsafe(48)


AUTH_SECRET = load_auth_secret()


# --- JWT access / refresh tokens ------------------------------------------------
import jwt  # PyJWT

JWT_ALG = "HS256"
ACCESS_TTL = int(os.getenv("ACCESS_TOKEN_TTL_SECONDS", "900"))        # 15 minutes
REFRESH_TTL = int(os.getenv("REFRESH_TOKEN_TTL_SECONDS", "604800"))   # 7 days

ACCESS_COOKIE = "access_token"
REFRESH_COOKIE = "refresh_token"
CSRF_COOKIE = "csrf_token"
REFRESH_PATH = "/api/auth"
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "false").lower() in {"1", "true", "yes", "on"}
COOKIE_SAMESITE = os.getenv("COOKIE_SAMESITE", "lax").lower()  # lax|strict|none


def _claims(identity: dict, token_type: str, ttl: int) -> dict:
    import time
    now = int(time.time())  # real UTC epoch (datetime.utcnow().timestamp() misreads local tz)
    return {
        "sub": identity.get("username"),
        "uid": identity.get("id"),
        "org": identity.get("organization_id", 1),
        "role": identity.get("role", DEFAULT_ROLE),
        "type": token_type,
        "iat": now,
        "exp": now + ttl,
        "jti": secrets.token_urlsafe(16),
    }


def create_access_token(identity: dict) -> str:
    return jwt.encode(_claims(identity, "access", ACCESS_TTL), AUTH_SECRET, algorithm=JWT_ALG)


def create_refresh_token(identity: dict) -> tuple[str, str]:
    """Returns (jwt, jti). The jti is tracked server-side for rotation/revocation."""
    claims = _claims(identity, "refresh", REFRESH_TTL)
    return jwt.encode(claims, AUTH_SECRET, algorithm=JWT_ALG), claims["jti"]


def decode_token(token: str, expected_type: str | None = None) -> dict:
    """Verify a JWT (signature + exp). Raises jwt.PyJWTError on failure."""
    payload = jwt.decode(token, AUTH_SECRET, algorithms=[JWT_ALG])
    if expected_type and payload.get("type") != expected_type:
        raise jwt.InvalidTokenError(f"expected {expected_type} token")
    return payload


# Backward-compatible alias (old code/tests referenced create_token/verify_token).
def create_token(identity: dict) -> str:
    return create_access_token(identity)


def verify_token(token: str) -> dict:
    try:
        return decode_token(token, expected_type="access")
    except jwt.PyJWTError as e:
        raise ValueError(str(e))


# --- refresh-token store (rotation + revocation) --------------------------------
# Tracks valid refresh jti's so a rotated/revoked token can't be reused. Backed by
# Redis when available; otherwise falls back to stateless validation (JWT sig+exp only).
def remember_refresh(jti: str, uid, ttl: int = REFRESH_TTL) -> None:
    from framework.cache import get_redis
    r = get_redis()
    if r is not None:
        try:
            r.setex(f"refresh:{jti}", ttl, str(uid))
        except Exception:
            pass


def refresh_is_valid(jti: str) -> bool:
    from framework.cache import get_redis
    r = get_redis()
    if r is None:
        return True  # stateless fallback (no server-side revocation)
    try:
        return r.exists(f"refresh:{jti}") == 1
    except Exception:
        return True


def revoke_refresh(jti: str) -> None:
    from framework.cache import get_redis
    r = get_redis()
    if r is not None:
        try:
            r.delete(f"refresh:{jti}")
        except Exception:
            pass


# --- auth cookies ---------------------------------------------------------------
def set_auth_cookies(response, identity: dict) -> str:
    """Issue access + refresh + CSRF cookies for a session. Returns the CSRF token."""
    access = create_access_token(identity)
    refresh, jti = create_refresh_token(identity)
    remember_refresh(jti, identity.get("id"), REFRESH_TTL)
    csrf = secrets.token_urlsafe(24)

    common = {"secure": COOKIE_SECURE, "samesite": COOKIE_SAMESITE}
    # Access token: httpOnly (JS can't read it), site-wide.
    response.set_cookie(ACCESS_COOKIE, access, httponly=True, max_age=ACCESS_TTL, path="/", **common)
    # Refresh token: httpOnly and scoped to /api/auth so it's only sent to refresh/logout.
    response.set_cookie(REFRESH_COOKIE, refresh, httponly=True, max_age=REFRESH_TTL, path=REFRESH_PATH, **common)
    # CSRF token: readable by JS so the SPA can echo it in the X-CSRF-Token header.
    # It must outlive the *access* token and track the *refresh* token instead: the
    # refresh call is itself a mutating request, so if this cookie expired with the
    # access token there would be no way to CSRF-validate a refresh and every
    # session would die after ACCESS_TTL — sending the user back to the login screen
    # 15 minutes in, despite a 7-day refresh token.
    response.set_cookie(CSRF_COOKIE, csrf, httponly=False, max_age=REFRESH_TTL, path="/", **common)
    return csrf


def clear_auth_cookies(response) -> None:
    response.delete_cookie(ACCESS_COOKIE, path="/")
    response.delete_cookie(REFRESH_COOKIE, path=REFRESH_PATH)
    response.delete_cookie(CSRF_COOKIE, path="/")
