"""FastAPI dependencies for session-token auth, RBAC, and API-key auth."""
from __future__ import annotations

from typing import Optional

from fastapi import Depends, Header, HTTPException, Query, Request

from db import get_db_connection
from framework.security import ACCESS_COOKIE, decode_token, hash_api_key, role_at_least


def require_auth(
    request: Request,
    authorization: Optional[str] = Header(None),
    token: Optional[str] = Query(None),
) -> dict:
    """
    Validate the session access token and return its identity payload.

    Resolution order: httpOnly `access_token` cookie (browser sessions) → Bearer
    header (API/CLI clients) → `?token=` query (Server-Sent Events, which can't set
    headers). All are verified as JWT access tokens.
    """
    raw_token = request.cookies.get(ACCESS_COOKIE)
    if not raw_token and authorization and authorization.lower().startswith("bearer "):
        raw_token = authorization.split(" ", 1)[1].strip()
    if not raw_token and token:
        raw_token = token
    if not raw_token:
        raise HTTPException(status_code=401, detail="Authentication required")
    try:
        return decode_token(raw_token, expected_type="access")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid or expired authentication token")


def require_role(minimum: str):
    """Dependency factory: require at least `minimum` role (viewer<analyst<admin<owner)."""

    def _checker(identity: dict = Depends(require_auth)) -> dict:
        if not role_at_least(identity.get("role", "viewer"), minimum):
            raise HTTPException(
                status_code=403,
                detail=f"This action requires the '{minimum}' role or higher.",
            )
        return identity

    return _checker


def require_api_key(x_api_key: Optional[str] = Header(None)) -> dict:
    """Authenticate a machine client via the X-API-Key header, scoped to its tenant."""
    if not x_api_key:
        raise HTTPException(status_code=401, detail="API key required (X-API-Key header)")
    key_hash = hash_api_key(x_api_key)
    conn = get_db_connection()
    c = conn.cursor()
    c.execute(
        "SELECT id, organization_id, name, active FROM api_keys WHERE key_hash = ?",
        (key_hash,),
    )
    row = c.fetchone()
    if row and row["active"]:
        c.execute("UPDATE api_keys SET last_used_at = CURRENT_TIMESTAMP WHERE id = ?", (row["id"],))
        conn.commit()
    conn.close()
    if not row or not row["active"]:
        raise HTTPException(status_code=401, detail="Invalid or inactive API key")
    return {
        "organization_id": row["organization_id"],
        "api_key_id": row["id"],
        "api_key_name": row["name"],
    }
