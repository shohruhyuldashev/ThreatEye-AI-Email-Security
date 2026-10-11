"""Forced first-login password change: token claim + require_auth enforcement."""
import os
import sys
import types

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from framework import security as s
from fastapi import HTTPException


def test_mcp_claim_carried_in_access_token():
    tok = s.create_access_token(
        {"id": 1, "username": "admin", "organization_id": 1, "role": "owner", "must_change_password": True}
    )
    assert s.decode_token(tok, expected_type="access")["mcp"] is True


def test_mcp_defaults_false_when_absent():
    tok = s.create_access_token({"id": 2, "username": "u", "organization_id": 1, "role": "viewer"})
    assert s.decode_token(tok, expected_type="access")["mcp"] is False


class _FakeURL:
    def __init__(self, path):
        self.path = path


class _FakeRequest:
    def __init__(self, token, path):
        self.cookies = {"access_token": token}
        self.url = _FakeURL(path)
        self.headers = {}


def _require_auth(token, path):
    from api import deps
    return deps.require_auth(_FakeRequest(token, path), authorization=None, token=None)


def test_mcp_user_blocked_on_data_endpoint():
    tok = s.create_access_token(
        {"id": 1, "username": "admin", "organization_id": 1, "role": "owner", "must_change_password": True}
    )
    with pytest.raises(HTTPException) as exc:
        _require_auth(tok, "/api/emails")
    assert exc.value.status_code == 403


def test_mcp_user_allowed_on_change_password():
    tok = s.create_access_token(
        {"id": 1, "username": "admin", "organization_id": 1, "role": "owner", "must_change_password": True}
    )
    payload = _require_auth(tok, "/api/auth/change-password")
    assert payload["mcp"] is True


def test_normal_user_not_blocked():
    tok = s.create_access_token({"id": 3, "username": "u", "organization_id": 1, "role": "analyst"})
    payload = _require_auth(tok, "/api/emails")
    assert payload["sub"] == "u"
