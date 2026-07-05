import pytest
from framework import security as s


def test_password_hash_roundtrip():
    h = s.hash_password("Sup3rSecret!")
    assert h.startswith("pbkdf2_sha256$")
    assert s.verify_password("Sup3rSecret!", h)
    assert not s.verify_password("wrong", h)


def test_password_legacy_plaintext():
    assert s.verify_password("admin", "admin")
    assert not s.verify_password("nope", "admin")


def test_token_sign_verify():
    tok = s.create_token({"id": 7, "username": "admin", "organization_id": 1, "role": "owner"})
    payload = s.verify_token(tok)
    assert payload["sub"] == "admin"
    assert payload["uid"] == 7
    assert payload["org"] == 1
    assert payload["role"] == "owner"


def test_token_tamper_detected():
    tok = s.create_token({"id": 1, "username": "a", "organization_id": 1, "role": "viewer"})
    tampered = tok[:-2] + ("aa" if not tok.endswith("aa") else "bb")
    with pytest.raises(ValueError):
        s.verify_token(tampered)


def test_rbac_ordering():
    assert s.role_at_least("owner", "admin")
    assert s.role_at_least("admin", "analyst")
    assert not s.role_at_least("viewer", "analyst")
    assert not s.role_at_least("analyst", "admin")


def test_api_key_format():
    k = s.generate_api_key()
    assert k.startswith("tek_")
    assert len(s.hash_api_key(k)) == 64
    assert s.hash_api_key(k) == s.hash_api_key(k)
