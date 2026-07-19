"""Encryption-at-rest round-trip + masking-boundary guards."""
import os, sys
os.environ.setdefault("THREATEYE_AUTH_SECRET", "test-secret-for-unit-tests")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from framework import secretbox as sb


def test_sensitive_keys_roundtrip():
    for key in ("siem_api_key", "ai_api_key", "gophish_key", "m365_client_secret", "imap_pass", "google_sa_json"):
        enc = sb.encrypt_setting(key, "PLAINTEXT-VALUE")
        assert enc.startswith("enc:v1:"), f"{key} was not encrypted"
        assert "PLAINTEXT-VALUE" not in enc
        assert sb.decrypt_setting(key, enc) == "PLAINTEXT-VALUE"


def test_non_sensitive_keys_untouched():
    for key in ("siem_webhook_url", "ai_model", "siem_format", "imap_server"):
        v = sb.encrypt_setting(key, "http://x")
        assert v == "http://x", f"{key} should not be encrypted"


def test_legacy_plaintext_decrypts_unchanged():
    # A value stored before encryption existed must still read back as-is.
    assert sb.decrypt_setting("siem_api_key", "old-plaintext-key") == "old-plaintext-key"


def test_empty_values_passthrough():
    assert sb.encrypt_setting("siem_api_key", "") == ""
