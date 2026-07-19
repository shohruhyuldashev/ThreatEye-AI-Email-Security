"""
Encryption-at-rest for sensitive settings (SIEM/AI/GoPhish keys, M365/Google creds).

Sensitive settings values are stored encrypted in the `settings` table and decrypted only
by the internal consumers that need the plaintext (the SIEM dispatcher, the model provider,
the GoPhish client, the mail-remediation clawback). The API never returns them anyway — it
masks them — so the plaintext only ever exists in memory at the point of use.

Backward-compatible: `decrypt_*` returns legacy plaintext values unchanged, so existing
databases keep working and values become encrypted the next time they are saved. The key is
derived from `THREATEYE_AUTH_SECRET` (the same persisted signing secret the app already
manages), so no new secret to distribute.
"""
from __future__ import annotations

import base64
import hashlib

from cryptography.fernet import Fernet, InvalidToken

# Same markers the API uses to decide what to mask.
SENSITIVE_MARKERS = ("pass", "password", "key", "secret", "token", "sa_json", "credential")
_TAG = "enc:v1:"  # marks a value this module encrypted


def is_sensitive(key: str) -> bool:
    k = (key or "").lower()
    return any(m in k for m in SENSITIVE_MARKERS)


def _fernet() -> Fernet:
    # Derive a stable Fernet key from the app's signing secret.
    from framework.security import AUTH_SECRET
    digest = hashlib.sha256(("threateye-settings::" + str(AUTH_SECRET)).encode()).digest()
    return Fernet(base64.urlsafe_b64encode(digest))


def encrypt_value(value) -> str:
    if value is None or value == "":
        return value
    try:
        return _TAG + _fernet().encrypt(str(value).encode()).decode()
    except Exception:
        return value  # never lose the setting because encryption failed


def decrypt_value(value):
    if not isinstance(value, str) or not value.startswith(_TAG):
        return value  # legacy plaintext, empty, or non-string
    try:
        return _fernet().decrypt(value[len(_TAG):].encode()).decode()
    except (InvalidToken, Exception):
        return value


def encrypt_setting(key: str, value):
    """Encrypt a value if its key is sensitive; otherwise pass through."""
    return encrypt_value(value) if (is_sensitive(key) and value) else value


def decrypt_setting(key: str, value):
    """Decrypt a stored value if its key is sensitive; otherwise pass through."""
    return decrypt_value(value) if is_sensitive(key) else value
