"""Cloud mail connectors — header parsing + graceful no-op when unconfigured."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from services import mail_connectors as mc


def test_auth_from_headers_parses_spf_dkim_dmarc():
    h = {"authentication-results": "mx.example.com; spf=pass smtp.mailfrom=x; dkim=fail; dmarc=fail"}
    a = mc._auth_from_headers(h)
    assert a["spf"] == "pass"
    assert a["dkim"] == "fail"
    assert a["dmarc"] == "fail"


def test_auth_from_headers_unknown_when_absent():
    a = mc._auth_from_headers({})
    assert a == {"spf": "unknown", "dkim": "unknown", "dmarc": "unknown"}


def test_gmail_body_decodes_base64url():
    import base64
    data = base64.urlsafe_b64encode(b"hello phishing body").decode()
    assert mc._gmail_body({"body": {"data": data}}) == "hello phishing body"


def test_gmail_body_walks_parts():
    import base64
    data = base64.urlsafe_b64encode(b"nested body").decode()
    payload = {"parts": [{"mimeType": "text/plain", "body": {"data": data}}]}
    assert mc._gmail_body(payload) == "nested body"
