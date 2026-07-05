from framework import mail_remediation as mr


def test_clawback_none_when_unconfigured():
    assert mr.clawback({}, "attacker@evil.com", "Invoice") is None


def test_m365_returns_none_without_mailboxes():
    assert mr.m365_clawback({"m365_tenant_id": "t"}, "a@b.com", "x") is None


def test_m365_failed_when_mailboxes_but_no_creds():
    r = mr.m365_clawback({"m365_mailboxes": "cfo@corp.com"}, "a@b.com", "x")
    assert r == {"provider": "m365", "status": "failed", "detail": "auth failed / not configured"}


def test_google_returns_none_without_config():
    assert mr.google_clawback({"google_mailboxes": "cfo@corp.com"}, "a@b.com", "x") is None
