"""Egress guard — SSRF policy for admin-controlled outbound targets."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from framework import egress


def _clear_env():
    for k in ("EGRESS_GUARD", "EGRESS_INTERNAL_HOSTS", "EGRESS_ALLOW_CIDRS"):
        os.environ.pop(k, None)


def test_blocks_cloud_metadata_ip():
    _clear_env()
    allowed, _ = egress.is_allowed("http://169.254.169.254/latest/meta-data/")
    assert not allowed


def test_blocks_loopback_and_private_literals():
    _clear_env()
    for target in ("http://127.0.0.1:9200/", "http://10.0.0.5/", "https://192.168.1.1/x", "redis://[::1]:6379"):
        allowed, _ = egress.is_allowed(target)
        assert not allowed, target


def test_blocks_private_host_port_without_scheme():
    _clear_env()
    # IMAP server field: bare host:port.
    allowed, _ = egress.is_allowed("127.0.0.1:143")
    assert not allowed


def test_allows_bundled_internal_service_names():
    _clear_env()
    for host in ("http://elasticsearch:9200/threateye-alerts/_doc", "mail_server", "http://ollama:11434/v1"):
        allowed, _ = egress.is_allowed(host)
        assert allowed, host


def test_allows_public_ip_literal():
    _clear_env()
    allowed, _ = egress.is_allowed("https://8.8.8.8/")
    assert allowed


def test_guard_can_be_disabled():
    _clear_env()
    os.environ["EGRESS_GUARD"] = "off"
    try:
        allowed, _ = egress.is_allowed("http://169.254.169.254/")
        assert allowed
    finally:
        _clear_env()


def test_allow_cidr_permits_specific_private_range():
    _clear_env()
    os.environ["EGRESS_ALLOW_CIDRS"] = "10.1.2.0/24"
    try:
        assert egress.is_allowed("http://10.1.2.3:9200/")[0] is True
        # A private IP outside the allow-listed CIDR is still blocked.
        assert egress.is_allowed("http://10.9.9.9/")[0] is False
    finally:
        _clear_env()


def test_custom_internal_hosts_override_default():
    _clear_env()
    os.environ["EGRESS_INTERNAL_HOSTS"] = "my-siem"
    try:
        # The default compose names are no longer allow-listed by name, so a
        # name that resolves to nothing public defers to connect (DNS fail -> allow),
        # but an explicit private literal is still blocked.
        assert egress.is_allowed("http://10.0.0.1/")[0] is False
    finally:
        _clear_env()


def test_assert_allowed_raises_on_blocked():
    _clear_env()
    try:
        egress.assert_allowed("http://169.254.169.254/", "metadata probe")
        assert False, "expected EgressBlocked"
    except egress.EgressBlocked:
        pass
