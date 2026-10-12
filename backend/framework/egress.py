"""
Egress guard — SSRF mitigation for admin-controlled outbound targets.

Several features let an (authenticated) admin point the server at an arbitrary
host: the IMAP/AI connection testers, the SIEM webhook, and the response
integrations (Slack/Teams/Jira/remediation webhooks). In a hosted, multi-tenant
setting that is an SSRF surface — a tenant admin could aim those at internal
infrastructure (the metadata endpoint at 169.254.169.254, the Postgres/Redis
containers, other tenants' services).

This module resolves a target host and blocks it when it lands on a
loopback / private / link-local / reserved range, *unless* the hostname is an
explicitly allow-listed internal service (the bundled docker-compose stack
legitimately uses private service names like ``mail_server`` and
``elasticsearch``) or its address falls inside an operator-configured CIDR.

Defaults are closed (guard on, only the bundled service names allowed). An
operator loosens it per deployment via env.

Env:
  EGRESS_GUARD           on|off     (default on) — master switch
  EGRESS_INTERNAL_HOSTS  csv        hostnames allowed to resolve to private IPs
                                    (default: the compose service names)
  EGRESS_ALLOW_CIDRS     csv        extra IP/CIDRs to permit (e.g. a trusted
                                    internal SIEM subnet)

Note: this is resolve-then-check, so it does not by itself defeat a DNS-rebinding
TOCTOU race between the check and the socket connect. It closes the common,
high-impact case (static internal addresses / the metadata IP). Pinning the
resolved address into the connection is a hardening follow-up.
"""
from __future__ import annotations

import ipaddress
import logging
import os
import socket
from urllib.parse import urlsplit

logger = logging.getLogger(__name__)

# Bundled docker-compose services that legitimately resolve to private IPs.
_DEFAULT_INTERNAL_HOSTS = (
    "gophish", "ollama", "postgres", "redis", "mail_server",
    "elasticsearch", "kibana", "frontend", "backend", "webmail", "caddy",
)


class EgressBlocked(ValueError):
    """Raised when an outbound target is not permitted by the egress policy."""


def _guard_enabled() -> bool:
    return os.getenv("EGRESS_GUARD", "on").strip().lower() not in ("0", "off", "false", "no")


def _internal_hosts() -> set[str]:
    raw = os.getenv("EGRESS_INTERNAL_HOSTS")
    hosts = [h.strip().lower() for h in raw.split(",")] if raw else list(_DEFAULT_INTERNAL_HOSTS)
    return {h for h in hosts if h}


def _allow_networks() -> list[ipaddress._BaseNetwork]:
    raw = os.getenv("EGRESS_ALLOW_CIDRS", "")
    nets: list[ipaddress._BaseNetwork] = []
    for item in raw.split(","):
        item = item.strip()
        if not item:
            continue
        try:
            nets.append(ipaddress.ip_network(item, strict=False))
        except ValueError:
            logger.warning("Ignoring invalid EGRESS_ALLOW_CIDRS entry: %r", item)
    return nets


def _host_from_target(target: str) -> str:
    """Extract the bare hostname from a URL or a ``host`` / ``host:port`` string."""
    t = (target or "").strip()
    if not t:
        return ""
    if "://" in t:
        host = urlsplit(t).hostname or ""
        return host.lower()
    # Bare host or host:port (IMAP server). Strip a trailing :port, but keep
    # bracketed IPv6 literals intact.
    if t.startswith("["):  # [::1]:143
        return t[1:].split("]")[0].lower()
    if t.count(":") == 1:  # host:port
        t = t.split(":", 1)[0]
    return t.lower()


def _ip_is_blocked(ip: ipaddress._BaseAddress) -> bool:
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


def is_allowed(target: str) -> tuple[bool, str]:
    """
    Return (allowed, reason). ``target`` may be a full URL, a bare host, or
    ``host:port``. Resolution failures are reported but not blocked here — the
    caller's own connect will surface a real network error.
    """
    if not _guard_enabled():
        return True, "egress guard disabled"

    host = _host_from_target(target)
    if not host:
        return False, "no host in target"

    if host in _internal_hosts():
        return True, f"allow-listed internal host '{host}'"

    allow_nets = _allow_networks()

    # A literal IP target: check it directly.
    try:
        literal = ipaddress.ip_address(host)
        if any(literal in n for n in allow_nets):
            return True, f"{literal} in EGRESS_ALLOW_CIDRS"
        if _ip_is_blocked(literal):
            return False, f"target IP {literal} is in a blocked (private/loopback/link-local/reserved) range"
        return True, f"public IP {literal}"
    except ValueError:
        pass  # it's a hostname — resolve it

    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as exc:
        # Fail closed: if we cannot resolve the host we cannot prove it is safe, so
        # deny by default (set EGRESS_ALLOW_ON_DNS_FAIL=1 to defer to the connect).
        if os.getenv("EGRESS_ALLOW_ON_DNS_FAIL", "0").lower() in ("1", "true", "yes", "on"):
            return True, f"DNS resolution failed ({exc}); deferring to connect"
        return False, f"DNS resolution failed ({exc}); denied (fail-closed)"

    addrs = {info[4][0] for info in infos}
    for addr in addrs:
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            continue
        if any(ip in n for n in allow_nets):
            continue
        if _ip_is_blocked(ip):
            return False, f"'{host}' resolves to {ip}, a blocked (private/loopback/link-local/reserved) address"
    return True, f"'{host}' resolves to public address(es)"


def assert_allowed(target: str, what: str = "outbound request") -> None:
    """Raise EgressBlocked if ``target`` is not permitted by the egress policy."""
    allowed, reason = is_allowed(target)
    if not allowed:
        logger.warning("Egress blocked for %s -> %s: %s", what, target, reason)
        raise EgressBlocked(f"Blocked {what}: {reason}")
