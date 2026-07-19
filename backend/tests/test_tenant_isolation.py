"""
Tenant-isolation regression guards.

Every read endpoint that returns tenant-owned rows must scope its query by
`organization_id`. These are static guards so that a future change removing a WHERE
clause fails CI instead of silently leaking one customer's data to another. The live
cross-tenant behaviour was verified end-to-end (org-2 rows are invisible to an org-1
session); this keeps it from regressing.
"""
import os
import re

ROUTER = os.path.join(os.path.dirname(__file__), "..", "api", "router.py")


def _handler_source(name: str) -> str:
    src = open(ROUTER, encoding="utf-8").read()
    # Grab from the handler's def to the next top-level def.
    m = re.search(rf"\ndef {re.escape(name)}\(.*?(?=\n@router\.|\ndef )", src, re.S)
    assert m, f"handler {name} not found in router.py"
    return m.group(0)


def test_scoped_read_endpoints_filter_by_org():
    # handler name -> the org-scoping token its SQL must contain
    scoped = {
        "list_iocs": "e.organization_id",
        "list_mitre_mappings": "e.organization_id",
        "list_cases": "c.organization_id",
        "get_audit_log": "organization_id = ?",
        "list_siem_events": "organization_id = ?",
    }
    for handler, token in scoped.items():
        body = _handler_source(handler)
        assert "_org_id(_auth)" in body, f"{handler} does not resolve the caller's org"
        assert token in body, f"{handler} is missing org scoping ({token!r}) — tenant leak risk"


def test_audit_log_writes_organization_id():
    src = open(os.path.join(os.path.dirname(__file__), "..", "framework", "audit.py")).read()
    assert "organization_id" in src, "audit_log() must record organization_id"
