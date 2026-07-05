from framework import siem_formats as sf
from framework.soc_metrics import sla_for
from framework.attack import TECHNIQUE_CATALOG
from framework.attachment_scanner import scan_attachment
from framework.clustering import _normalize_subject, _sender_domain

_PAYLOAD = {
    "sender": "hr@miicrosoft.com", "recipient": "cfo@corp.com", "subject": "Wire now",
    "risk_score": 92, "threat_type": "BEC / Payment Fraud", "organization_id": 1,
    "mitre": {"technique_id": "T1566", "technique": "Phishing", "tactic": "Initial Access"},
    "iocs": [{"type": "domain", "value": "miicrosoft.com"}],
    "rule_matches": [{"name": "BEC Wire-Transfer Fraud"}],
}


def test_ecs_format():
    ecs = sf.format_event("ecs", "threateye.email_alert", _PAYLOAD)
    assert ecs["event"]["kind"] == "alert"
    assert ecs["email"]["from"]["address"] == "hr@miicrosoft.com"
    assert ecs["threat"]["technique"]["id"] == "T1566"


def test_ocsf_format():
    ocsf = sf.format_event("ocsf", "threateye.email_alert", _PAYLOAD)
    assert ocsf["class_uid"] == 4009
    assert ocsf["severity_id"] == 5
    assert ocsf["attacks"][0]["technique"]["uid"] == "T1566"


def test_raw_format():
    raw = sf.format_event("raw", "x", _PAYLOAD)
    assert raw["event_type"] == "x" and raw["sender"] == "hr@miicrosoft.com"


def test_sla_mapping():
    assert sla_for("Critical") == 60
    assert sla_for("Low") == 4320
    assert sla_for("Nonsense") == 1440


def test_attack_catalog():
    assert "T1566.002" in TECHNIQUE_CATALOG
    assert TECHNIQUE_CATALOG["T1566"]["tactic"] == "Initial Access"


def test_attachment_pe_executable():
    r = scan_attachment("invoice.exe", "application/octet-stream", b"MZ\x90\x00" + b"\x00" * 64)
    assert r["verdict"] == "malicious" and r["risk_score"] >= 80


def test_attachment_disguised_executable():
    r = scan_attachment("report.pdf", "application/pdf", b"MZ\x90\x00rest")
    assert r["risk_score"] >= 90
    assert any("does not match" in s for s in r["signals"])


def test_attachment_double_extension():
    r = scan_attachment("invoice.pdf.exe", "application/octet-stream", b"data")
    assert r["risk_score"] >= 85


def test_attachment_pdf_active_content():
    r = scan_attachment("s.pdf", "application/pdf", b"%PDF-1.7\n/OpenAction /JavaScript (x)")
    assert r["risk_score"] >= 70


def test_attachment_hash_blocklist():
    import hashlib
    payload = b"benign"
    h = hashlib.sha256(payload).hexdigest()
    r = scan_attachment("n.txt", "text/plain", payload, intel_hashes={h})
    assert r["risk_score"] == 95 and r["verdict"] == "malicious"


def test_attachment_clean():
    r = scan_attachment("hello.txt", "text/plain", b"normal note")
    assert r["verdict"] == "clean" and r["risk_score"] == 0


def test_clustering_normalization():
    assert _normalize_subject("RE: Invoice 12345 overdue") == _normalize_subject("Invoice 99 overdue")
    assert _sender_domain("a@evil.com") == "evil.com"
