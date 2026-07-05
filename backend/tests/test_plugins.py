import json
import os

import pytest

from framework import plugins as P

SAMPLE = os.path.join(os.path.dirname(__file__), "..", "..", "plugins", "samples", "emotet-pack.tap")


def _valid_doc():
    return {
        "tap_version": "1.0",
        "plugin": {"id": "test-pack", "name": "Test Pack", "category": "detection"},
        "detection_rules": [
            {"rule_id": "r1", "name": "Rule 1", "conditions": {"min_score": 50, "threat_type_contains": "Malware"}}
        ],
        "intel_indicators": [{"type": "domain", "value": "Evil.Com", "verdict": "block"}],
        "playbooks": [],
    }


def test_validate_ok():
    out = P.validate_tap(_valid_doc())
    assert out["plugin"]["id"] == "test-pack"
    assert out["plugin"]["version"] == "1.0"  # defaulted


def test_reject_bad_version():
    d = _valid_doc(); d["tap_version"] = "9.9"
    with pytest.raises(P.PluginError):
        P.validate_tap(d)


def test_reject_bad_id():
    d = _valid_doc(); d["plugin"]["id"] = "Bad ID!"
    with pytest.raises(P.PluginError):
        P.validate_tap(d)


def test_reject_unknown_condition():
    d = _valid_doc(); d["detection_rules"][0]["conditions"] = {"exec": "rm -rf /"}
    with pytest.raises(P.PluginError):
        P.validate_tap(d)


def test_reject_bad_intel_type():
    d = _valid_doc(); d["intel_indicators"] = [{"type": "registry", "value": "x"}]
    with pytest.raises(P.PluginError):
        P.validate_tap(d)


def test_reject_empty_content():
    d = {"tap_version": "1.0", "plugin": {"id": "empty", "name": "Empty"}, "detection_rules": [], "intel_indicators": [], "playbooks": []}
    with pytest.raises(P.PluginError):
        P.validate_tap(d)


def test_signature_roundtrip():
    doc = _valid_doc()
    sig = P.sign_tap(doc, "secret-key")
    assert len(sig) == 64
    # Deterministic over canonical content.
    assert P.sign_tap(doc, "secret-key") == sig


def test_sample_plugin_parses():
    with open(os.path.abspath(SAMPLE)) as f:
        tap = P.parse_tap(f.read())
    assert tap["plugin"]["id"] == "emotet-pack"
    assert len(tap["intel_indicators"]) == 3
    assert len(tap["detection_rules"]) == 1
