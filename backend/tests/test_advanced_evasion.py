# -*- coding: utf-8 -*-
"""Advanced-evasion detection: Unicode/Cyrillic homoglyph domains, zero-width
characters, invisible keyword-stuffing, and anchor-text vs href mismatch."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from services import ai_detector as d


def test_confusable_normalization_folds_cyrillic():
    assert d.normalize_confusables("mediа-tecth") == "media-tecth"  # Cyrillic а -> a
    assert d.normalize_confusables("paypаl") == "paypal"


def test_hidden_char_helpers():
    assert d.count_hidden_chars("v​e​rify") == 2
    assert d.strip_hidden_chars("v​e​rify") == "verify"


def test_non_ascii_domain_detection():
    assert d.has_non_ascii_domain("mediа-tecth.com")
    assert d.has_non_ascii_domain("xn--medi-tecth-1gb.com")
    assert not d.has_non_ascii_domain("microsoft.com")


def test_layer3_flags_non_ascii_domain():
    score, feat = d.layer3_domain_intel(["https://mediа-tecth.com/annex"])
    assert feat.get("non_ascii_domain") is True
    assert score >= 70


def test_layer1_flags_zero_width_and_invisible_text():
    _, feat = d.layer1_heuristics(
        'Please v​e​rify <span style="font-size:0pt;color:#FFFFFF">urgent wire</span>', [])
    assert feat.get("hidden_chars") is True


def test_layer1_flags_anchor_href_mismatch():
    html = '<a href="https://evil-phish.ru/login">https://www.microsoft.com/account</a>'
    _, feat = d.layer1_heuristics(html, [])
    assert feat.get("anchor_href_mismatch") is True
