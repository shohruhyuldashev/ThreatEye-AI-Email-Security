"""CPU ML classifier — fail-open behaviour and basic phishing/benign separation."""
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from services import ml_classifier


PHISH = (
    "Reset your password at http://0ffice365-reset.gq/login and enter your credentials now",
    {"sender": "it@0ffice365-reset.gq", "subject": "Mandatory password reset",
     "urls": ["http://0ffice365-reset.gq/login"]},
)
BENIGN = (
    "Hi team, attached is the Q3 report for review. Thanks.",
    {"sender": "cfo@corp.com", "subject": "Q3 report", "urls": []},
)


def test_score_shape_is_always_safe():
    # Whether or not the model/sklearn is present, scoring returns (int, bool)
    # and never raises — the pipeline must keep working either way.
    score, ok = ml_classifier.score_email(*PHISH)
    assert isinstance(score, int) and 0 <= score <= 100
    assert isinstance(ok, bool)


@pytest.mark.skipif(not ml_classifier.is_available(), reason="ML model/sklearn not present")
def test_phishing_scores_higher_than_benign():
    p, _ = ml_classifier.score_email(*PHISH)
    b, _ = ml_classifier.score_email(*BENIGN)
    assert p > b
    assert p >= 75  # confident enough to act as a raise-only booster
