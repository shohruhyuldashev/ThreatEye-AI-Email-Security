"""
CPU phishing ML classifier — runtime loader (ROADMAP §5.1).

Loads the HashingVectorizer + SGD(log-loss) model trained by
scripts/train_ml_classifier.py and scores an email as a phishing probability.
It is an independent, language-agnostic statistical signal: it learns from the
word/character n-grams of real phishing vs benign mail, so it contributes on
messages in any language, complementing the deterministic stack and the LLM.

Fail-open by design: if scikit-learn or the model artifact is missing, scoring
returns (0, available=False) and the pipeline runs exactly as before — the ML
layer can only ever raise the risk score, never block detection.
"""
from __future__ import annotations

import logging
import os
import threading

logger = logging.getLogger(__name__)

_MODEL_PATH = os.getenv(
    "ML_MODEL_PATH",
    os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "models", "ml_phish.joblib"),
)

_lock = threading.Lock()
_loaded = False
_bundle = None  # {"vectorizer", "classifier", ...}


def _load():
    global _loaded, _bundle
    if _loaded:
        return
    with _lock:
        if _loaded:
            return
        try:
            import joblib
            if not os.path.exists(_MODEL_PATH):
                logger.info("ML classifier model not found at %s; ML layer disabled.", _MODEL_PATH)
            else:
                _bundle = joblib.load(_MODEL_PATH)
                logger.info("ML classifier loaded (%s, trained_rows=%s).",
                            _MODEL_PATH, (_bundle or {}).get("trained_rows", "?"))
        except Exception as exc:  # scikit-learn missing, bad artifact, etc.
            logger.warning("ML classifier unavailable: %s", exc)
            _bundle = None
        finally:
            _loaded = True


def is_available() -> bool:
    _load()
    return _bundle is not None


def _text(email_text: str, metadata: dict | None) -> str:
    metadata = metadata or {}
    parts = [str(metadata.get("sender", "") or ""),
             str(metadata.get("subject", "") or ""),
             str(email_text or "")]
    urls = metadata.get("urls") or []
    if urls:
        parts.append(" ".join(str(u) for u in urls))
    return " ".join(parts)


def score_email(email_text: str, metadata: dict | None = None) -> tuple[int, bool]:
    """
    Return (phishing_probability_0_100, available). `available` is False when the
    model/sklearn isn't present, in which case the score is 0 and callers skip it.
    """
    _load()
    if _bundle is None:
        return 0, False
    try:
        vec = _bundle["vectorizer"]
        clf = _bundle["classifier"]
        X = vec.transform([_text(email_text, metadata)])
        prob = float(clf.predict_proba(X)[0][1])
        return int(round(prob * 100)), True
    except Exception as exc:
        logger.warning("ML scoring failed: %s", exc)
        return 0, False
