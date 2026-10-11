#!/usr/bin/env python3
"""
Train the CPU phishing ML classifier (ROADMAP §5.1) on the 1M labeled dataset.

A HashingVectorizer (no stored vocabulary → tiny, reproducible model) over
sender + subject + body, feeding an SGDClassifier with log-loss (logistic
regression trained incrementally, minutes on CPU, no GPU). The result is an
independent, language-agnostic statistical signal that complements the
deterministic stack and the LLM — it learns from the words/character n-grams of
real phishing vs benign mail, so it fires on messages in any language.

Output: backend/models/ml_phish.joblib  (loaded by services/ml_classifier.py).

Usage:
    python3 scripts/train_ml_classifier.py                 # full data/phish_dataset.jsonl
    python3 scripts/train_ml_classifier.py --data <path> --max-rows 200000
"""
from __future__ import annotations

import argparse
import json
import os
import sys

from sklearn.feature_extraction.text import HashingVectorizer
from sklearn.linear_model import SGDClassifier
from sklearn.metrics import precision_recall_fscore_support, confusion_matrix
import joblib

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_DATA = os.path.join(REPO, "data", "phish_dataset.jsonl")
OUT = os.path.join(REPO, "backend", "models", "ml_phish.joblib")
N_FEATURES = 2 ** 18  # ~262k hashed features; model is just the SGD coef (~1-2 MB)


def row_text(row: dict) -> str:
    """The text the classifier sees — sender + subject + body (+ urls)."""
    return " ".join(str(row.get(k, "") or "") for k in ("sender", "subject", "body")) + \
           " " + " ".join(row.get("urls", []) or [])


def iter_rows(path: str, max_rows: int | None):
    n = 0
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            yield row
            n += 1
            if max_rows and n >= max_rows:
                return


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default=DEFAULT_DATA)
    ap.add_argument("--max-rows", type=int, default=None)
    ap.add_argument("--out", default=OUT)
    ap.add_argument("--test-frac", type=float, default=0.1)
    args = ap.parse_args()

    if not os.path.exists(args.data):
        print(f"Dataset not found: {args.data}\n"
              f"Build it first (scripts/build_dataset.py) or pass --data.", file=sys.stderr)
        return 1

    vec = HashingVectorizer(
        n_features=N_FEATURES, alternate_sign=False, ngram_range=(1, 2),
        norm="l2", lowercase=True,
    )
    clf = SGDClassifier(loss="log_loss", alpha=1e-5, max_iter=1, warm_start=True, random_state=42)

    # Stream in mini-batches so 1M rows never need to fit in memory at once.
    BATCH = 20000
    classes = [0, 1]  # 0=benign, 1=phishing
    texts, labels = [], []
    test_X, test_y = [], []
    n_train = n_test = 0
    first = True
    import random
    random.seed(42)

    def flush(texts, labels):
        nonlocal first
        X = vec.transform(texts)
        clf.partial_fit(X, labels, classes=classes if first else None)
        first = False

    for i, row in enumerate(iter_rows(args.data, args.max_rows)):
        label = 1 if str(row.get("label", "")).lower() == "phishing" else 0
        txt = row_text(row)
        # Hold out a random test slice.
        if random.random() < args.test_frac:
            test_X.append(txt); test_y.append(label); n_test += 1
            continue
        texts.append(txt); labels.append(label); n_train += 1
        if len(texts) >= BATCH:
            flush(texts, labels); texts, labels = [], []
    if texts:
        flush(texts, labels)

    print(f"Trained on {n_train} rows; evaluating on {n_test} held-out rows.")
    if test_X:
        Xt = vec.transform(test_X)
        pred = clf.predict(Xt)
        p, r, f1, _ = precision_recall_fscore_support(test_y, pred, labels=[1], average="binary", zero_division=0)
        tn, fp, fn, tp = confusion_matrix(test_y, pred, labels=[0, 1]).ravel()
        fpr = fp / (fp + tn) if (fp + tn) else 0.0
        print(f"  phishing  precision={p:.4f}  recall={r:.4f}  f1={f1:.4f}  FPR={fpr:.4f}")
        print(f"  confusion: tp={tp} fp={fp} fn={fn} tn={tn}")

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    joblib.dump({"vectorizer": vec, "classifier": clf, "n_features": N_FEATURES,
                 "version": 1, "trained_rows": n_train}, args.out, compress=3)
    size_mb = os.path.getsize(args.out) / 1e6
    print(f"Saved model → {args.out} ({size_mb:.1f} MB)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
