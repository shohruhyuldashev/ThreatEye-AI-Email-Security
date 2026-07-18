#!/usr/bin/env python3
"""
Validate the detector against the labeled dataset at scale.

Runs every sample through the detector's deterministic layer (no LLM — 100k CPU
inferences is not feasible, and this layer must stand on its own) and reports the
confusion matrix, precision, recall, F1 and accuracy for phishing detection.

    docker compose exec -T backend python /app/../scripts/validate_dataset.py   # inside container
    # or from repo root with the backend importable:
    PYTHONPATH=backend python3 scripts/validate_dataset.py --data data/phish_dataset.jsonl --limit 100000
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="data/phish_dataset.jsonl")
    ap.add_argument("--limit", type=int, default=0, help="0 = all")
    args = ap.parse_args()

    try:
        from services.ai_detector import deterministic_score
    except ImportError:
        sys.path.insert(0, "backend")
        from services.ai_detector import deterministic_score

    tp = fp = tn = fn = 0
    n = 0
    t0 = time.time()
    path = Path(args.data)
    if not path.exists():
        print(f"dataset not found: {path}", file=sys.stderr)
        return 1

    with open(path) as f:
        for line in f:
            if args.limit and n >= args.limit:
                break
            s = json.loads(line)
            content = f"Subject: {s['subject']}\nBody: {s['body']}"
            meta = {"spf": s["spf"], "dkim": s["dkim"], "dmarc": s["dmarc"], "sender": s["sender"]}
            verdict = deterministic_score(content, meta)
            predicted_phish = verdict["is_threat"]
            actual_phish = s["label"] == "phishing"
            if predicted_phish and actual_phish:
                tp += 1
            elif predicted_phish and not actual_phish:
                fp += 1
            elif not predicted_phish and not actual_phish:
                tn += 1
            else:
                fn += 1
            n += 1
            if n % 20000 == 0:
                print(f"  … {n} scored ({n/(time.time()-t0):.0f}/s)", file=sys.stderr)

    dt = time.time() - t0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    accuracy = (tp + tn) / n if n else 0.0

    print(json.dumps({
        "samples": n,
        "elapsed_sec": round(dt, 1),
        "throughput_per_sec": round(n / dt, 0) if dt else None,
        "confusion": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "accuracy": round(accuracy, 4),
        "false_positive_rate": round(fp / (fp + tn), 4) if (fp + tn) else 0.0,
    }, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
