"""
Minimal, dependency-free Prometheus metrics.

Exposes request counters and a latency histogram in Prometheus text format so any
Prometheus/Grafana stack can scrape `/metrics` without pulling in a client library.
"""
from __future__ import annotations

import threading
import time
from typing import Any

_lock = threading.Lock()
_counters: dict[tuple, float] = {}
_hist: dict[tuple, dict[str, Any]] = {}

_BUCKETS = [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10]


def inc_counter(name: str, labels: tuple[tuple[str, str], ...] = (), value: float = 1.0) -> None:
    with _lock:
        key = (name, labels)
        _counters[key] = _counters.get(key, 0.0) + value


def observe(name: str, labels: tuple[tuple[str, str], ...], value: float) -> None:
    with _lock:
        key = (name, labels)
        h = _hist.get(key)
        if h is None:
            h = {"buckets": {b: 0 for b in _BUCKETS}, "sum": 0.0, "count": 0}
            _hist[key] = h
        h["sum"] += value
        h["count"] += 1
        for b in _BUCKETS:
            if value <= b:
                h["buckets"][b] += 1


def _fmt_labels(labels: tuple[tuple[str, str], ...], extra: tuple[tuple[str, str], ...] = ()) -> str:
    items = list(labels) + list(extra)
    if not items:
        return ""
    inner = ",".join(f'{k}="{str(v)}"' for k, v in items)
    return "{" + inner + "}"


def render() -> str:
    lines: list[str] = []
    with _lock:
        counter_names = sorted({name for name, _ in _counters})
        for name in counter_names:
            lines.append(f"# TYPE {name} counter")
            for (n, labels), val in _counters.items():
                if n == name:
                    lines.append(f"{name}{_fmt_labels(labels)} {val}")

        hist_names = sorted({name for name, _ in _hist})
        for name in hist_names:
            lines.append(f"# TYPE {name} histogram")
            for (n, labels), h in _hist.items():
                if n != name:
                    continue
                # Buckets are maintained cumulatively in observe().
                for b in _BUCKETS:
                    lines.append(f'{name}_bucket{_fmt_labels(labels, (("le", str(b)),))} {h["buckets"][b]}')
                lines.append(f'{name}_bucket{_fmt_labels(labels, (("le", "+Inf"),))} {h["count"]}')
                lines.append(f"{name}_sum{_fmt_labels(labels)} {h['sum']}")
                lines.append(f"{name}_count{_fmt_labels(labels)} {h['count']}")
    return "\n".join(lines) + "\n"


def record_request(method: str, path: str, status: int, duration: float) -> None:
    labels = (("method", method), ("path", path), ("status", str(status)))
    inc_counter("threateye_http_requests_total", labels)
    observe("threateye_http_request_duration_seconds", (("method", method), ("path", path)), duration)


class MetricsTimer:
    def __init__(self, method: str, path: str):
        self.method = method
        self.path = path
        self.start = time.perf_counter()

    def done(self, status: int) -> None:
        record_request(self.method, self.path, status, time.perf_counter() - self.start)
