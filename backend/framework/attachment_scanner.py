"""
Attachment malware analysis.

Layers (all best-effort, all offline-safe):
  1. Static: magic-byte type, dangerous extensions, double extensions,
     extension/type mismatch, PDF active content, archive inspection.
  2. Office macros via oletools (if installed).
  3. Hash reputation against the tenant threat-intel blocklist.
  4. Optional ClamAV (clamd) INSTREAM scan if CLAMAV_TCP="host:port" is set.

Returns a dict: {sha256, risk_score, verdict, signals, size}.
"""
from __future__ import annotations

import hashlib
import io
import os
import socket
import zipfile
from typing import Any

DANGEROUS_EXT = {
    ".exe", ".scr", ".com", ".pif", ".bat", ".cmd", ".js", ".jse", ".vbs", ".vbe",
    ".ps1", ".psm1", ".hta", ".wsf", ".wsh", ".jar", ".msi", ".msix", ".lnk",
    ".iso", ".img", ".vhd", ".reg", ".cpl", ".dll", ".apk",
}
MACRO_EXT = {".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".xlam", ".doc", ".xls", ".ppt"}
ARCHIVE_EXT = {".zip", ".rar", ".7z", ".gz", ".tar"}

# magic bytes → coarse type
_MAGIC = [
    (b"MZ", "pe"),                         # Windows executable / DLL
    (b"\x7fELF", "elf"),                   # Linux executable
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole"),  # legacy Office (macro-capable)
    (b"%PDF", "pdf"),
    (b"PK\x03\x04", "zip"),                # zip / OOXML
    (b"Rar!\x1a\x07", "rar"),
    (b"\x1f\x8b", "gzip"),
]

PDF_ACTIVE_MARKERS = [b"/JavaScript", b"/JS", b"/OpenAction", b"/AA", b"/Launch", b"/EmbeddedFile"]


def _ext(filename: str) -> str:
    name = (filename or "").lower().strip()
    dot = name.rfind(".")
    return name[dot:] if dot != -1 else ""


def _magic_type(payload: bytes) -> str:
    for sig, kind in _MAGIC:
        if payload.startswith(sig):
            return kind
    return "unknown"


def _double_extension(filename: str) -> bool:
    parts = (filename or "").lower().split(".")
    if len(parts) < 3:
        return False
    # e.g. invoice.pdf.exe → benign-looking middle ext + dangerous final ext
    benign_middle = {"pdf", "doc", "docx", "xls", "xlsx", "jpg", "png", "txt", "zip", "html"}
    return parts[-2] in benign_middle and f".{parts[-1]}" in DANGEROUS_EXT


def _scan_office_macros(payload: bytes) -> tuple[int, list[str]]:
    try:
        from oletools.olevba import VBA_Parser  # type: ignore
    except Exception:
        return 0, []
    signals: list[str] = []
    score = 0
    try:
        parser = VBA_Parser("attachment", data=payload)
        if parser.detect_vba_macros():
            score = 85
            signals.append("Office document contains VBA macros")
            for _, _, _, vba_code in parser.extract_macros():
                results = parser.analyze_macros() if hasattr(parser, "analyze_macros") else []
                for kw_type, keyword, _desc in results or []:
                    if kw_type in ("AutoExec", "Suspicious"):
                        score = 95
                        signals.append(f"Macro {kw_type}: {keyword}")
                break
        parser.close()
    except Exception:
        return score, signals
    return score, signals[:6]


def _scan_pdf(payload: bytes) -> tuple[int, list[str]]:
    found = [m.decode() for m in PDF_ACTIVE_MARKERS if m in payload]
    if found:
        return 70, [f"PDF active content: {', '.join(found[:4])}"]
    return 0, []


def _scan_zip(payload: bytes) -> tuple[int, list[str]]:
    signals: list[str] = []
    score = 0
    try:
        zf = zipfile.ZipFile(io.BytesIO(payload))
        for info in zf.infolist():
            if info.flag_bits & 0x1:
                score = max(score, 60)
                signals.append("Password-protected archive (cannot inspect)")
            inner = _ext(info.filename)
            if inner in DANGEROUS_EXT:
                score = max(score, 80)
                signals.append(f"Archive contains executable: {info.filename}")
    except Exception:
        return 0, []
    return score, signals[:6]


def _clamd_scan(payload: bytes) -> tuple[int, list[str]]:
    """Optional clamd INSTREAM scan. Returns (score, signals). Safe no-op if unavailable."""
    target = os.getenv("CLAMAV_TCP", "").strip()  # "host:port"
    if not target or ":" not in target:
        return 0, []
    host, _, port = target.partition(":")
    try:
        with socket.create_connection((host, int(port)), timeout=4) as s:
            s.sendall(b"zINSTREAM\x00")
            chunk = payload[:2 * 1024 * 1024]
            s.sendall(len(chunk).to_bytes(4, "big") + chunk)
            s.sendall((0).to_bytes(4, "big"))
            resp = s.recv(4096).decode(errors="ignore")
        if "FOUND" in resp:
            sig = resp.split(":", 1)[-1].replace("FOUND", "").strip()
            return 100, [f"ClamAV: {sig}"]
    except Exception:
        return 0, []
    return 0, []


def scan_attachment(
    filename: str,
    content_type: str,
    payload: bytes | str | None,
    intel_hashes: set[str] | None = None,
) -> dict[str, Any]:
    if isinstance(payload, str):
        payload = payload.encode("latin-1", errors="ignore")
    payload = payload or b""
    sha256 = hashlib.sha256(payload).hexdigest() if payload else ""
    ext = _ext(filename)
    magic = _magic_type(payload) if payload else "unknown"

    score = 0
    signals: list[str] = []

    if ext in DANGEROUS_EXT:
        score = max(score, 65)
        signals.append(f"Dangerous file type: {ext}")
    if _double_extension(filename):
        score = max(score, 85)
        signals.append(f"Double extension disguise: {filename}")
    if magic in ("pe", "elf"):
        score = max(score, 80)
        signals.append(f"Executable binary detected ({magic.upper()})")

    # Extension/type mismatch — e.g. an .pdf that is really a PE.
    declared_exec = ext in {".pdf", ".doc", ".docx", ".jpg", ".png", ".txt"}
    if declared_exec and magic in ("pe", "elf"):
        score = max(score, 90)
        signals.append("File content does not match its extension (disguised executable)")

    if magic == "ole" or ext in MACRO_EXT:
        m_score, m_signals = _scan_office_macros(payload)
        if m_score:
            score = max(score, m_score)
            signals.extend(m_signals)
        elif magic == "ole":
            score = max(score, 45)
            signals.append("Legacy Office file (macro-capable)")

    if magic == "pdf" or ext == ".pdf":
        p_score, p_signals = _scan_pdf(payload)
        score = max(score, p_score)
        signals.extend(p_signals)

    if magic == "zip" and ext in ARCHIVE_EXT:
        z_score, z_signals = _scan_zip(payload)
        score = max(score, z_score)
        signals.extend(z_signals)

    if sha256 and intel_hashes and sha256 in intel_hashes:
        score = 95
        signals.insert(0, "Attachment hash on threat-intel blocklist")

    c_score, c_signals = _clamd_scan(payload)
    if c_score:
        score = max(score, c_score)
        signals.extend(c_signals)

    verdict = "malicious" if score >= 80 else ("suspicious" if score >= 45 else "clean")
    return {
        "sha256": sha256,
        "risk_score": min(score, 100),
        "verdict": verdict,
        "signals": signals[:8],
        "size": len(payload),
    }
