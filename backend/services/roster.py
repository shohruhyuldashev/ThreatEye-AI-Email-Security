"""
Employee roster: parse an uploaded CSV of targets and store it for the phishing
simulator. Robust to messy headers and to a plain one-email-per-line file.
"""
from __future__ import annotations

import csv
import io
import re
from typing import Any

from db import get_db_connection

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")

# Header aliases → canonical field.
_ALIASES = {
    "email": "email", "e-mail": "email", "mail": "email", "email address": "email",
    "first_name": "first_name", "firstname": "first_name", "first name": "first_name", "fname": "first_name",
    "last_name": "last_name", "lastname": "last_name", "last name": "last_name", "surname": "last_name", "lname": "last_name",
    "name": "name", "full_name": "name", "full name": "name", "fullname": "name", "employee": "name",
    "department": "department", "dept": "department", "team": "department", "division": "department", "unit": "department",
    "position": "position", "title": "position", "role": "position", "job title": "position",
}


def _split_name(full: str) -> tuple[str, str]:
    parts = (full or "").strip().split()
    if not parts:
        return "", ""
    if len(parts) == 1:
        return parts[0], ""
    return parts[0], " ".join(parts[1:])


def parse_targets(content: str) -> list[dict[str, Any]]:
    """
    Parse CSV (or plain email list) into normalised target dicts:
    {email, first_name, last_name, department, position}. Deduped by email.
    """
    content = (content or "").strip()
    if not content:
        return []

    targets: dict[str, dict[str, Any]] = {}

    # Detect a header row: first line contains 'email'/'mail' and a delimiter.
    first_line = content.splitlines()[0].lower()
    has_header = ("email" in first_line or "mail" in first_line or "name" in first_line) and ("," in first_line or ";" in first_line or "\t" in first_line)

    if has_header:
        # Sniff the delimiter.
        try:
            dialect = csv.Sniffer().sniff(content.splitlines()[0], delimiters=",;\t")
            delimiter = dialect.delimiter
        except Exception:
            delimiter = ","
        reader = csv.DictReader(io.StringIO(content), delimiter=delimiter)
        field_map = {}
        for raw in reader.fieldnames or []:
            key = _ALIASES.get((raw or "").strip().lower())
            if key:
                field_map[raw] = key
        for row in reader:
            mapped = {}
            for raw, canonical in field_map.items():
                mapped[canonical] = (row.get(raw) or "").strip()
            email_val = mapped.get("email", "")
            m = _EMAIL_RE.search(email_val) or _EMAIL_RE.search(" ".join(row.values() if isinstance(row, dict) else []))
            if not m:
                continue
            email = m.group(0).lower()
            first = mapped.get("first_name", "")
            last = mapped.get("last_name", "")
            if not first and mapped.get("name"):
                first, last = _split_name(mapped["name"])
            targets[email] = {
                "email": email,
                "first_name": first or email.split("@")[0],
                "last_name": last,
                "department": mapped.get("department") or "General",
                "position": mapped.get("position", ""),
            }
    else:
        # Plain list: pull every email, derive a name from the local part.
        for m in _EMAIL_RE.finditer(content):
            email = m.group(0).lower()
            local = email.split("@")[0]
            first, last = _split_name(local.replace(".", " ").replace("_", " "))
            targets[email] = {
                "email": email,
                "first_name": first.capitalize() if first else local,
                "last_name": last.capitalize() if last else "",
                "department": "General",
                "position": "",
            }

    return list(targets.values())


def store_targets(organization_id: int, targets: list[dict[str, Any]]) -> int:
    """Upsert targets into the roster. Returns the number processed."""
    if not targets:
        return 0
    conn = get_db_connection()
    c = conn.cursor()
    for t in targets:
        c.execute(
            '''
            INSERT INTO sim_targets (organization_id, email, first_name, last_name, department, position)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT (organization_id, email) DO UPDATE SET
                first_name = excluded.first_name,
                last_name = excluded.last_name,
                department = excluded.department,
                position = excluded.position,
                active = TRUE
            ''',
            (organization_id, t["email"], t.get("first_name", ""), t.get("last_name", ""),
             t.get("department", "General"), t.get("position", "")),
        )
    conn.commit()
    conn.close()
    return len(targets)


def get_targets(organization_id: int, department: str | None = None, limit: int | None = None) -> list[dict[str, Any]]:
    conn = get_db_connection()
    c = conn.cursor()
    query = "SELECT id, email, first_name, last_name, department, position FROM sim_targets WHERE organization_id = ? AND active = TRUE"
    params: list[Any] = [organization_id]
    if department:
        query += " AND department = ?"
        params.append(department)
    query += " ORDER BY department, email"
    if limit:
        query += " LIMIT ?"
        params.append(limit)
    c.execute(query, tuple(params))
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return rows


def roster_summary(organization_id: int) -> dict[str, Any]:
    conn = get_db_connection()
    c = conn.cursor()
    c.execute(
        "SELECT department, COUNT(*) AS n FROM sim_targets WHERE organization_id = ? AND active = TRUE GROUP BY department ORDER BY n DESC",
        (organization_id,),
    )
    by_dept = {row["department"]: row["n"] for row in c.fetchall()}
    conn.close()
    return {"total": sum(by_dept.values()), "by_department": by_dept}


def clear_targets(organization_id: int) -> None:
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("DELETE FROM sim_targets WHERE organization_id = ?", (organization_id,))
    conn.commit()
    conn.close()
