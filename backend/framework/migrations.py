"""
Lightweight, dependency-free SQL migration runner.

Applies ordered `backend/migrations/*.sql` files exactly once, tracked in a
`schema_migrations` table. This is the Alembic-style foundation for evolving the
schema going forward, kept in the project's raw-SQL style (no ORM required).
"""
from __future__ import annotations

import logging
from pathlib import Path

import psycopg2

from db import DATABASE_URL
from framework.security import hash_password

logger = logging.getLogger(__name__)

MIGRATIONS_DIR = Path(__file__).resolve().parents[1] / "migrations"


def run_migrations() -> list[str]:
    """Apply any pending .sql migrations in filename order. Returns applied versions."""
    applied_now: list[str] = []
    conn = psycopg2.connect(DATABASE_URL)
    try:
        cur = conn.cursor()
        cur.execute(
            "CREATE TABLE IF NOT EXISTS schema_migrations ("
            "version TEXT PRIMARY KEY, applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)"
        )
        conn.commit()

        cur.execute("SELECT version FROM schema_migrations")
        done = {row[0] for row in cur.fetchall()}

        for path in sorted(MIGRATIONS_DIR.glob("*.sql")):
            version = path.stem
            if version in done:
                continue
            logger.info("Applying migration %s", version)
            try:
                cur.execute(path.read_text())
                cur.execute("INSERT INTO schema_migrations (version) VALUES (%s)", (version,))
                conn.commit()
                applied_now.append(version)
            except Exception:
                conn.rollback()
                logger.exception("Migration %s failed", version)
                raise
    finally:
        conn.close()
    return applied_now


def seed_saas_defaults() -> None:
    """
    Ensure a default tenant + an initial 'admin' owner user exist.

    The admin password is migrated from the legacy `settings.admin_password`
    value when present (hashing a plaintext value), otherwise it falls back to
    'admin' so the shipped default login keeps working until it's changed.
    """
    conn = psycopg2.connect(DATABASE_URL)
    try:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO organizations (name) VALUES ('Default Organization') "
            "ON CONFLICT (name) DO NOTHING"
        )

        cur.execute("SELECT COUNT(*) FROM users")
        if cur.fetchone()[0] == 0:
            cur.execute("SELECT value FROM settings WHERE key = 'admin_password'")
            row = cur.fetchone()
            saved = row[0] if row and row[0] else None
            if saved and saved.startswith("pbkdf2_sha256$"):
                pw_hash = saved
            elif saved:
                pw_hash = hash_password(saved)
            else:
                pw_hash = hash_password("admin")

            cur.execute(
                "INSERT INTO users (organization_id, username, email, full_name, password_hash, role) "
                "VALUES (1, 'admin', 'admin@threateye.local', 'Administrator', %s, 'owner') "
                "ON CONFLICT (username) DO NOTHING",
                (pw_hash,),
            )
            logger.info("Seeded default 'admin' owner user.")
        conn.commit()
    finally:
        conn.close()
