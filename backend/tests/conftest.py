"""
Shared test fixtures. Stubs the `db` module so pure-logic modules import without a
live Postgres, and sets a fixed auth secret for deterministic token tests.
"""
import os
import sys
import types
from pathlib import Path

# Make the backend package importable (tests/ -> backend/).
BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))

os.environ.setdefault("THREATEYE_AUTH_SECRET", "unit-test-secret")


def _install_db_stub():
    if "db" in sys.modules:
        return
    stub = types.ModuleType("db")

    def _no_db(*_a, **_k):
        raise RuntimeError("DB access not available in unit tests")

    stub.get_db_connection = _no_db
    stub.DATABASE_URL = "postgresql://test/test"
    sys.modules["db"] = stub


_install_db_stub()


class FakeCursor:
    """Minimal cursor over an in-memory list of dict rows for query-shape tests."""

    def __init__(self, rows):
        self._all = rows
        self._result = []

    def execute(self, query, params=()):
        q = query.lower()
        if "from reputation" in q:
            org = params[0]
            values = {str(v).lower() for v in params[1:]}
            self._result = [r for r in self._all if r.get("organization_id") == org and str(r.get("value", "")).lower() in values]
        else:
            self._result = []
        return self

    def fetchall(self):
        return [dict(r) for r in self._result]

    def fetchone(self):
        return dict(self._result[0]) if self._result else None
