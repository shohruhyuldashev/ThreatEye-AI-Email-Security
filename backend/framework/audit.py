from db import get_db_connection


def audit_log(action: str, actor: str = "system", target_type: str = "", target_id: str = "",
              details: str = "", organization_id: int = 1):
    """Record an auditable action, scoped to the acting tenant so the audit view can be
    tenant-isolated. Callers that have a session should pass the caller's org."""
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('''
        INSERT INTO audit_log (actor, action, target_type, target_id, details, organization_id)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (actor, action, target_type, str(target_id), details, int(organization_id or 1)))
    conn.commit()
    conn.close()
