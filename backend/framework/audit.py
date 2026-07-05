from db import get_db_connection


def audit_log(action: str, actor: str = "system", target_type: str = "", target_id: str = "", details: str = ""):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('''
        INSERT INTO audit_log (actor, action, target_type, target_id, details)
        VALUES (?, ?, ?, ?, ?)
    ''', (actor, action, target_type, str(target_id), details))
    conn.commit()
    conn.close()

