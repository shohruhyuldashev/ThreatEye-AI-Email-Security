from db import get_db_connection


def create_case_for_email(email_id: int, title: str, severity: str, description: str = "") -> int:
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('''
        INSERT INTO cases (organization_id, email_id, title, severity, status, description)
        VALUES (1, ?, ?, ?, 'Open', ?)
    ''', (email_id, title, severity, description))
    case_id = c.lastrowid
    c.execute('''
        INSERT INTO case_events (case_id, event_type, details)
        VALUES (?, 'created', ?)
    ''', (case_id, description or title))
    conn.commit()
    conn.close()
    return case_id

