import os
import re

import psycopg2


DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://threateye:threateye@postgres:5432/threateye",
)


class DbRow(dict):
    def __init__(self, keys, values):
        super().__init__(zip(keys, values))
        self._keys = list(keys)
        self._values = list(values)

    def __getitem__(self, key):
        if isinstance(key, int):
            return self._values[key]
        return super().__getitem__(key)


class DbCursor:
    SERIAL_TABLES = {
        "emails",
        "quarantine",
        "simulations",
        "user_profiles",
        "email_timeline",
        "email_feedback",
        "organizations",
        "users",
        "api_keys",
        "policies",
        "attachments",
        "cases",
        "case_events",
        "audit_log",
        "iocs",
        "mitre_mappings",
        "siem_events",
        "playbooks",
        "playbook_runs",
        "detection_rules",
        "intel_indicators",
        "remediation_actions",
        "sim_targets",
        "sim_campaigns",
        "phishing_reports",
        "reputation",
        "plugins",
    }

    def __init__(self, cursor):
        self._cursor = cursor
        self.lastrowid = None

    def execute(self, query, params=None):
        self.lastrowid = None
        sql = self._translate_sql(query)
        insert_table = self._insert_table(sql)
        should_return_id = insert_table in self.SERIAL_TABLES and " returning " not in sql.lower()
        if should_return_id:
            sql = f"{sql.rstrip().rstrip(';')} RETURNING id"

        # Only pass params when there are some: psycopg2 does %-substitution whenever a
        # params sequence is given, which breaks queries containing a literal % (e.g.
        # LIKE 'sim_%'). With no params, execute(sql) leaves the % untouched.
        if params:
            self._cursor.execute(sql, params)
        else:
            self._cursor.execute(sql)

        if should_return_id:
            row = self._cursor.fetchone()
            self.lastrowid = row[0] if row else None
        return self

    def fetchone(self):
        row = self._cursor.fetchone()
        if row is None:
            return None
        return self._wrap_row(row)

    def fetchall(self):
        return [self._wrap_row(row) for row in self._cursor.fetchall()]

    def close(self):
        self._cursor.close()

    def _wrap_row(self, row):
        keys = [desc[0] for desc in self._cursor.description]
        return DbRow(keys, row)

    def _translate_sql(self, query: str) -> str:
        sql = query.strip()
        sql = sql.replace("?", "%s")
        sql = re.sub(r"\bDATETIME\b", "TIMESTAMP", sql, flags=re.IGNORECASE)
        sql = re.sub(r"\bINTEGER PRIMARY KEY AUTOINCREMENT\b", "SERIAL PRIMARY KEY", sql, flags=re.IGNORECASE)
        return sql

    def _insert_table(self, sql: str):
        match = re.match(r"insert\s+into\s+([a-zA-Z_][a-zA-Z0-9_]*)", sql.strip(), re.IGNORECASE)
        return match.group(1).lower() if match else None


class DbConnection:
    def __init__(self, conn):
        self._conn = conn

    def cursor(self):
        return DbCursor(self._conn.cursor())

    def commit(self):
        self._conn.commit()

    def rollback(self):
        self._conn.rollback()

    def close(self):
        self._conn.close()


def get_db_connection():
    conn = psycopg2.connect(DATABASE_URL)
    return DbConnection(conn)


def init_db():
    conn = get_db_connection()
    c = conn.cursor()

    c.execute('''
        CREATE TABLE IF NOT EXISTS emails (
            id SERIAL PRIMARY KEY,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            sender TEXT NOT NULL,
            subject TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            url_threat_score INTEGER NOT NULL,
            urls_found TEXT,
            status TEXT NOT NULL,
            threat_type TEXT DEFAULT 'Unknown',
            confidence_score INTEGER DEFAULT 0,
            recommended_action TEXT,
            ai_analysis_log TEXT,
            evidence_json TEXT,
            agent_verdicts_json TEXT,
            review_status TEXT DEFAULT 'Unreviewed'
        )
    ''')
    _ensure_column(c, "emails", "threat_type", "TEXT DEFAULT 'Unknown'")
    _ensure_column(c, "emails", "confidence_score", "INTEGER DEFAULT 0")
    _ensure_column(c, "emails", "recommended_action", "TEXT")
    _ensure_column(c, "emails", "ai_analysis_log", "TEXT")
    _ensure_column(c, "emails", "evidence_json", "TEXT")
    _ensure_column(c, "emails", "agent_verdicts_json", "TEXT")
    _ensure_column(c, "emails", "review_status", "TEXT DEFAULT 'Unreviewed'")

    c.execute('''
        CREATE TABLE IF NOT EXISTS quarantine (
            id SERIAL PRIMARY KEY,
            email_id INTEGER,
            recipient TEXT NOT NULL,
            ai_reason TEXT NOT NULL,
            quarantined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (email_id) REFERENCES emails(id) ON DELETE CASCADE
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS simulations (
            id SERIAL PRIMARY KEY,
            target_name TEXT,
            target_department TEXT,
            run_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            status TEXT
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS user_profiles (
            id SERIAL PRIMARY KEY,
            email TEXT UNIQUE NOT NULL,
            role TEXT NOT NULL,
            behavioral_risk_score INTEGER DEFAULT 0,
            failed_simulations_count INTEGER DEFAULT 0,
            typical_topics TEXT
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS organizations (
            id SERIAL PRIMARY KEY,
            name TEXT NOT NULL UNIQUE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS api_keys (
            id SERIAL PRIMARY KEY,
            organization_id INTEGER NOT NULL DEFAULT 1,
            name TEXT NOT NULL,
            key_hash TEXT NOT NULL,
            active BOOLEAN DEFAULT TRUE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS policies (
            id SERIAL PRIMARY KEY,
            organization_id INTEGER NOT NULL DEFAULT 1,
            name TEXT NOT NULL,
            conditions_json TEXT NOT NULL,
            action TEXT NOT NULL,
            severity TEXT DEFAULT 'Medium',
            enabled BOOLEAN DEFAULT TRUE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS domain_intel_cache (
            domain TEXT PRIMARY KEY,
            risk_score INTEGER NOT NULL,
            features_json TEXT NOT NULL,
            checked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS email_timeline (
            id SERIAL PRIMARY KEY,
            email_id INTEGER NOT NULL,
            event_type TEXT NOT NULL,
            details TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (email_id) REFERENCES emails(id) ON DELETE CASCADE
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS email_feedback (
            id SERIAL PRIMARY KEY,
            email_id INTEGER NOT NULL,
            verdict TEXT NOT NULL,
            notes TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (email_id) REFERENCES emails(id) ON DELETE CASCADE
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS attachments (
            id SERIAL PRIMARY KEY,
            email_id INTEGER NOT NULL,
            filename TEXT NOT NULL,
            content_type TEXT,
            size_bytes INTEGER DEFAULT 0,
            risk_score INTEGER DEFAULT 0,
            signals_json TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (email_id) REFERENCES emails(id) ON DELETE CASCADE
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS cases (
            id SERIAL PRIMARY KEY,
            organization_id INTEGER NOT NULL DEFAULT 1,
            email_id INTEGER,
            title TEXT NOT NULL,
            severity TEXT DEFAULT 'Medium',
            status TEXT DEFAULT 'Open',
            assignee TEXT,
            description TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE,
            FOREIGN KEY (email_id) REFERENCES emails(id) ON DELETE SET NULL
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS case_events (
            id SERIAL PRIMARY KEY,
            case_id INTEGER NOT NULL,
            event_type TEXT NOT NULL,
            details TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS audit_log (
            id SERIAL PRIMARY KEY,
            actor TEXT DEFAULT 'system',
            action TEXT NOT NULL,
            target_type TEXT,
            target_id TEXT,
            details TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS iocs (
            id SERIAL PRIMARY KEY,
            email_id INTEGER NOT NULL,
            type TEXT NOT NULL,
            value TEXT NOT NULL,
            source TEXT,
            confidence INTEGER DEFAULT 60,
            tags_json TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(email_id, type, value),
            FOREIGN KEY (email_id) REFERENCES emails(id) ON DELETE CASCADE
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS mitre_mappings (
            id SERIAL PRIMARY KEY,
            email_id INTEGER NOT NULL,
            technique_id TEXT NOT NULL,
            technique TEXT NOT NULL,
            tactic TEXT NOT NULL,
            defense TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (email_id) REFERENCES emails(id) ON DELETE CASCADE
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS siem_events (
            id SERIAL PRIMARY KEY,
            event_type TEXT NOT NULL,
            payload_json TEXT NOT NULL,
            destination TEXT,
            status TEXT NOT NULL,
            response_code INTEGER,
            error TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS playbooks (
            id SERIAL PRIMARY KEY,
            organization_id INTEGER NOT NULL DEFAULT 1,
            name TEXT NOT NULL,
            trigger_action TEXT NOT NULL,
            steps_json TEXT NOT NULL,
            enabled BOOLEAN DEFAULT TRUE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS playbook_runs (
            id SERIAL PRIMARY KEY,
            playbook_id INTEGER NOT NULL,
            email_id INTEGER,
            case_id INTEGER,
            status TEXT NOT NULL,
            result_json TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (playbook_id) REFERENCES playbooks(id) ON DELETE CASCADE,
            FOREIGN KEY (email_id) REFERENCES emails(id) ON DELETE SET NULL,
            FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE SET NULL
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS detection_rules (
            id SERIAL PRIMARY KEY,
            rule_id TEXT NOT NULL UNIQUE,
            name TEXT NOT NULL,
            description TEXT,
            conditions_json TEXT NOT NULL,
            severity TEXT DEFAULT 'Medium',
            enabled BOOLEAN DEFAULT TRUE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Indexes for the dashboard/monitor/quarantine hot paths (idempotent).
    for index_sql in [
        "CREATE INDEX IF NOT EXISTS idx_emails_timestamp ON emails (timestamp DESC)",
        "CREATE INDEX IF NOT EXISTS idx_emails_risk_score ON emails (risk_score)",
        "CREATE INDEX IF NOT EXISTS idx_emails_status ON emails (status)",
        "CREATE INDEX IF NOT EXISTS idx_quarantine_email_id ON quarantine (email_id)",
        "CREATE INDEX IF NOT EXISTS idx_quarantine_at ON quarantine (quarantined_at DESC)",
        "CREATE INDEX IF NOT EXISTS idx_timeline_email_id ON email_timeline (email_id)",
        "CREATE INDEX IF NOT EXISTS idx_iocs_email_id ON iocs (email_id)",
        "CREATE INDEX IF NOT EXISTS idx_mitre_email_id ON mitre_mappings (email_id)",
        "CREATE INDEX IF NOT EXISTS idx_audit_created_at ON audit_log (created_at DESC)",
        "CREATE INDEX IF NOT EXISTS idx_cases_created_at ON cases (created_at DESC)",
    ]:
        c.execute(index_sql)

    c.execute("INSERT INTO organizations (name) VALUES ('Default Organization') ON CONFLICT(name) DO NOTHING")

    c.execute('SELECT COUNT(*) FROM emails')
    if c.fetchone()[0] == 0:
        _insert_initial_dummy_data(c)

    c.execute('SELECT COUNT(*) FROM settings')
    if c.fetchone()[0] == 0:
        c.execute("INSERT INTO settings (key, value) VALUES ('ai_model', 'glm-4.5')")
        c.execute("INSERT INTO settings (key, value) VALUES ('ai_aggressiveness', 'Medium')")
        c.execute("INSERT INTO settings (key, value) VALUES ('imap_server', 'mail_server')")
        c.execute("INSERT INTO settings (key, value) VALUES ('imap_user', 'default@example.com')")
        c.execute("INSERT INTO settings (key, value) VALUES ('imap_pass', 'mail_server')")

    conn.commit()
    conn.close()


def _insert_initial_dummy_data(cursor):
    cursor.execute('''
        INSERT INTO emails (sender, subject, risk_score, url_threat_score, urls_found, status, threat_type, confidence_score, recommended_action, ai_analysis_log, evidence_json, agent_verdicts_json)
        VALUES (
            'hr-update@miicrosoft.com',
            'URGENT: Mandatory Compliance Review',
            95,
            98,
            '["http://miicrosoft.com/login"]',
            'Quarantined',
            'Credential Harvesting',
            92,
            'Quarantine immediately and require password reset review for targeted users.',
            'Typosquatting and urgency indicators detected.',
            '{"signals":["Typosquatting brand mimic","Credential-themed URL","Urgency language"],"recommended_action":"Quarantine immediately and require password reset review for targeted users."}',
            '{"url_analyst":{"score":98,"verdict":"malicious"},"content_analyst":{"score":86,"verdict":"credential harvesting"},"soc_verdict":{"score":95,"verdict":"quarantine"}}'
        )
    ''')
    email_id_1 = cursor.lastrowid

    cursor.execute('''
        INSERT INTO emails (sender, subject, risk_score, url_threat_score, urls_found, status, threat_type, confidence_score, recommended_action, ai_analysis_log, evidence_json, agent_verdicts_json)
        VALUES ('john.doe@internal.com', 'Project Alpha status report', 5, 0, '[]', 'Allowed', 'Safe', 80, 'Allow and continue passive monitoring.', 'Routine internal project update.', '{"signals":["No URLs","Internal sender pattern"],"recommended_action":"Allow and continue passive monitoring."}', '{"soc_verdict":{"score":5,"verdict":"allow"}}')
    ''')

    cursor.execute('''
        INSERT INTO emails (sender, subject, risk_score, url_threat_score, urls_found, status, threat_type, confidence_score, recommended_action, ai_analysis_log, evidence_json, agent_verdicts_json)
        VALUES ('noreply@dhi-delivery.net', 'Your package is stalled', 82, 80, '["http://dhi-tracking.net"]', 'Quarantined', 'Suspicious Link', 78, 'Quarantine and review delivery-themed lure.', 'Delivery lure with suspicious tracking domain.', '{"signals":["Suspicious delivery theme","External URL"],"recommended_action":"Quarantine and review delivery-themed lure."}', '{"url_analyst":{"score":80,"verdict":"suspicious"},"soc_verdict":{"score":82,"verdict":"quarantine"}}')
    ''')
    email_id_2 = cursor.lastrowid

    cursor.execute('''
        INSERT INTO quarantine (email_id, recipient, ai_reason)
        VALUES (%s, 'finance@corp.com', 'Sender domain typosquatting detected. Urgency triggers found.')
    ''', (email_id_1,))

    cursor.execute('''
        INSERT INTO quarantine (email_id, recipient, ai_reason)
        VALUES (%s, 'marketing@corp.com', 'Suspicious link directing to unknown tracker IP.')
    ''', (email_id_2,))

    cursor.execute('''
        INSERT INTO simulations (target_name, target_department, status)
        VALUES ('Employee User', 'IT', 'Sent')
    ''')

    profiles = [
        ('user1@example.com', 'Finance', 25, 0, 'Invoices, Payroll, Tax Documents'),
        ('user2@example.com', 'Engineering', 10, 0, 'Code Review, Github, Jira'),
        ('user3@example.com', 'Sales', 45, 1, 'Client Meetings, CRM, Leads'),
        ('user4@example.com', 'HR', 20, 0, 'Recruitment, Policy, Training'),
        ('user5@example.com', 'Executive', 70, 2, 'Strategy, Reports, Confidential'),
        ('user6@example.com', 'IT', 15, 0, 'Networking, Support, Backups'),
        ('user7@example.com', 'Marketing', 30, 0, 'Ads, Social Media, Branding'),
        ('user8@example.com', 'Legal', 50, 1, 'Contracts, Compliance, Litigation'),
        ('user9@example.com', 'Security', 5, 0, 'Logs, Alerts, Incidents'),
        ('user10@example.com', 'Operations', 40, 0, 'Logistics, Supply Chain, Scheduling'),
    ]
    for profile in profiles:
        cursor.execute('''
            INSERT INTO user_profiles (email, role, behavioral_risk_score, failed_simulations_count, typical_topics)
            VALUES (%s, %s, %s, %s, %s)
            ON CONFLICT(email) DO NOTHING
        ''', profile)


def _ensure_column(cursor, table: str, column: str, definition: str):
    cursor.execute('''
        SELECT 1
        FROM information_schema.columns
        WHERE table_name = %s AND column_name = %s
    ''', (table, column))
    if not cursor.fetchone():
        cursor.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


init_db()
