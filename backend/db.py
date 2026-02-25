import sqlite3
import os
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), "phishing_monitor.db")

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    c = conn.cursor()
    
    # Create the emails table (all monitored emails)
    c.execute('''
        CREATE TABLE IF NOT EXISTS emails (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            sender TEXT NOT NULL,
            subject TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            url_threat_score INTEGER NOT NULL,
            urls_found TEXT,
            status TEXT NOT NULL
        )
    ''')
    
    # Create the quarantine table (specifically quarantined emails)
    c.execute('''
        CREATE TABLE IF NOT EXISTS quarantine (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email_id INTEGER,
            recipient TEXT NOT NULL,
            ai_reason TEXT NOT NULL,
            quarantined_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (email_id) REFERENCES emails(id)
        )
    ''')
    
    # Create the simulations table (gophish campaigns)
    c.execute('''
        CREATE TABLE IF NOT EXISTS simulations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_name TEXT,
            target_department TEXT,
            run_time DATETIME DEFAULT CURRENT_TIMESTAMP,
            status TEXT
        )
    ''')

    # Create user_profiles for Context and Behavioral Risk Tracking
    c.execute('''
        CREATE TABLE IF NOT EXISTS user_profiles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            role TEXT NOT NULL,
            behavioral_risk_score INTEGER DEFAULT 0,
            failed_simulations_count INTEGER DEFAULT 0,
            typical_topics TEXT
        )
    ''')

    # Create settings table
    c.execute('''
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT
        )
    ''')

    # Insert some initial dummy data if table is empty just to have something to display
    c.execute('SELECT COUNT(*) FROM emails')
    if c.fetchone()[0] == 0:
        _insert_initial_dummy_data(c)
        
    # Ensure default settings exist regardless of dummy data
    c.execute('SELECT COUNT(*) FROM settings')
    if c.fetchone()[0] == 0:
        c.execute("INSERT INTO settings (key, value) VALUES ('ai_model', 'phi3')")
        c.execute("INSERT INTO settings (key, value) VALUES ('ai_aggressiveness', 'Medium')")
        c.execute("INSERT INTO settings (key, value) VALUES ('imap_server', 'mail_server')")
        c.execute("INSERT INTO settings (key, value) VALUES ('imap_user', 'default@example.com')")
        c.execute("INSERT INTO settings (key, value) VALUES ('imap_pass', 'mail_server')")
        
        
    conn.commit()
    conn.close()

def _insert_initial_dummy_data(cursor):
    # Dummy Emails
    cursor.execute('''
        INSERT INTO emails (sender, subject, risk_score, url_threat_score, urls_found, status)
        VALUES ('hr-update@miicrosoft.com', 'URGENT: Mandatory Compliance Review', 95, 98, '["http://miicrosoft.com/login"]', 'Quarantined')
    ''')
    email_id_1 = cursor.lastrowid
    
    cursor.execute('''
        INSERT INTO emails (sender, subject, risk_score, url_threat_score, urls_found, status)
        VALUES ('john.doe@internal.com', 'Project Alpha status report', 5, 0, '[]', 'Allowed')
    ''')
    
    cursor.execute('''
        INSERT INTO emails (sender, subject, risk_score, url_threat_score, urls_found, status)
        VALUES ('noreply@dhi-delivery.net', 'Your package is stalled', 82, 80, '["http://dhi-tracking.net"]', 'Quarantined')
    ''')
    email_id_2 = cursor.lastrowid
    
    # Dummy Quarantines
    cursor.execute('''
        INSERT INTO quarantine (email_id, recipient, ai_reason)
        VALUES (?, 'finance@corp.com', 'Sender domain typosquatting detected. Urgency triggers found.')
    ''', (email_id_1,))
    
    cursor.execute('''
        INSERT INTO quarantine (email_id, recipient, ai_reason)
        VALUES (?, 'marketing@corp.com', 'Suspicious link directing to unknown tracker IP.')
    ''', (email_id_2,))
    
    # Dummy Simulations
    cursor.execute('''
        INSERT INTO simulations (target_name, target_department, status)
        VALUES ('Employee User', 'IT', 'Sent')
    ''')

    # Dummy User Profiles for Behavioral/Context Profiling
    cursor.execute('''
        INSERT INTO user_profiles (email, role, behavioral_risk_score, failed_simulations_count, typical_topics)
        VALUES ('finance@corp.com', 'Finance', 85, 2, 'Invoices, Payroll, Tax Documents, Budget')
    ''')
    cursor.execute('''
        INSERT INTO user_profiles (email, role, behavioral_risk_score, failed_simulations_count, typical_topics)
        VALUES ('dev@corp.com', 'Developer', 15, 0, 'Code Review, Github, Jira, Deployments')
    ''')
    
    # Default Settings moved to init_db
# Initialize the db when the module is imported
init_db()
