-- 0011_mail_connectors
-- State for the Microsoft 365 / Google Workspace mail connectors: a per-mailbox
-- cursor (last processed receivedDateTime) and a dedup set of seen message ids, so
-- polling never re-analyses the same message. Works alongside the IMAP watcher.
CREATE TABLE IF NOT EXISTS mail_cursor (
    source TEXT NOT NULL,            -- 'm365' | 'gmail'
    mailbox TEXT NOT NULL,
    organization_id INTEGER NOT NULL DEFAULT 1,
    last_received TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (source, mailbox)
);
CREATE TABLE IF NOT EXISTS mail_seen (
    message_id TEXT PRIMARY KEY,
    source TEXT,
    seen_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_mail_seen_time ON mail_seen (seen_at);
