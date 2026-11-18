"""SQLite schema and connection helpers."""
import sqlite3

from flask import current_app, g

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    username         TEXT UNIQUE NOT NULL,
    password_hash    TEXT NOT NULL,
    role             TEXT NOT NULL CHECK (role IN ('user','admin','auditor')),
    status           TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','disabled')),
    failed_attempts  INTEGER NOT NULL DEFAULT 0,
    locked_until     TEXT,
    created_at       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    id_hash     TEXT PRIMARY KEY,           -- SHA-256 of the session id in the cookie
    user_id     INTEGER NOT NULL REFERENCES users(id),
    created_at  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    ip          TEXT,
    revoked     INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS files (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id     INTEGER NOT NULL REFERENCES users(id),
    orig_name    TEXT NOT NULL,
    stored_name  TEXT UNIQUE NOT NULL,      -- random name on disk
    size         INTEGER NOT NULL,
    sha256       TEXT NOT NULL,             -- hash of the plaintext, checked on download
    wrapped_key  BLOB NOT NULL,             -- per-file key encrypted with the master key
    uploaded_at  TEXT NOT NULL,
    deleted      INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS shares (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    file_id        INTEGER NOT NULL REFERENCES files(id),
    token_hash     TEXT UNIQUE NOT NULL,
    created_by     INTEGER NOT NULL REFERENCES users(id),
    created_at     TEXT NOT NULL,
    expires_at     TEXT NOT NULL,
    max_downloads  INTEGER NOT NULL,
    downloads      INTEGER NOT NULL DEFAULT 0,
    revoked        INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS audit_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ts         TEXT NOT NULL,
    actor      TEXT NOT NULL,
    action     TEXT NOT NULL,
    target     TEXT NOT NULL,
    outcome    TEXT NOT NULL,
    ip         TEXT NOT NULL,
    detail     TEXT NOT NULL,
    prev_hash  TEXT NOT NULL,
    hash       TEXT NOT NULL
);

-- The application never edits audit records. These triggers make the
-- database itself refuse UPDATE and DELETE on the audit table.
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;

CREATE TABLE IF NOT EXISTS alerts (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts        TEXT NOT NULL,
    severity  TEXT NOT NULL CHECK (severity IN ('low','medium','high')),
    kind      TEXT NOT NULL,
    detail    TEXT NOT NULL,
    resolved  INTEGER NOT NULL DEFAULT 0,
    resolved_by TEXT
);
"""


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = sqlite3.connect(current_app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


def close_db(_exc=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db(path: str):
    con = sqlite3.connect(path)
    con.executescript(SCHEMA)
    con.commit()
    con.close()
