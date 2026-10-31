"""
database.py — SQLite connection, schema creation, and admin seeding.
Uses raw sqlite3 (no ORM).
"""

import logging
import secrets
import sqlite3
from contextlib import contextmanager
from typing import Generator

from config import DATABASE_PATH
from services.auth_service import hash_password

logger = logging.getLogger(__name__)

_MEMORY_DATABASE_URI = "file:phishguard-memory?mode=memory&cache=shared"
_memory_keeper: sqlite3.Connection | None = None

# --------------------------------------------------------------------------- #
# Connection helper
# --------------------------------------------------------------------------- #

def get_connection() -> sqlite3.Connection:
    """Return a sqlite3 connection with Row factory enabled."""
    global _memory_keeper
    if DATABASE_PATH == ":memory:":
        if _memory_keeper is None:
            _memory_keeper = sqlite3.connect(
                _MEMORY_DATABASE_URI,
                uri=True,
                check_same_thread=False,
            )
        conn = sqlite3.connect(
            _MEMORY_DATABASE_URI,
            uri=True,
            check_same_thread=False,
        )
    else:
        conn = sqlite3.connect(DATABASE_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


@contextmanager
def get_db() -> Generator[sqlite3.Connection, None, None]:
    """Context-manager that yields a connection and commits/rolls-back."""
    conn = get_connection()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# --------------------------------------------------------------------------- #
# Schema
# --------------------------------------------------------------------------- #

_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    NOT NULL UNIQUE,
    email         TEXT    NOT NULL UNIQUE,
    password_hash TEXT    NOT NULL,
    role          TEXT    NOT NULL DEFAULT 'user',
    created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS scans (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id             INTEGER REFERENCES users(id),
    url                 TEXT    NOT NULL,
    prediction          TEXT    NOT NULL,
    risk_level          TEXT    NOT NULL,
    phishing_probability REAL   NOT NULL,
    model_version       TEXT    NOT NULL,
    warnings_json       TEXT    DEFAULT '[]',
    explanation         TEXT,
    source              TEXT    DEFAULT 'model',
    created_at          TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS allowlist (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL REFERENCES users(id),
    domain     TEXT    NOT NULL,
    notes      TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, domain)
);

CREATE TABLE IF NOT EXISTS blocklist (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL REFERENCES users(id),
    domain     TEXT    NOT NULL,
    notes      TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, domain)
);

CREATE TABLE IF NOT EXISTS forum_posts (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL REFERENCES users(id),
    title      TEXT    NOT NULL,
    body       TEXT    NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS forum_replies (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    post_id    INTEGER NOT NULL REFERENCES forum_posts(id),
    user_id    INTEGER NOT NULL REFERENCES users(id),
    body       TEXT    NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_scans_user_id     ON scans(user_id);
CREATE INDEX IF NOT EXISTS idx_scans_created_at  ON scans(created_at);
CREATE INDEX IF NOT EXISTS idx_forum_replies_post ON forum_replies(post_id);
"""


def init_db() -> None:
    """Create tables and seed the admin user on first run."""
    with get_db() as conn:
        conn.executescript(_SCHEMA)
        logger.info("Database schema initialised.")
        _seed_admin(conn)


def _seed_admin(conn: sqlite3.Connection) -> None:
    """Create the admin account if it doesn't exist; print password once."""
    existing = conn.execute(
        "SELECT id FROM users WHERE username = 'admin'"
    ).fetchone()
    if existing:
        return

    password = secrets.token_urlsafe(16)
    hashed = hash_password(password)
    conn.execute(
        """
        INSERT INTO users (username, email, password_hash, role)
        VALUES ('admin', 'admin@localhost', ?, 'admin')
        """,
        (hashed,),
    )
    # Print ONCE to console — not logged to file
    print(
        "\n"
        "╔══════════════════════════════════════════════════════╗\n"
        "║          ADMIN ACCOUNT CREATED (first run)           ║\n"
        f"║  username : admin                                    ║\n"
        f"║  password : {password:<40}║\n"
        "║  Change this immediately in production!              ║\n"
        "╚══════════════════════════════════════════════════════╝\n"
    )
