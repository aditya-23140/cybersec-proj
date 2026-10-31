"""
models.py — Named SQL query helpers (no ORM).
Each function operates on a passed-in sqlite3.Connection.
"""

import json
import sqlite3
from typing import Any


# --------------------------------------------------------------------------- #
# Users
# --------------------------------------------------------------------------- #

def get_user_by_username(conn: sqlite3.Connection, username: str) -> sqlite3.Row | None:
    return conn.execute(
        "SELECT * FROM users WHERE username = ?", (username,)
    ).fetchone()


def get_user_by_id(conn: sqlite3.Connection, user_id: int) -> sqlite3.Row | None:
    return conn.execute(
        "SELECT * FROM users WHERE id = ?", (user_id,)
    ).fetchone()


def get_user_by_email(conn: sqlite3.Connection, email: str) -> sqlite3.Row | None:
    return conn.execute(
        "SELECT * FROM users WHERE email = ?", (email,)
    ).fetchone()


def create_user(
    conn: sqlite3.Connection,
    username: str,
    email: str,
    password_hash: str,
    role: str = "user",
) -> int:
    cursor = conn.execute(
        """
        INSERT INTO users (username, email, password_hash, role)
        VALUES (?, ?, ?, ?)
        """,
        (username, email, password_hash, role),
    )
    return cursor.lastrowid  # type: ignore[return-value]


# --------------------------------------------------------------------------- #
# Scans
# --------------------------------------------------------------------------- #

def insert_scan(conn: sqlite3.Connection, **kwargs: Any) -> int:
    cursor = conn.execute(
        """
        INSERT INTO scans
            (user_id, url, prediction, risk_level, phishing_probability,
             model_version, warnings_json, explanation, source)
        VALUES (:user_id, :url, :prediction, :risk_level,
                :phishing_probability, :model_version,
                :warnings_json, :explanation, :source)
        """,
        kwargs,
    )
    return cursor.lastrowid  # type: ignore[return-value]


def get_scans_for_user(
    conn: sqlite3.Connection, user_id: int, limit: int = 50, offset: int = 0
) -> list[sqlite3.Row]:
    return conn.execute(
        """
        SELECT * FROM scans
        WHERE user_id = ?
        ORDER BY created_at DESC
        LIMIT ? OFFSET ?
        """,
        (user_id, limit, offset),
    ).fetchall()


# --------------------------------------------------------------------------- #
# Allowlist
# --------------------------------------------------------------------------- #

def get_allowlist(conn: sqlite3.Connection, user_id: int) -> list[sqlite3.Row]:
    return conn.execute(
        "SELECT * FROM allowlist WHERE user_id = ? ORDER BY created_at DESC",
        (user_id,),
    ).fetchall()


def get_allowlist_entry(
    conn: sqlite3.Connection, entry_id: int, user_id: int
) -> sqlite3.Row | None:
    return conn.execute(
        "SELECT * FROM allowlist WHERE id = ? AND user_id = ?",
        (entry_id, user_id),
    ).fetchone()


def insert_allowlist(
    conn: sqlite3.Connection, user_id: int, domain: str, notes: str | None
) -> int:
    cursor = conn.execute(
        "INSERT INTO allowlist (user_id, domain, notes) VALUES (?, ?, ?)",
        (user_id, domain, notes),
    )
    return cursor.lastrowid  # type: ignore[return-value]


def delete_allowlist_entry(
    conn: sqlite3.Connection, entry_id: int, user_id: int
) -> int:
    cursor = conn.execute(
        "DELETE FROM allowlist WHERE id = ? AND user_id = ?",
        (entry_id, user_id),
    )
    return cursor.rowcount


def get_all_allowlist_domains(
    conn: sqlite3.Connection, user_id: int
) -> list[str]:
    rows = conn.execute(
        "SELECT domain FROM allowlist WHERE user_id = ?", (user_id,)
    ).fetchall()
    return [row["domain"] for row in rows]


# --------------------------------------------------------------------------- #
# Blocklist
# --------------------------------------------------------------------------- #

def get_blocklist(conn: sqlite3.Connection, user_id: int) -> list[sqlite3.Row]:
    return conn.execute(
        "SELECT * FROM blocklist WHERE user_id = ? ORDER BY created_at DESC",
        (user_id,),
    ).fetchall()


def get_blocklist_entry(
    conn: sqlite3.Connection, entry_id: int, user_id: int
) -> sqlite3.Row | None:
    return conn.execute(
        "SELECT * FROM blocklist WHERE id = ? AND user_id = ?",
        (entry_id, user_id),
    ).fetchone()


def insert_blocklist(
    conn: sqlite3.Connection, user_id: int, domain: str, notes: str | None
) -> int:
    cursor = conn.execute(
        "INSERT INTO blocklist (user_id, domain, notes) VALUES (?, ?, ?)",
        (user_id, domain, notes),
    )
    return cursor.lastrowid  # type: ignore[return-value]


def delete_blocklist_entry(
    conn: sqlite3.Connection, entry_id: int, user_id: int
) -> int:
    cursor = conn.execute(
        "DELETE FROM blocklist WHERE id = ? AND user_id = ?",
        (entry_id, user_id),
    )
    return cursor.rowcount


def get_all_blocklist_domains(
    conn: sqlite3.Connection, user_id: int
) -> list[str]:
    rows = conn.execute(
        "SELECT domain FROM blocklist WHERE user_id = ?", (user_id,)
    ).fetchall()
    return [row["domain"] for row in rows]


# --------------------------------------------------------------------------- #
# Forum
# --------------------------------------------------------------------------- #

def get_forum_posts(
    conn: sqlite3.Connection, limit: int = 50, offset: int = 0
) -> list[sqlite3.Row]:
    return conn.execute(
        """
        SELECT fp.*, u.username
        FROM forum_posts fp
        JOIN users u ON fp.user_id = u.id
        ORDER BY fp.created_at DESC
        LIMIT ? OFFSET ?
        """,
        (limit, offset),
    ).fetchall()


def get_forum_post(
    conn: sqlite3.Connection, post_id: int
) -> sqlite3.Row | None:
    return conn.execute(
        """
        SELECT fp.*, u.username
        FROM forum_posts fp
        JOIN users u ON fp.user_id = u.id
        WHERE fp.id = ?
        """,
        (post_id,),
    ).fetchone()


def insert_forum_post(
    conn: sqlite3.Connection, user_id: int, title: str, body: str
) -> int:
    cursor = conn.execute(
        "INSERT INTO forum_posts (user_id, title, body) VALUES (?, ?, ?)",
        (user_id, title, body),
    )
    return cursor.lastrowid  # type: ignore[return-value]


def get_forum_replies(
    conn: sqlite3.Connection, post_id: int
) -> list[sqlite3.Row]:
    return conn.execute(
        """
        SELECT fr.*, u.username
        FROM forum_replies fr
        JOIN users u ON fr.user_id = u.id
        WHERE fr.post_id = ?
        ORDER BY fr.created_at ASC
        """,
        (post_id,),
    ).fetchall()


def insert_forum_reply(
    conn: sqlite3.Connection, post_id: int, user_id: int, body: str
) -> int:
    cursor = conn.execute(
        "INSERT INTO forum_replies (post_id, user_id, body) VALUES (?, ?, ?)",
        (post_id, user_id, body),
    )
    return cursor.lastrowid  # type: ignore[return-value]


# --------------------------------------------------------------------------- #
# Stats
# --------------------------------------------------------------------------- #

def get_stats(conn: sqlite3.Connection) -> dict:
    row = conn.execute(
        """
        SELECT
            COUNT(*)                                          AS total_scans,
            SUM(CASE WHEN prediction = 'benign'   THEN 1 ELSE 0 END) AS benign_count,
            SUM(CASE WHEN prediction = 'phishing' THEN 1 ELSE 0 END) AS phishing_count,
            SUM(CASE WHEN risk_level = 'dangerous'   THEN 1 ELSE 0 END) AS dangerous_count,
            SUM(CASE WHEN risk_level = 'suspicious'  THEN 1 ELSE 0 END) AS suspicious_count,
            SUM(CASE WHEN risk_level = 'safe'        THEN 1 ELSE 0 END) AS safe_count,
            SUM(CASE WHEN created_at >= datetime('now','-1 day') THEN 1 ELSE 0 END)
                                                              AS recent_scans_24h,
            MAX(created_at)                                   AS last_scan_at
        FROM scans
        """
    ).fetchone()
    return dict(row)
