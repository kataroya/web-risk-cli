"""Local hash prefix DB (SQLite) management module.

Table structure:
  - hash_prefixes: stores hash prefixes per threat_type
  - metadata: manages version_token and next_diff time per threat_type
"""

import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Optional

DB_PATH = Path(__file__).parent / "webrisk_local.db"


def get_connection(db_path: Path = DB_PATH) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path))
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db(db_path: Path = DB_PATH) -> None:
    """Initialize database tables."""
    conn = get_connection(db_path)
    try:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS hash_prefixes (
                threat_type   INTEGER NOT NULL,
                hash_prefix   BLOB    NOT NULL,
                PRIMARY KEY (threat_type, hash_prefix)
            );

            CREATE TABLE IF NOT EXISTS metadata (
                threat_type       INTEGER PRIMARY KEY,
                version_token     BLOB,
                next_diff_time    TEXT
            );
            """
        )
        conn.commit()
    finally:
        conn.close()


# ── version_token / next_diff management ────────────────────────────


def get_version_token(threat_type: int, db_path: Path = DB_PATH) -> bytes:
    """Return the stored version_token. Returns b'' if not found (first call)."""
    conn = get_connection(db_path)
    try:
        row = conn.execute(
            "SELECT version_token FROM metadata WHERE threat_type = ?",
            (threat_type,),
        ).fetchone()
        return row[0] if row and row[0] else b""
    finally:
        conn.close()


def save_metadata(
    threat_type: int,
    version_token: bytes,
    next_diff_time: Optional[datetime] = None,
    db_path: Path = DB_PATH,
) -> None:
    conn = get_connection(db_path)
    try:
        next_diff_str = next_diff_time.isoformat() if next_diff_time else None
        conn.execute(
            """
            INSERT INTO metadata (threat_type, version_token, next_diff_time)
            VALUES (?, ?, ?)
            ON CONFLICT(threat_type) DO UPDATE SET
                version_token  = excluded.version_token,
                next_diff_time = excluded.next_diff_time
            """,
            (threat_type, version_token, next_diff_str),
        )
        conn.commit()
    finally:
        conn.close()


def get_next_diff_time(
    threat_type: int, db_path: Path = DB_PATH
) -> Optional[datetime]:
    conn = get_connection(db_path)
    try:
        row = conn.execute(
            "SELECT next_diff_time FROM metadata WHERE threat_type = ?",
            (threat_type,),
        ).fetchone()
        if row and row[0]:
            return datetime.fromisoformat(row[0])
        return None
    finally:
        conn.close()


# ── hash prefix CRUD ────────────────────────────────────────────────


def reset_prefixes(
    threat_type: int, prefixes: list[bytes], db_path: Path = DB_PATH
) -> None:
    """Handle RESET response: delete all existing prefixes and insert new ones."""
    conn = get_connection(db_path)
    try:
        conn.execute(
            "DELETE FROM hash_prefixes WHERE threat_type = ?", (threat_type,)
        )
        conn.executemany(
            "INSERT OR IGNORE INTO hash_prefixes (threat_type, hash_prefix) VALUES (?, ?)",
            [(threat_type, p) for p in prefixes],
        )
        conn.commit()
    finally:
        conn.close()


def apply_diff(
    threat_type: int,
    additions: list[bytes],
    removals: list[int],
    db_path: Path = DB_PATH,
) -> None:
    """Handle DIFF response: remove prefixes at given indices, then add new ones.

    removals are indices into the current DB sorted by prefix in ascending order.
    """
    conn = get_connection(db_path)
    try:
        if removals:
            # Fetch prefixes sorted ascending, then delete those at removal indices
            rows = conn.execute(
                "SELECT hash_prefix FROM hash_prefixes WHERE threat_type = ? ORDER BY hash_prefix",
                (threat_type,),
            ).fetchall()
            to_remove = {rows[i][0] for i in removals if i < len(rows)}
            if to_remove:
                conn.executemany(
                    "DELETE FROM hash_prefixes WHERE threat_type = ? AND hash_prefix = ?",
                    [(threat_type, p) for p in to_remove],
                )

        if additions:
            conn.executemany(
                "INSERT OR IGNORE INTO hash_prefixes (threat_type, hash_prefix) VALUES (?, ?)",
                [(threat_type, p) for p in additions],
            )
        conn.commit()
    finally:
        conn.close()


def lookup_prefix(
    hash_prefix: bytes, db_path: Path = DB_PATH
) -> list[int]:
    """Return which threat_types match the given hash prefix.

    The local DB stores 4-32 byte prefixes, so this compares the leading
    bytes of the full hash (32 bytes) against each stored prefix.
    """
    conn = get_connection(db_path)
    try:
        rows = conn.execute(
            "SELECT DISTINCT threat_type, hash_prefix FROM hash_prefixes"
        ).fetchall()
        matched = set()
        for threat_type, stored_prefix in rows:
            prefix_len = len(stored_prefix)
            if hash_prefix[:prefix_len] == stored_prefix:
                matched.add(threat_type)
        return list(matched)
    finally:
        conn.close()


def get_prefix_count(threat_type: int, db_path: Path = DB_PATH) -> int:
    conn = get_connection(db_path)
    try:
        row = conn.execute(
            "SELECT COUNT(*) FROM hash_prefixes WHERE threat_type = ?",
            (threat_type,),
        ).fetchone()
        return row[0]
    finally:
        conn.close()
