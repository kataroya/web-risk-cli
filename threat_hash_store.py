"""Local hash prefix DB (SQLite) management module.

Table structure:
  - hash_prefixes: stores hash prefixes per threat_type
  - metadata: manages version_token and next_diff time per threat_type
  - url_check_cache: caches URL check results until expire_time
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

            CREATE TABLE IF NOT EXISTS url_check_cache (
                url_sha256    BLOB    PRIMARY KEY,
                url           TEXT    NOT NULL,
                is_safe       INTEGER NOT NULL,
                threats_json  TEXT,
                expire_time   TEXT    NOT NULL,
                checked_at    TEXT    NOT NULL
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


# ── URL check cache ─────────────────────────────────────────────────

import hashlib
import json
from datetime import timezone as _tz


def get_cached_result(url: str, db_path: Path = DB_PATH) -> Optional[dict]:
    """Return cached check result if it exists and has not expired. Otherwise None."""
    url_hash = hashlib.sha256(url.encode("utf-8")).digest()
    conn = get_connection(db_path)
    try:
        row = conn.execute(
            "SELECT url, is_safe, threats_json, expire_time FROM url_check_cache "
            "WHERE url_sha256 = ?",
            (url_hash,),
        ).fetchone()
        if not row:
            return None
        expire_time = datetime.fromisoformat(row[3])
        if expire_time.tzinfo is None:
            expire_time = expire_time.replace(tzinfo=_tz.utc)
        if datetime.now(_tz.utc) >= expire_time:
            # Cache expired — delete and return None
            conn.execute(
                "DELETE FROM url_check_cache WHERE url_sha256 = ?", (url_hash,)
            )
            conn.commit()
            return None
        return {
            "url": row[0],
            "safe": bool(row[1]),
            "threats": json.loads(row[2]) if row[2] else [],
            "cached": True,
            "expire_time": row[3],
        }
    finally:
        conn.close()


def save_cached_result(
    url: str,
    is_safe: bool,
    threats: list[dict],
    expire_time: datetime,
    db_path: Path = DB_PATH,
) -> None:
    """Cache a URL check result until expire_time."""
    url_hash = hashlib.sha256(url.encode("utf-8")).digest()
    conn = get_connection(db_path)
    try:
        conn.execute(
            """
            INSERT INTO url_check_cache
                (url_sha256, url, is_safe, threats_json, expire_time, checked_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(url_sha256) DO UPDATE SET
                is_safe      = excluded.is_safe,
                threats_json = excluded.threats_json,
                expire_time  = excluded.expire_time,
                checked_at   = excluded.checked_at
            """,
            (
                url_hash,
                url,
                int(is_safe),
                json.dumps(threats) if threats else None,
                expire_time.isoformat(),
                datetime.now(_tz.utc).isoformat(),
            ),
        )
        conn.commit()
    finally:
        conn.close()


def clear_cache(db_path: Path = DB_PATH) -> int:
    """Delete all cached results. Returns the number of deleted rows."""
    conn = get_connection(db_path)
    try:
        cursor = conn.execute("DELETE FROM url_check_cache")
        conn.commit()
        return cursor.rowcount
    finally:
        conn.close()


def purge_expired_cache(db_path: Path = DB_PATH) -> int:
    """Delete only expired cache entries. Returns the number of deleted rows."""
    conn = get_connection(db_path)
    try:
        now = datetime.now(_tz.utc).isoformat()
        cursor = conn.execute(
            "DELETE FROM url_check_cache WHERE expire_time <= ?", (now,)
        )
        conn.commit()
        return cursor.rowcount
    finally:
        conn.close()


def get_cache_count(db_path: Path = DB_PATH) -> int:
    conn = get_connection(db_path)
    try:
        row = conn.execute("SELECT COUNT(*) FROM url_check_cache").fetchone()
        return row[0]
    finally:
        conn.close()
