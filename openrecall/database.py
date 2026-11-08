import os
import sqlite3
import time
from collections import namedtuple
import numpy as np
from typing import List, Optional
from cryptography.fernet import Fernet

from openrecall.config import db_path, screenshots_path, ENCRYPTION_KEY, RETENTION_DAYS

SECONDS_PER_DAY = 24 * 60 * 60

cipher_suite = Fernet(ENCRYPTION_KEY)

Entry = namedtuple("Entry", ["id", "app", "title", "text", "timestamp", "embedding"])


def _encrypt_str(data: str) -> str:
    return cipher_suite.encrypt(data.encode("utf-8")).decode("utf-8")


def _decrypt_str(data: str) -> str:
    return cipher_suite.decrypt(data.encode("utf-8")).decode("utf-8")


def create_db() -> None:
    try:
        with sqlite3.connect(db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""CREATE TABLE IF NOT EXISTS entries (
                       id INTEGER PRIMARY KEY AUTOINCREMENT,
                       app TEXT,
                       title TEXT,
                       text TEXT,
                       timestamp INTEGER UNIQUE,
                       embedding BLOB
                   )""")
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_timestamp ON entries (timestamp)"
            )
            conn.commit()
    except sqlite3.Error as e:
        print(f"Database error during table creation: {e}")


def get_all_entries() -> List[Entry]:
    entries: List[Entry] = []
    try:
        with sqlite3.connect(db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(
                "SELECT id, app, title, text, timestamp, embedding FROM entries ORDER BY timestamp DESC"
            )
            results = cursor.fetchall()
            for row in results:
                embedding = np.frombuffer(row["embedding"], dtype=np.float32)
                entries.append(
                    Entry(
                        id=row["id"],
                        app=_decrypt_str(row["app"]),
                        title=_decrypt_str(row["title"]),
                        text=_decrypt_str(row["text"]),
                        timestamp=row["timestamp"],
                        embedding=embedding,
                    )
                )
    except sqlite3.Error as e:
        print(f"Database error while fetching all entries: {e}")
    return entries


def get_timestamps() -> List[int]:
    timestamps: List[int] = []
    try:
        with sqlite3.connect(db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT timestamp FROM entries ORDER BY timestamp DESC")
            results = cursor.fetchall()
            timestamps = [result[0] for result in results]
    except sqlite3.Error as e:
        print(f"Database error while fetching timestamps: {e}")
    return timestamps


def insert_entry(
    text: str, timestamp: int, embedding: np.ndarray, app: str, title: str
) -> Optional[int]:
    embedding_bytes: bytes = embedding.astype(np.float32).tobytes()
    last_row_id: Optional[int] = None
    try:
        with sqlite3.connect(db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """INSERT INTO entries (text, timestamp, embedding, app, title)
                   VALUES (?, ?, ?, ?, ?)
                   ON CONFLICT(timestamp) DO NOTHING""",
                (
                    _encrypt_str(text),
                    timestamp,
                    embedding_bytes,
                    _encrypt_str(app),
                    _encrypt_str(title),
                ),
            )
            conn.commit()
            if cursor.rowcount > 0:
                last_row_id = cursor.lastrowid
    except sqlite3.Error as e:
        print(f"Database error during insertion: {e}")
    return last_row_id


def _screenshot_timestamp(filename: str) -> Optional[int]:
    """Extracts the capture timestamp from a screenshot file name.

    Args:
        filename: A file name from the screenshots folder, e.g. "1793289255.webp".

    Returns:
        Optional[int]: The Unix timestamp, or None if the file is not a screenshot.
    """
    stem, extension = os.path.splitext(filename)
    if extension != ".webp":
        return None
    try:
        return int(stem)
    except ValueError:
        return None


def delete_entries_between(start_ts: int, end_ts: int) -> int:
    """Permanently deletes the captures taken between two timestamps, inclusive.

    Removes the database rows (OCR text, metadata and embedding) and the
    screenshot files of that period.

    Args:
        start_ts: Unix timestamp of the first capture to delete.
        end_ts: Unix timestamp of the last capture to delete.

    Returns:
        int: The number of database rows deleted.
    """
    deleted_rows = 0
    try:
        with sqlite3.connect(db_path) as conn:
            # secure delete (pragma statement) wipes deleted data from disk
            # default behaviour only marks them as free space
            conn.execute("PRAGMA secure_delete = ON")
            cursor = conn.execute(
                "DELETE FROM entries WHERE timestamp BETWEEN ? AND ?",
                (start_ts, end_ts),
            )
            conn.commit()
            deleted_rows = cursor.rowcount
    except sqlite3.Error as e:
        print(f"Database error during deletion: {e}")

    # Files are matched by name rather than by row: a screenshot in which OCR
    # found no text is saved but never gets a row
    if os.path.isdir(screenshots_path):
        for filename in os.listdir(screenshots_path):
            timestamp = _screenshot_timestamp(filename)
            if timestamp is not None and start_ts <= timestamp <= end_ts:
                try:
                    os.remove(os.path.join(screenshots_path, filename))
                except FileNotFoundError:
                    pass
    return deleted_rows


def purge_old_entries(max_age_days: int = RETENTION_DAYS) -> int:
    """Deletes every capture older than the retention period.

    Args:
        max_age_days: Number of days a capture is kept.

    Returns:
        int: The number of database rows deleted.
    """
    cutoff = int(time.time()) - max_age_days * SECONDS_PER_DAY
    return delete_entries_between(0, cutoff - 1)
