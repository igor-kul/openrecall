import base64
import os
import sqlite3
import time
from collections import namedtuple
import numpy as np
from typing import List, Optional
from cryptography.fernet import InvalidToken

from openrecall import vault
from openrecall.config import (
    db_path,
    screenshots_path,
    MAX_STORAGE_BYTES,
    RETENTION_DAYS,
)

SECONDS_PER_DAY = 24 * 60 * 60
BLOCK_SIZE = 4096  # Disks allocate space in blocks of this size


Entry = namedtuple("Entry", ["id", "app", "title", "text", "timestamp", "embedding"])


def _encrypt_str(data: str) -> str:
    # Text columns hold strings, so the encrypted bytes are stored base64-encoded
    encrypted = vault.encrypt(data.encode("utf-8"))
    return base64.urlsafe_b64encode(encrypted).decode("ascii")


def _decrypt_str(data: str) -> str:
    return vault.decrypt(base64.urlsafe_b64decode(data)).decode("utf-8")


def _encrypt_embedding(embedding: np.ndarray) -> bytes:
    return vault.encrypt(embedding.astype(np.float32).tobytes())


def _decrypt_embedding(data: bytes) -> np.ndarray:
    return np.frombuffer(vault.decrypt(data), dtype=np.float32)


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
                try:
                    entry = Entry(
                        id=row["id"],
                        app=_decrypt_str(row["app"]),
                        title=_decrypt_str(row["title"]),
                        text=_decrypt_str(row["text"]),
                        timestamp=row["timestamp"],
                        embedding=_decrypt_embedding(row["embedding"]),
                    )
                except InvalidToken:
                    # Encrypted with keys that no longer exist (auth.json was
                    # deleted, or an old version), so it can never be read again
                    continue
                entries.append(entry)
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
    embedding_bytes = _encrypt_embedding(embedding)
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


def _space_on_disk(path: str) -> int:
    """Returns the space a file really takes on disk, or 0 if it does not exist."""
    try:
        stat = os.stat(path)
    except FileNotFoundError:
        return 0
    if hasattr(stat, "st_blocks"):
        # macOS and Linux report the allocated 512-byte blocks
        return stat.st_blocks * 512
    # Windows has no st_blocks: NTFS gives every file whole clusters of 4 KB
    return -(-stat.st_size // BLOCK_SIZE) * BLOCK_SIZE


def _padding_path() -> str:
    """The filler file that keeps the data folder at a constant size."""
    return os.path.join(os.path.dirname(db_path), "padding.bin")


def _data_size() -> int:
    """Space taken by the recorded data: the database and the screenshots."""
    total = _space_on_disk(db_path)
    if os.path.isdir(screenshots_path):
        for filename in os.listdir(screenshots_path):
            total += _space_on_disk(os.path.join(screenshots_path, filename))
    return total


def _oldest_capture() -> Optional[int]:
    """Timestamp of the oldest capture, in the database or in the screenshots."""
    timestamps = []
    if os.path.isdir(screenshots_path):
        for filename in os.listdir(screenshots_path):
            timestamp = _screenshot_timestamp(filename)
            if timestamp is not None:
                timestamps.append(timestamp)
    try:
        with sqlite3.connect(db_path) as conn:
            oldest_row = conn.execute("SELECT MIN(timestamp) FROM entries").fetchone()[0]
        if oldest_row is not None:
            timestamps.append(oldest_row)
    except sqlite3.Error as e:
        print(f"Database error while looking for the oldest capture: {e}")
    return min(timestamps) if timestamps else None


def _resize_padding(size: int) -> None:
    """Makes the filler file exactly `size` bytes long.

    Growing the file writes real bytes: a file that is only extended without
    writing takes no space on disk (sparse file), so the folder would still
    visibly grow for anyone measuring it with du. The bytes are random rather
    than zeros, because some file systems and backup tools compress zeros to
    almost nothing, which would make the folder shrink again.
    """
    path = _padding_path()
    current_size = os.path.getsize(path) if os.path.exists(path) else 0
    if size < current_size:
        os.truncate(path, size)
    elif size > current_size:
        with open(path, "ab") as f:
            remaining = size - current_size
            while remaining > 0:
                # Written in chunks of 1 MB so gigabytes never sit in memory
                chunk_size = min(remaining, 1024 * 1024)
                f.write(os.urandom(chunk_size))
                remaining -= chunk_size


def enforce_storage_limit() -> None:
    """Keeps the data folder at the same size on disk, whatever the activity.

    The folder always takes MAX_STORAGE_BYTES: a filler file takes the space
    the data does not use yet. When the data reaches the limit, the oldest
    captures are deleted. Someone who measures the folder over time therefore
    cannot tell when or how much the user worked.
    """
    if MAX_STORAGE_BYTES is None:
        # Only the tests switch the limit off, so they never write gigabytes
        return

    data_size = _data_size()
    while data_size > MAX_STORAGE_BYTES:
        oldest = _oldest_capture()
        if oldest is None:
            break
        delete_entries_between(0, oldest)
        data_size = _data_size()

    # Rounded down to whole blocks, so the filler adds exactly what it says
    free_space = max(0, MAX_STORAGE_BYTES - data_size)
    _resize_padding(free_space - free_space % BLOCK_SIZE)
