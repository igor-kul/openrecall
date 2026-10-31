import sqlite3
from collections import namedtuple
import numpy as np
from typing import List, Optional
from cryptography.fernet import Fernet

from openrecall.config import db_path, ENCRYPTION_KEY

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
            cursor.execute(
                """CREATE TABLE IF NOT EXISTS entries (
                       id INTEGER PRIMARY KEY AUTOINCREMENT,
                       app TEXT,
                       title TEXT,
                       text TEXT,
                       timestamp INTEGER UNIQUE,
                       embedding BLOB
                   )"""
            )
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON entries (timestamp)")
            conn.commit()
    except sqlite3.Error as e:
        print(f"Database error during table creation: {e}")

def get_all_entries() -> List[Entry]:
    entries: List[Entry] = []
    try:
        with sqlite3.connect(db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT id, app, title, text, timestamp, embedding FROM entries ORDER BY timestamp DESC")
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

def insert_entry(text: str, timestamp: int, embedding: np.ndarray, app: str, title: str) -> Optional[int]:
    embedding_bytes: bytes = embedding.astype(np.float32).tobytes()
    last_row_id: Optional[int] = None
    try:
        with sqlite3.connect(db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """INSERT INTO entries (text, timestamp, embedding, app, title)
                   VALUES (?, ?, ?, ?, ?)
                   ON CONFLICT(timestamp) DO NOTHING""",
                (_encrypt_str(text), timestamp, embedding_bytes, _encrypt_str(app), _encrypt_str(title)),
            )
            conn.commit()
            if cursor.rowcount > 0:
                last_row_id = cursor.lastrowid
    except sqlite3.Error as e:
        print(f"Database error during insertion: {e}")
    return last_row_id