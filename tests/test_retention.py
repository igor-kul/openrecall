import os
import tempfile
import time
from unittest.mock import patch

import numpy as np
import pytest


def test_data_retention_older_than_one_year_is_purged():
    with tempfile.NamedTemporaryFile(delete=False) as tmp_db:
        db_path = tmp_db.name

    try:
        with patch("sys.argv", ["openrecall"]):
            with patch("openrecall.config.db_path", db_path):
                import openrecall.database as db

                db.db_path = db_path
                db.create_db()

                current_time = int(time.time())
                one_year_seconds = 365 * 24 * 60 * 60

                # 1. Timestamps for testing
                old_timestamp = current_time - (one_year_seconds + 86400)  # 1 year + 1 day old
                recent_timestamp = current_time - (30 * 24 * 60 * 60)       # 30 days old

                dummy_embedding = np.zeros(384, dtype=np.float32)

                # 2. Insert test entries
                db.insert_entry(
                    text="OLD EXPIRED RECORD",
                    timestamp=old_timestamp,
                    embedding=dummy_embedding,
                    app="TestApp",
                    title="Old Window",
                )
                db.insert_entry(
                    text="RECENT VALID RECORD",
                    timestamp=recent_timestamp,
                    embedding=dummy_embedding,
                    app="TestApp",
                    title="Recent Window",
                )

                # 3. Retrieve entries from the database
                entries = db.get_all_entries()
                assert len(entries) > 0, "No entries found in database."

                # 4. Assert no entries older than 1 year exist
                for entry in entries:
                    age_in_seconds = current_time - entry.timestamp
                    assert age_in_seconds <= one_year_seconds, (
                        f"Database retained entry older than 1 year! "
                        f"Timestamp: {entry.timestamp} (Age: {age_in_seconds // 86400} days), "
                        f"Text: '{entry.text}'"
                    )
    finally:
        if os.path.exists(db_path):
            try:
                os.remove(db_path)
            except PermissionError:
                pass