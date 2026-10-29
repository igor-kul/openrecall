import os
import sqlite3
import tempfile
import time
from unittest.mock import patch

import numpy as np
import pytest


def test_database_is_protected_from_external_process_access():
    with tempfile.NamedTemporaryFile(delete=False) as tmp_db:
        db_path = tmp_db.name

    try:
        with patch("sys.argv", ["openrecall"]):
            with patch("openrecall.config.db_path", db_path):
                import openrecall.database as db

                db.db_path = db_path
                db.create_db()

                current_time = int(time.time())
                dummy_embedding = np.zeros(384, dtype=np.float32)

                # 1. Insert entry into database
                db.insert_entry(
                    text="CONFIDENTIAL USER ACTIVITY",
                    timestamp=current_time,
                    embedding=dummy_embedding,
                    app="Confidential App",
                    title="Private Document",
                )

                # 2. Attempt to open and read the database as an unauthorized external process
                try:
                    external_conn = sqlite3.connect(db_path)
                    cursor = external_conn.cursor()
                    cursor.execute("SELECT text FROM entries")
                    records = cursor.fetchall()
                    external_conn.close()

                    # 3. Assert that no plain-text records could be retrieved
                    has_unencrypted_data = any(
                        "CONFIDENTIAL USER ACTIVITY" in row[0] for row in records
                    )
                    assert not has_unencrypted_data, (
                        f"Database Security Check Failed: External process successfully read plain-text database content! "
                        f"Retrieved: {records}"
                    )
                except (sqlite3.DatabaseError, PermissionError):
                    # Test passes if access is denied or database is encrypted
                    pass
    finally:
        if os.path.exists(db_path):
            try:
                os.remove(db_path)
            except PermissionError:
                pass