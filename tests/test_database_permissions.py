import os
import gc
import sqlite3
import tempfile
import time
from unittest.mock import patch
import numpy as np
import pytest

def test_database_text_is_encrypted_on_disk():
    tmp_file = tempfile.NamedTemporaryFile(delete=False)
    db_path = tmp_file.name
    tmp_file.close()

    try:
        with patch("openrecall.config.db_path", db_path):
            import openrecall.database as db
            db.db_path = db_path
            db.create_db()

            current_time = int(time.time())
            dummy_embedding = np.zeros(384, dtype=np.float32)

            db.insert_entry(
                text="CONFIDENTIAL USER ACTIVITY",
                timestamp=current_time,
                embedding=dummy_embedding,
                app="Confidential App",
                title="Private Document",
            )

            # Read data directly from the database file to check for unencrypted text
            conn = sqlite3.connect(db_path)
            try:
                cursor = conn.cursor()
                cursor.execute("SELECT text FROM entries")
                rows = cursor.fetchall()
            finally:
                conn.close() 

            raw_text_in_db = rows[0][0]
            
            assert "CONFIDENTIAL USER ACTIVITY" not in raw_text_in_db, (
                "DATABASE SECURITY FAILURE: Tekst unencrypted in database."
            )

    finally:
        gc.collect()
        if os.path.exists(db_path):
            os.remove(db_path)