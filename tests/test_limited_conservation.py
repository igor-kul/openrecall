"""
Objective : testing if personal data is stored longer than x amount of time

In accordance with GDPR core principle 8 (storage limitation) and article 5.1.e.

Currently openrecall never deletes anything.
"""

import pytest
from openrecall import database
import time
import numpy as np
import sqlite3

CONSERVATION_LIMIT = 30  # amount of days


@pytest.fixture
def store(tmp_path, monkeypatch):
    db_path = tmp_path / "recall.db"
    screenshots_path = tmp_path / "screenshots"

    screenshots_path.mkdir()

    monkeypatch.setattr(database, "db_path", str(db_path))
    monkeypatch.setattr(
        database, "screenshots_path", str(screenshots_path), raising=False
    )
    database.create_db()

    expiration_time = (CONSERVATION_LIMIT + 1) * 24 * 3600
    current_ts = int(time.time())
    expired_ts = current_ts - expiration_time

    empty_embedding = np.zeros(384, dtype=np.float32)
    database.insert_entry(
        "age: 32, profession: pilot", current_ts, empty_embedding, "pytest", "test"
    )
    database.insert_entry(
        "age: 95, profession: retired", expired_ts, empty_embedding, "pytest", "test"
    )

    for ts in (current_ts, expired_ts):
        (screenshots_path / f"{ts}.webp").touch()

    return (db_path, screenshots_path)


def test_entries_purged(store):
    # should call purge function

    db_path = store[0]
    with sqlite3.connect(db_path) as conn:
        for row in conn.execute("SELECT timestamp FROM entries"):
            timestamp = row[0]
            assert timestamp > time.time() - (
                (CONSERVATION_LIMIT) * 24 * 3600
            ), "expired entires are not purged"


def test_screenshots_purged(store):
    screenshot_path = store[1]
    for path in screenshot_path.iterdir():
        timestamp = int(path.stem)
        assert timestamp > time.time() - (
            (CONSERVATION_LIMIT) * 24 * 3600
        ), "expired screenshots are not purged"
