"""
Objective : testing if personal data is stored longer than x amount of time

In accordance with GDPR core principle 8 (storage limitation) and article 5.1.e.

Currently openrecall never deletes anything.
"""

import os
import pytest
from openrecall import database, screenshot
import time
import numpy as np
import sqlite3

RETENTION_DAYS = 30  # amount of days
DAY = 24 * 60 * 60


@pytest.fixture
def store(tmp_path, monkeypatch):
    db_path = str(tmp_path / "recall.db")
    screenshots_path = tmp_path / "screenshots"
    screenshots_path.mkdir()

    monkeypatch.setattr(database, "db_path", db_path)
    monkeypatch.setattr(
        database, "screenshots_path", str(screenshots_path), raising=False
    )
    database.create_db()

    now = int(time.time())
    expired_ts = now - (RETENTION_DAYS + 1) * DAY
    recent_ts = now - 1 * DAY

    empty_embedding = np.zeros(384, dtype=np.float32)
    database.insert_entry(
        "age: 32, profession: pilot", recent_ts, empty_embedding, "pytest", "test"
    )
    database.insert_entry(
        "age: 95, profession: retired", expired_ts, empty_embedding, "pytest", "test"
    )

    for ts in (recent_ts, expired_ts):
        (screenshots_path / f"{ts}.webp").write_bytes(b"fake webp")

    return {
        "db_path": db_path,
        "screenshots_path": screenshots_path,
        "expired_ts": expired_ts,
        "recent_ts": recent_ts,
    }


def _stored_timestamps(db_path: str) -> set:
    """Returns set of timestamps in db"""
    with sqlite3.connect(db_path) as conn:
        return {row[0] for row in conn.execute("SELECT timestamp FROM entries")}


def _run_openrecall_once(monkeypatch) -> None:
    """Runs one turn of the capture loop, like the application does on its own.

    The tests do not call any delete function themselves: expired data has to
    disappear just because openrecall is running.
    """

    def stop_loop(seconds: float) -> None:
        # The capture loop never ends, so stop it at its first pause
        raise InterruptedError

    # No real screen capture: the loop grabs the screen once before it starts
    monkeypatch.setattr(screenshot, "take_screenshots", lambda: [])
    # An idle user: the loop takes no screenshot and goes straight to sleep
    monkeypatch.setattr(screenshot, "is_user_active", lambda: False)
    monkeypatch.setattr(screenshot.time, "sleep", stop_loop)

    with pytest.raises(InterruptedError):
        screenshot.record_screenshots_thread()


def test_expired_entries_are_removed_from_database(store, monkeypatch) -> None:
    """OCR text and metadata older than 30 days must not stay in the database."""
    _run_openrecall_once(monkeypatch)

    remaining = _stored_timestamps(store["db_path"])
    assert (
        store["expired_ts"] not in remaining
    ), f"Entry older than {RETENTION_DAYS} days is still stored"
    assert store["recent_ts"] in remaining, "Recent entry must be kept"


def test_expired_screenshots_are_removed_from_disk(store, monkeypatch) -> None:
    """Screenshot files older than 30 days must not stay on disk."""
    _run_openrecall_once(monkeypatch)

    screenshots_path = store["screenshots_path"]
    assert not os.path.exists(
        screenshots_path / f"{store['expired_ts']}.webp"
    ), f"Screenshot older than {RETENTION_DAYS} days is still on disk"
    assert os.path.exists(
        screenshots_path / f"{store['recent_ts']}.webp"
    ), "Recent screenshot must be kept"
