"""Privacy test: user-controlled erasure of recent activity.

The tests fail until the user, as a controller, can control data by forgetting a time range.
Feature needed according to the right to erasure (gdpr art 17).
"""

import os
import sqlite3
import time
from pathlib import Path
from typing import Dict

import numpy as np
import pytest

from openrecall import database

MINUTE = 60


@pytest.fixture
def store(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Dict[str, object]:
    db_path = str(tmp_path / "recall.db")
    screenshots_path = tmp_path / "screenshots"
    screenshots_path.mkdir()
    monkeypatch.setattr(database, "db_path", db_path)
    monkeypatch.setattr(
        database, "screenshots_path", str(screenshots_path), raising=False
    )
    database.create_db()

    now = int(time.time())
    keep_ts = now - 60 * MINUTE
    forget_ts = [now - 10 * MINUTE, now - 1 * MINUTE]
    embedding = np.zeros(384, dtype=np.float32)
    for ts in [keep_ts, *forget_ts]:
        database.insert_entry("PASSWORD: hunter2", ts, embedding, "Browser", "Login")
        (screenshots_path / f"{ts}.webp").write_bytes(b"fake webp")

    return {
        "db_path": db_path,
        "screenshots_path": screenshots_path,
        "now": now,
        "keep_ts": keep_ts,
        "forget_ts": forget_ts,
    }


def _stored_timestamps(db_path: str) -> set:
    """Read the timestamps stored in the entries table.

    Args:
        db_path: Path to the SQLite database.

    Returns:
        set: All timestamps currently stored.
    """
    with sqlite3.connect(db_path) as conn:
        return {row[0] for row in conn.execute("SELECT timestamp FROM entries")}


def _assert_only_recent_activity_forgotten(store: Dict[str, object]) -> None:
    """Check that the last 15 minutes are gone, rows and files, and nothing else.

    Args:
        store: The data store created by the fixture.
    """
    remaining = _stored_timestamps(store["db_path"])
    screenshots_path = store["screenshots_path"]
    for ts in store["forget_ts"]:
        assert ts not in remaining, "Forgotten capture is still in the database"
        assert not os.path.exists(
            screenshots_path / f"{ts}.webp"
        ), "Forgotten screenshot is still on disk"
    assert store["keep_ts"] in remaining, "Older capture must be kept"
    assert os.path.exists(
        screenshots_path / f"{store['keep_ts']}.webp"
    ), "Older screenshot must be kept"


def test_time_range_can_be_forgotten(store: Dict[str, object]) -> None:
    """Deleting a time range removes its rows and screenshots, and only those."""
    if not hasattr(database, "delete_entries_between"):
        pytest.fail(
            "No erasure mechanism: openrecall.database.delete_entries_between() "
            "does not exist, so the user cannot remove what was captured."
        )

    database.delete_entries_between(store["now"] - 15 * MINUTE, store["now"])

    _assert_only_recent_activity_forgotten(store)


def test_web_interface_can_forget_last_minutes(store: Dict[str, object]) -> None:
    """The user can forget the last minutes from the web interface."""
    from openrecall.app import app

    response = app.test_client().post("/forget", data={"minutes": "15"})

    assert response.status_code in (
        302,
        303,
    ), f"POST /forget is not available (HTTP {response.status_code})"
    _assert_only_recent_activity_forgotten(store)
