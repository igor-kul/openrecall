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


@pytest.fixture
def user_client(request):
    """The web interface as the user sees it: logged in if OpenRecall has a login."""
    try:
        from openrecall import vault  # noqa: F401
    except ImportError:
        # The original version has no login: the interface is open to anyone
        from openrecall.app import app

        return app.test_client()
    # calls logged_in_client fixture through request fixture instead of arg
    return request.getfixturevalue("logged_in_client")


def _forget_last_15_minutes(client) -> None:
    """Does what the user does in the web interface: Forget, last 15 minutes.

    The tests do not call any delete function themselves: they only use what
    the user can reach.
    """
    client.post("/forget", data={"minutes": "15"})


def test_forgotten_entries_are_removed_from_database(store, user_client) -> None:
    """After Forget, the last 15 minutes must not stay in the database."""
    _forget_last_15_minutes(user_client)

    remaining = _stored_timestamps(store["db_path"])
    for ts in store["forget_ts"]:
        assert ts not in remaining, "Forgotten entry is still stored"
    assert store["keep_ts"] in remaining, "Older entry must be kept"


def test_forgotten_screenshots_are_removed_from_disk(store, user_client) -> None:
    """After Forget, the screenshots of the last 15 minutes must not stay on disk."""
    _forget_last_15_minutes(user_client)

    screenshots_path = store["screenshots_path"]
    for ts in store["forget_ts"]:
        assert not os.path.exists(
            screenshots_path / f"{ts}.webp"
        ), "Forgotten screenshot is still on disk"
    assert os.path.exists(
        screenshots_path / f"{store['keep_ts']}.webp"
    ), "Older screenshot must be kept"
