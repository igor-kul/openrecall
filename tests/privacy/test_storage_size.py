"""
Privacy test: the size of the data folder must not reveal how much the user works.

Anyone who can see the data folder (an employer's IT department, an
administrator) can follow its size over time without any password. A folder
that grows by a few hundred megabytes on busy days and not at all on quiet
days shows when and how much the employee worked (LINDDUN Detectability).
The folder must therefore always take the same space on disk, and captures
must stop at a fixed limit (also storage limitation, GDPR Art. 5(1)(e)).
"""

import os
import time

import numpy as np
import pytest

from openrecall import database, screenshot

# A small limit so the tests never write gigabytes
TEST_LIMIT = 1024 * 1024  # 1 MB


@pytest.fixture
def store(tmp_path, monkeypatch):
    """An empty data folder in a temporary directory, with a 1 MB storage limit."""
    data_folder = tmp_path / "data"
    screenshots_path = data_folder / "screenshots"
    screenshots_path.mkdir(parents=True)
    db_path = str(data_folder / "recall.db")

    monkeypatch.setattr(database, "db_path", db_path)
    monkeypatch.setattr(
        database, "screenshots_path", str(screenshots_path), raising=False
    )
    monkeypatch.setattr(screenshot, "screenshots_path", str(screenshots_path))
    # raising=False so the tests fail on their assertions, not here, on a
    # version of OpenRecall that has no storage limit
    monkeypatch.setattr(database, "MAX_STORAGE_BYTES", TEST_LIMIT, raising=False)
    database.create_db()
    return {
        "data_folder": data_folder,
        "screenshots_path": screenshots_path,
        "clock": {"now": time.time()},
    }


def _capture(store, monkeypatch, turns: int) -> None:
    """Runs the capture loop for a number of turns, with a new screen at every turn.

    The screen, OCR and embedding are faked so the test is fast. Sleeping is
    faked too, but it moves a fake clock forward like a real sleep would:
    otherwise every capture would get the same timestamp.
    """
    clock = store["clock"]
    sleeps = []

    def new_screen() -> list:
        return [np.random.randint(0, 256, (100, 100, 3), dtype=np.uint8)]

    def sleep(seconds: float) -> None:
        clock["now"] += seconds
        # The capture loop never ends, so stop it after the wanted number of turns
        sleeps.append(seconds)
        if len(sleeps) >= turns:
            raise InterruptedError

    monkeypatch.setattr(screenshot.time, "time", lambda: clock["now"])

    monkeypatch.setattr(screenshot, "is_user_active", lambda: True)
    monkeypatch.setattr(screenshot, "take_screenshots", new_screen)
    monkeypatch.setattr(screenshot, "get_active_app_name", lambda: "Safari")
    monkeypatch.setattr(screenshot, "get_active_window_title", lambda: "Report")
    monkeypatch.setattr(
        screenshot, "extract_text_from_image", lambda image: "meeting notes"
    )
    monkeypatch.setattr(
        screenshot, "get_embedding", lambda text: np.zeros(384, np.float32)
    )
    monkeypatch.setattr(screenshot.time, "sleep", sleep)

    with pytest.raises(InterruptedError):
        screenshot.record_screenshots_thread()


def _space_on_disk(folder) -> int:
    """The space a folder takes on disk, as an administrator would measure it (du)."""
    total = 0
    for root, _, files in os.walk(folder):
        for name in files:
            total += os.stat(os.path.join(root, name)).st_blocks * 512
    return total


def _screenshot_names(store) -> list:
    return sorted(os.listdir(store["screenshots_path"]))


def test_folder_size_does_not_grow_with_activity(store, monkeypatch) -> None:
    """Working more must not make the data folder bigger."""
    _capture(store, monkeypatch, turns=2)
    captures_before = len(_screenshot_names(store))
    size_before = _space_on_disk(store["data_folder"])

    _capture(store, monkeypatch, turns=6)

    # Control: without new captures the size would trivially stay the same
    assert len(_screenshot_names(store)) > captures_before, "No new capture was stored"
    assert (
        _space_on_disk(store["data_folder"]) == size_before
    ), "The data folder grew with the user's activity"


def test_oldest_captures_are_removed_at_the_limit(store, monkeypatch) -> None:
    """When the limit is reached, the oldest captures make room for the new ones."""
    _capture(store, monkeypatch, turns=2)
    first_capture = _screenshot_names(store)[0]

    # Each fake capture takes about 40 KB, so 40 of them do not fit in 1 MB
    _capture(store, monkeypatch, turns=40)

    assert (
        _space_on_disk(store["data_folder"]) <= TEST_LIMIT
    ), "The data folder grew beyond the storage limit"
    assert first_capture not in _screenshot_names(store), "The oldest capture was kept"
