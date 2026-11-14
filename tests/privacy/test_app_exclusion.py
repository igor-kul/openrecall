"""
Privacy test: applications that must not be recorded.

OpenRecall captures whatever is on screen, including a password manager or a
private chat. Users cannot exclude such applications (LINDDUN Unawareness,
U.2: no preferences on what is processed), which goes against data
minimisation (GDPR Art. 5(1)(c)) and data protection by default (Art. 25).
"""

import sqlite3
from pathlib import Path
from typing import Dict

import numpy as np
import pytest

from openrecall import database, screenshot


@pytest.fixture
def store(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Dict[str, object]:
    """Redirect the database and the screenshot folder to a temporary directory."""
    db_path = str(tmp_path / "recall.db")
    screenshots_path = tmp_path / "screenshots"
    screenshots_path.mkdir()
    monkeypatch.setattr(database, "db_path", db_path)
    monkeypatch.setattr(database, "screenshots_path", str(screenshots_path))
    monkeypatch.setattr(screenshot, "screenshots_path", str(screenshots_path))
    database.create_db()
    return {"db_path": db_path, "screenshots_path": screenshots_path}


def _capture_once(monkeypatch: pytest.MonkeyPatch, active_app: str) -> None:
    """Run one turn of the capture loop while `active_app` is in the foreground.

    The screen, OCR and embedding are faked so the test is fast and the screen
    always looks new
    """

    def new_screen() -> list:
        return [np.random.randint(0, 256, (100, 100, 3), dtype=np.uint8)]

    def stop_loop(seconds: float) -> None:
        raise InterruptedError

    monkeypatch.setattr(screenshot, "is_user_active", lambda: True)
    monkeypatch.setattr(screenshot, "take_screenshots", new_screen)
    monkeypatch.setattr(screenshot, "get_active_app_name", lambda: active_app)
    monkeypatch.setattr(
        screenshot, "get_active_window_title", lambda: "Chat with Alice"
    )
    monkeypatch.setattr(
        screenshot, "extract_text_from_image", lambda image: "see you at 8"
    )
    monkeypatch.setattr(
        screenshot, "get_embedding", lambda text: np.zeros(384, np.float32)
    )
    monkeypatch.setattr(screenshot.time, "sleep", stop_loop)

    with pytest.raises(InterruptedError):
        screenshot.record_screenshots_thread()


def _stored_rows(db_path: str) -> int:
    with sqlite3.connect(db_path) as conn:
        return conn.execute("SELECT COUNT(*) FROM entries").fetchone()[0]


def _assert_nothing_stored(store: Dict[str, object]) -> None:
    assert not list(store["screenshots_path"].iterdir()), "A screenshot was saved"
    assert _stored_rows(store["db_path"]) == 0, "A database entry was stored"


def test_user_excluded_app_is_not_recorded(store, monkeypatch) -> None:
    """An application the user excluded must leave no screenshot and no entry."""
    # raising=False so a missing setting fails the assertions instead of erroring
    monkeypatch.setattr(screenshot, "EXCLUDED_APPS", ["WhatsApp"], raising=False)

    _capture_once(monkeypatch, "WhatsApp")

    _assert_nothing_stored(store)


def test_password_manager_is_excluded_by_default(store, monkeypatch) -> None:
    """Without any configuration, a password manager must not be recorded."""
    _capture_once(monkeypatch, "1Password")

    _assert_nothing_stored(store)


def test_other_apps_are_still_recorded(store, monkeypatch) -> None:
    """Control: the exclusion must not stop the capture of ordinary apps.

    Without it, the two tests above would also pass if the faked loop simply
    stopped saving anything.
    """
    _capture_once(monkeypatch, "Safari")

    assert len(list(store["screenshots_path"].iterdir())) == 1
    assert _stored_rows(store["db_path"]) == 1
