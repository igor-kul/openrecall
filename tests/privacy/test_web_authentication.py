"""Privacy test: only someone who knows the password can open the web interface.

The web interface shows decrypted screenshots and search results. Without
authentication anyone at the computer, any local program, other user account
or website (through CSRF or DNS rebinding) can read or erase them, which
breaks confidentiality (GDPR Art. 32).

The tests only do what a person or a website can do: send HTTP requests. On a
version without a login those requests simply succeed, so the tests fail on
the privacy problem itself.
"""

import time

import pytest
from flask.testing import FlaskClient

from tests.conftest import TEST_PASSWORD, history_is_readable

# The interface must lock after this much inactivity (see README)
IDLE_LIMIT_SECONDS = 5 * 60


@pytest.fixture(autouse=True)
def empty_store(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Points the web UI at an empty test store.

    On a version without a login these requests get through, and the
    /forget test would otherwise erase the user's real history.
    """
    from openrecall import database
    import openrecall.app as app_module

    screenshots_path = tmp_path / "screenshots"
    screenshots_path.mkdir()
    monkeypatch.setattr(database, "db_path", str(tmp_path / "recall.db"))
    monkeypatch.setattr(
        database, "screenshots_path", str(screenshots_path), raising=False
    )
    monkeypatch.setattr(app_module, "screenshots_path", str(screenshots_path))
    database.create_db()


@pytest.mark.parametrize("path", ["/", "/search?q=password", "/static/1.webp"])
def test_pages_redirect_to_login_without_session(
    app_client: FlaskClient, path: str
) -> None:
    response = app_client.get(path)

    assert response.status_code == 302, f"{path} is reachable without logging in"
    assert response.headers["Location"].endswith("/login")


def test_forget_without_session_is_rejected(app_client: FlaskClient) -> None:
    """Another website cannot erase the history with a hidden form."""
    response = app_client.post("/forget", data={"minutes": "99999999"})

    assert response.status_code == 403, "The history can be erased without logging in"


def test_wrong_password_is_rejected(app_client: FlaskClient) -> None:
    response = app_client.post("/login", data={"password": "not the password"})

    assert response.status_code == 401, "There is no password check"
    assert not history_is_readable()


def test_password_guessing_is_slowed_down(app_client: FlaskClient) -> None:
    for _ in range(5):
        app_client.post("/login", data={"password": "guess"})

    response = app_client.post("/login", data={"password": TEST_PASSWORD})

    assert response.status_code == 429, "Unlimited password guesses are allowed"
    assert not history_is_readable()


def test_right_password_unlocks(app_client: FlaskClient) -> None:
    response = app_client.post("/login", data={"password": TEST_PASSWORD})

    assert response.status_code == 302, "There is no login with a password"
    assert history_is_readable()
    cookie = response.headers["Set-Cookie"]
    assert "HttpOnly" in cookie
    assert "SameSite=Strict" in cookie
    assert app_client.get("/").status_code == 200


def test_lock_button_ends_session(logged_in_client: FlaskClient) -> None:
    logged_in_client.post("/lock")

    assert logged_in_client.get("/").status_code == 302, "Still logged in after Lock"
    assert not history_is_readable(), "The history can still be decrypted"


def test_idle_session_locks_itself(
    logged_in_client: FlaskClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Someone who sits down at the computer later finds the interface locked."""
    later = time.time() + IDLE_LIMIT_SECONDS + 1
    monkeypatch.setattr(time, "time", lambda: later)

    assert logged_in_client.get("/").status_code == 302, "Still open after idling"
    assert not history_is_readable(), "The history can still be decrypted"


def test_foreign_host_is_rejected(logged_in_client: FlaskClient) -> None:
    """A rebound domain is refused even with a valid session (DNS rebinding)."""
    response = logged_in_client.get("/", headers={"Host": "evil.example:8082"})

    assert response.status_code == 403, "Requests for other domains are answered"
