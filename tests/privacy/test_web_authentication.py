"""Privacy test: only someone who knows the password can open the web interface.

The web interface shows decrypted screenshots and search results. Without
authentication anyone at the computer, any local program, other user account
or website (through CSRF or DNS rebinding) can read or erase them, which
breaks confidentiality (GDPR Art. 32).
"""

import time

import pytest
from flask.testing import FlaskClient

from tests.conftest import TEST_PASSWORD

# Skips this file on versions of OpenRecall that have no vault yet,
# instead of stopping the whole test run
vault = pytest.importorskip("openrecall.vault", exc_type=ImportError)


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

    assert response.status_code == 403


def test_wrong_password_is_rejected(app_client: FlaskClient) -> None:
    response = app_client.post("/login", data={"password": "not the password"})

    assert response.status_code == 401
    assert not vault.is_unlocked()


def test_password_guessing_is_slowed_down(app_client: FlaskClient) -> None:
    for _ in range(5):
        app_client.post("/login", data={"password": "guess"})

    response = app_client.post("/login", data={"password": TEST_PASSWORD})

    assert response.status_code == 429, "Unlimited password guesses are allowed"
    assert not vault.is_unlocked()


def test_right_password_unlocks(app_client: FlaskClient) -> None:
    response = app_client.post("/login", data={"password": TEST_PASSWORD})

    assert response.status_code == 302
    assert vault.is_unlocked()
    cookie = response.headers["Set-Cookie"]
    assert "HttpOnly" in cookie
    assert "SameSite=Strict" in cookie
    assert app_client.get("/").status_code == 200


def test_lock_button_ends_session(logged_in_client: FlaskClient) -> None:
    logged_in_client.post("/lock")

    assert not vault.is_unlocked(), "The private key is still in memory"
    assert logged_in_client.get("/").status_code == 302


def test_idle_session_locks_itself(logged_in_client: FlaskClient) -> None:
    import openrecall.app as app_module

    app_module._session["last_activity"] = (
        time.time() - app_module.SESSION_IDLE_SECONDS - 1
    )

    assert logged_in_client.get("/").status_code == 302
    assert not vault.is_unlocked()


def test_foreign_host_is_rejected(logged_in_client: FlaskClient) -> None:
    """A rebound domain is refused even with a valid session (DNS rebinding)."""
    response = logged_in_client.get("/", headers={"Host": "evil.example:8082"})

    assert response.status_code == 403
