"""Privacy test: only the user can open the web interface.

The web interface serves decrypted screenshots and search results on
localhost. Without authentication any local program, other user account or
website (through CSRF or DNS rebinding) can read or erase them, which breaks
confidentiality (GDPR Art. 32) and the purpose of encrypting the data at rest.
"""

import pytest
from flask.testing import FlaskClient

from openrecall.app import ACCESS_TOKEN, SESSION_COOKIE, app


@pytest.fixture
def client() -> FlaskClient:
    return app.test_client()


@pytest.mark.parametrize("path", ["/", "/search?q=password", "/static/1.webp"])
def test_requests_without_token_are_rejected(client: FlaskClient, path: str) -> None:
    """Pages and screenshots are refused without the startup token."""
    response = client.get(path)

    assert response.status_code == 403, f"{path} is reachable without logging in"


def test_forget_without_token_is_rejected(client: FlaskClient) -> None:
    """Another website cannot erase the history with a hidden form."""
    response = client.post("/forget", data={"minutes": "99999999"})

    assert response.status_code == 403


def test_wrong_token_is_rejected(client: FlaskClient) -> None:
    response = client.get("/?token=not-the-token")

    assert response.status_code == 403


def test_startup_link_sets_session_and_hides_token(client: FlaskClient) -> None:
    """The startup link logs the browser in and removes the token from the URL."""
    response = client.get(f"/?token={ACCESS_TOKEN}")

    assert response.status_code == 302
    assert "token" not in response.headers["Location"]
    cookie = response.headers["Set-Cookie"]
    assert f"{SESSION_COOKIE}=" in cookie
    assert "HttpOnly" in cookie
    assert "SameSite=Strict" in cookie


def test_session_cookie_gives_access(client: FlaskClient) -> None:
    client.set_cookie(SESSION_COOKIE, ACCESS_TOKEN)

    response = client.get("/static/does-not-exist.webp")

    # 404 instead of 403: the request got past authentication
    assert response.status_code == 404


def test_foreign_host_is_rejected(client: FlaskClient) -> None:
    """A rebound domain is refused even with a valid session (DNS rebinding)."""
    client.set_cookie(SESSION_COOKIE, ACCESS_TOKEN, domain="evil.example")

    response = client.get("/", headers={"Host": "evil.example:8082"})

    assert response.status_code == 403
