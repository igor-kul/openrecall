import sys

import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

# openrecall.config parses sys.argv at import time; hide pytest's own
# arguments so they are not rejected as unknown OpenRecall options.
sys.argv = sys.argv[:1]

# One key pair for the whole run: some tests share a database across tests
_TEST_PRIVATE_KEY = X25519PrivateKey.generate()


@pytest.fixture(autouse=True)
def unlocked_vault(monkeypatch: pytest.MonkeyPatch) -> None:
    """Gives every test an unlocked vault without a password or an auth.json."""
    try:
        from openrecall import vault
    except ImportError:
        # Older versions of OpenRecall have no vault, so there is nothing to
        # prepare; the tests must still run there to show what is missing
        return

    monkeypatch.setattr(vault, "_public_key", _TEST_PRIVATE_KEY.public_key())
    monkeypatch.setattr(vault, "_private_key", _TEST_PRIVATE_KEY)


@pytest.fixture(autouse=True)
def no_storage_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    """Switches the storage limit off, so no test writes gigabytes of filler.

    With the limit on, every test that runs the capture loop would fill its
    data folder up to the default limit (several GB). Some tests also point
    the screenshots to the real folder, where the limit could delete real
    captures. The storage tests set their own small limit.
    """
    from openrecall import database

    # raising=False: older versions of OpenRecall have no storage limit
    monkeypatch.setattr(database, "MAX_STORAGE_BYTES", None, raising=False)


TEST_PASSWORD = "correct horse battery staple"


def history_is_readable() -> bool:
    """Whether the recorded history can be decrypted right now.

    Versions of OpenRecall without a vault keep one key that is always
    available, so there the history is always readable.
    """
    try:
        from openrecall import vault
    except ImportError:
        return True
    return vault.is_unlocked()


@pytest.fixture
def password_vault(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A real, locked vault in a temporary auth.json, protected by TEST_PASSWORD.

    Does nothing on versions without a vault, so the tests that use it fail
    on what the user can do instead of erroring during setup.
    """
    try:
        from openrecall import vault
    except ImportError:
        return

    monkeypatch.setattr(vault, "auth_path", str(tmp_path / "auth.json"))
    vault.set_up(TEST_PASSWORD)
    vault.lock()
    # Re-read from the new auth.json instead of the shared test key
    monkeypatch.setattr(vault, "_public_key", None)


@pytest.fixture
def app_client(password_vault, monkeypatch: pytest.MonkeyPatch):
    """The web UI with no session and no failed logins."""
    import openrecall.app as app_module

    # raising=False: versions without a login have no session state
    monkeypatch.setattr(
        app_module, "_session", {"id": None, "last_activity": 0.0}, raising=False
    )
    monkeypatch.setattr(
        app_module,
        "_login_attempts",
        {"failed": 0, "blocked_until": 0.0},
        raising=False,
    )
    return app_module.app.test_client()


@pytest.fixture
def logged_in_client(app_client):
    """The web UI after logging in with the right password.

    Not asserted here: whether the login works is what the tests check.
    """
    app_client.post("/login", data={"password": TEST_PASSWORD})
    return app_client
