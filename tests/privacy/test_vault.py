"""Privacy test: the recorded history can only be read with the password.

Recording uses a public key, so it works without the password; viewing needs
the private key, which is only stored encrypted with the password. Someone
with access to the user's account (a colleague at an unlocked computer, an
employer, malware) therefore cannot read the history from disk, nor regain
access by deleting auth.json.
"""

import os

import pytest
from cryptography.fernet import InvalidToken

from tests.conftest import TEST_PASSWORD


def _require_vault():
    """Returns the vault, or fails the test on versions that have none.

    Failing instead of skipping: without a vault the history is protected by
    a single key that anyone using the account can read, which is exactly
    what these tests must report.
    """
    try:
        from openrecall import vault
    except ImportError:
        pytest.fail(
            "OpenRecall has no vault: the recorded history can be decrypted "
            "without the user's password"
        )
    return vault


def test_recording_works_while_locked(password_vault) -> None:
    vault = _require_vault()
    encrypted = vault.encrypt(b"screenshot")

    assert b"screenshot" not in encrypted


def test_viewing_requires_password(password_vault) -> None:
    vault = _require_vault()
    encrypted = vault.encrypt(b"screenshot")

    with pytest.raises(vault.VaultLocked):
        vault.decrypt(encrypted)

    assert vault.unlock(TEST_PASSWORD)
    assert vault.decrypt(encrypted) == b"screenshot"


def test_wrong_password_does_not_unlock(password_vault) -> None:
    vault = _require_vault()
    assert not vault.unlock("not the password")
    assert not vault.is_unlocked()


def test_private_key_is_not_stored_in_plain_form(password_vault) -> None:
    vault = _require_vault()
    assert vault.unlock(TEST_PASSWORD)
    private_bytes = vault._private_key.private_bytes_raw()

    with open(vault.auth_path, encoding="utf-8") as f:
        stored = f.read()

    assert private_bytes.hex() not in stored
    assert TEST_PASSWORD not in stored


def test_password_cannot_be_overwritten(password_vault) -> None:
    vault = _require_vault()
    with pytest.raises(FileExistsError):
        vault.set_up("an attacker's password")


def test_deleting_auth_json_does_not_give_access(password_vault, monkeypatch) -> None:
    """Choosing a new password after deleting auth.json leaves the history unreadable."""
    vault = _require_vault()
    encrypted = vault.encrypt(b"screenshot")

    os.remove(vault.auth_path)
    monkeypatch.setattr(vault, "_public_key", None)
    vault.set_up("an attacker's password")
    assert vault.unlock("an attacker's password")

    with pytest.raises(InvalidToken):
        vault.decrypt(encrypted)


def test_password_must_be_long_enough(tmp_path, monkeypatch) -> None:
    vault = _require_vault()
    monkeypatch.setattr(vault, "auth_path", str(tmp_path / "auth.json"))

    with pytest.raises(ValueError):
        vault.set_up("short")
