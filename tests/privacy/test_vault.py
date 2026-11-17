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

from openrecall import vault
from tests.conftest import TEST_PASSWORD


def test_recording_works_while_locked(password_vault) -> None:
    encrypted = vault.encrypt(b"screenshot")

    assert b"screenshot" not in encrypted


def test_viewing_requires_password(password_vault) -> None:
    encrypted = vault.encrypt(b"screenshot")

    with pytest.raises(vault.VaultLocked):
        vault.decrypt(encrypted)

    assert vault.unlock(TEST_PASSWORD)
    assert vault.decrypt(encrypted) == b"screenshot"


def test_wrong_password_does_not_unlock(password_vault) -> None:
    assert not vault.unlock("not the password")
    assert not vault.is_unlocked()


def test_private_key_is_not_stored_in_plain_form(password_vault) -> None:
    assert vault.unlock(TEST_PASSWORD)
    private_bytes = vault._private_key.private_bytes_raw()

    with open(vault.auth_path, encoding="utf-8") as f:
        stored = f.read()

    assert private_bytes.hex() not in stored
    assert TEST_PASSWORD not in stored


def test_password_cannot_be_overwritten(password_vault) -> None:
    with pytest.raises(FileExistsError):
        vault.set_up("an attacker's password")


def test_deleting_auth_json_does_not_give_access(password_vault, monkeypatch) -> None:
    """Choosing a new password after deleting auth.json leaves the history unreadable."""
    encrypted = vault.encrypt(b"screenshot")

    os.remove(vault.auth_path)
    monkeypatch.setattr(vault, "_public_key", None)
    vault.set_up("an attacker's password")
    assert vault.unlock("an attacker's password")

    with pytest.raises(InvalidToken):
        vault.decrypt(encrypted)


def test_password_must_be_long_enough(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(vault, "auth_path", str(tmp_path / "auth.json"))

    with pytest.raises(ValueError):
        vault.set_up("short")
