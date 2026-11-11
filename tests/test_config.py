import pytest
from unittest import mock
from cryptography.fernet import Fernet
from openrecall.config import get_appdata_folder


def test_get_appdata_folder_windows(tmp_path):
    with mock.patch("sys.platform", "win32"):
        # Test met LOCALAPPDATA
        with mock.patch.dict("os.environ", {"LOCALAPPDATA": str(tmp_path)}):
            expected_path = tmp_path / "openrecall"
            assert get_appdata_folder() == str(expected_path)
            assert expected_path.exists()


def test_get_appdata_folder_windows_no_appdata():
    with mock.patch("sys.platform", "win32"):
        with mock.patch.dict("os.environ", {}, clear=True):
            with pytest.raises(
                EnvironmentError, match="No APPDATA or LOCALAPPDATA environment variable set."
            ):
                get_appdata_folder()


def test_get_appdata_folder_darwin(tmp_path):
    with mock.patch("sys.platform", "darwin"):
        with mock.patch("os.path.expanduser", return_value=str(tmp_path)):
            expected_path = tmp_path / "Library" / "Application Support" / "openrecall"
            assert get_appdata_folder() == str(expected_path)
            assert expected_path.exists()


def test_get_appdata_folder_linux(tmp_path):
    with mock.patch("sys.platform", "linux"):
        with mock.patch("os.path.expanduser", return_value=str(tmp_path)):
            expected_path = tmp_path / ".local" / "share" / "openrecall"
            assert get_appdata_folder() == str(expected_path)
            assert expected_path.exists()


def test_encryption_key_is_stored_in_keyring(tmp_path, monkeypatch):
    import openrecall.config as config

    stored = {}
    monkeypatch.setattr(config, "appdata_folder", str(tmp_path))
    monkeypatch.setattr(config, "KEYRING_USERNAME", str(tmp_path))
    monkeypatch.setattr(
        config.keyring,
        "get_password",
        lambda service, username: stored.get((service, username)),
    )
    monkeypatch.setattr(
        config.keyring,
        "set_password",
        lambda service, username, value: stored.__setitem__(
            (service, username), value
        ),
    )

    key = config._load_encryption_key()

    assert Fernet(key)
    assert stored[(config.KEYRING_SERVICE, str(tmp_path))] == key
    assert not (tmp_path / "secret.key").exists()


def test_encryption_key_storage_must_be_verified(tmp_path, monkeypatch):
    import openrecall.config as config

    monkeypatch.setattr(config, "appdata_folder", str(tmp_path))
    monkeypatch.setattr(config, "KEYRING_USERNAME", str(tmp_path))
    monkeypatch.setattr(config.keyring, "get_password", lambda service, username: None)
    monkeypatch.setattr(config.keyring, "set_password", lambda service, username, value: None)

    with pytest.raises(RuntimeError, match="could not store"):
        config._load_encryption_key()