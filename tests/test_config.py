import pytest
from unittest import mock
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