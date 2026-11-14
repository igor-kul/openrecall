import os
import sys
import argparse
from cryptography.fernet import Fernet
import keyring
from keyring.errors import KeyringError

parser = argparse.ArgumentParser(description="OpenRecall")
parser.add_argument(
    "--storage-path", default=None, help="Path to store the screenshots and database"
)
parser.add_argument(
    "--primary-monitor-only",
    action="store_true",
    help="Only record the primary monitor",
    default=False,
)
parser.add_argument(
    "--retention-days", type=int, default=30, help="Defines size of storage window"
)
DEFAULT_EXCLUDED_APPS = ["1Password", "Bitwarden", "KeePassXC", "Keychain Access"]
parser.add_argument(
    "--exclude-apps",
    default="",
    help="Comma-separated names of extra applications that are never recorded, "
    "e.g. 'WhatsApp,Signal'. Password managers are always excluded.",
)
args, _ = parser.parse_known_args()

if args.retention_days < 1:
    parser.error("--retention-days must be at least 1")
RETENTION_DAYS = args.retention_days

EXCLUDED_APPS = DEFAULT_EXCLUDED_APPS + [
    name.strip() for name in args.exclude_apps.split(",") if name.strip()
]


def get_appdata_folder(app_name="openrecall"):
    if sys.platform == "win32":
        appdata = os.getenv("LOCALAPPDATA") or os.getenv("APPDATA")
        if not appdata:
            raise EnvironmentError(
                "No APPDATA or LOCALAPPDATA environment variable set."
            )
        path = os.path.join(appdata, app_name)
    elif sys.platform == "darwin":
        home = os.path.expanduser("~")
        path = os.path.join(home, "Library", "Application Support", app_name)
    else:
        home = os.path.expanduser("~")
        path = os.path.join(home, ".local", "share", app_name)
    if not os.path.exists(path):
        os.makedirs(path)
    return path


if args.storage_path:
    appdata_folder = os.path.abspath(os.path.expanduser(args.storage_path))
else:
    appdata_folder = get_appdata_folder()

screenshots_path = os.path.join(appdata_folder, "screenshots")
db_path = os.path.join(appdata_folder, "recall.db")

if not os.path.exists(screenshots_path):
    try:
        os.makedirs(screenshots_path)
    except:
        pass

KEYRING_SERVICE = "OpenRecall Encryption"
KEYRING_USERNAME = os.path.abspath(appdata_folder)


def _load_encryption_key() -> str:
    environment_key = os.environ.get("OPENRECALL_ENCRYPTION_KEY")
    if environment_key:
        Fernet(environment_key)
        return environment_key

    try:
        stored_key = keyring.get_password(KEYRING_SERVICE, KEYRING_USERNAME)
    except KeyringError as exc:
        raise RuntimeError(
            "OpenRecall could not access the operating system keyring."
        ) from exc
    if stored_key:
        Fernet(stored_key)
        return stored_key

    legacy_key_file = os.path.join(appdata_folder, "secret.key")
    if os.path.exists(legacy_key_file):
        try:
            with open(legacy_key_file, "rb") as f:
                legacy_key = f.read().decode("ascii")
            Fernet(legacy_key)
        except (OSError, UnicodeDecodeError, ValueError) as exc:
            raise RuntimeError(
                "OpenRecall found an invalid legacy encryption key."
            ) from exc
        try:
            keyring.set_password(KEYRING_SERVICE, KEYRING_USERNAME, legacy_key)
            if keyring.get_password(KEYRING_SERVICE, KEYRING_USERNAME) != legacy_key:
                raise KeyringError("Keyring did not persist the migrated key.")
            os.remove(legacy_key_file)
        except (KeyringError, OSError) as exc:
            raise RuntimeError(
                "OpenRecall could not migrate the legacy encryption key securely."
            ) from exc
        return legacy_key

    new_key = Fernet.generate_key().decode("ascii")
    try:
        keyring.set_password(KEYRING_SERVICE, KEYRING_USERNAME, new_key)
        if keyring.get_password(KEYRING_SERVICE, KEYRING_USERNAME) != new_key:
            raise KeyringError("Keyring did not persist the generated key.")
    except KeyringError as exc:
        raise RuntimeError(
            "OpenRecall could not store its encryption key in the operating system keyring."
        ) from exc
    return new_key


ENCRYPTION_KEY = _load_encryption_key()
