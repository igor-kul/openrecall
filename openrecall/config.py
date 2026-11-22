import os
import sys
import argparse

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
parser.add_argument(
    "--max-storage-gb",
    type=float,
    default=5,
    help="Space the data folder always takes on disk, in GB. When it is full, "
    "the oldest captures are deleted.",
)
args, _ = parser.parse_known_args()

if args.retention_days < 1:
    parser.error("--retention-days must be at least 1")
RETENTION_DAYS = args.retention_days

if args.max_storage_gb <= 0:
    parser.error("--max-storage-gb must be greater than 0")
MAX_STORAGE_BYTES = int(args.max_storage_gb * 1024**3)

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

# Holds the public key and the password-protected private key, see vault.py
auth_path = os.path.join(appdata_folder, "auth.json")
