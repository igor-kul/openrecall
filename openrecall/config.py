import os
import sys
import argparse
from cryptography.fernet import Fernet

parser = argparse.ArgumentParser(description="OpenRecall")
parser.add_argument("--storage-path", default=None, help="Path to store the screenshots and database")
parser.add_argument("--primary-monitor-only", action="store_true", help="Only record the primary monitor", default=False)
args, _ = parser.parse_known_args()

def get_appdata_folder(app_name="openrecall"):
    if sys.platform == "win32":
        appdata = os.getenv("LOCALAPPDATA") or os.getenv("APPDATA")
        if not appdata:
            raise EnvironmentError("No APPDATA or LOCALAPPDATA environment variable set.")
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

# Centralized Encryption Key logic
ENCRYPTION_KEY = os.environ.get("OPENRECALL_ENCRYPTION_KEY")
if not ENCRYPTION_KEY:
    key_file = os.path.join(appdata_folder, "secret.key")
    if os.path.exists(key_file):
        with open(key_file, "rb") as f:
            ENCRYPTION_KEY = f.read().decode()
    else:
        new_key = Fernet.generate_key()
        with open(key_file, "wb") as f:
            f.write(new_key)
        ENCRYPTION_KEY = new_key.decode()