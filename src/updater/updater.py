"""Updater for GhostChatter client."""

import os
import time
import requests
import shutil
import subprocess
import ctypes
import sys
from pathlib import Path


def restart_client():
    print("Starte Client...")
    subprocess.Popen([CLIENT_PATH])
    sys.exit()


def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


if not is_admin():
    # Neustart mit Adminrechten
    ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable, " ".join(sys.argv), None, 1
    )
    sys.exit()


# URLs zur neuesten Version (Client & Version)
UPDATE_URL = "https://raw.githubusercontent.com/lelewithheart/GhostChatterV2/main/release/GhostChatterClient.exe"
VERSION_URL = "https://raw.githubusercontent.com/lelewithheart/GhostChatterV2/main/release/version.txt"

# Pfade relativ zum Executable
if getattr(sys, "frozen", False):
    base = Path(sys.executable).parent
else:
    base = Path(__file__).resolve().parent.parent.parent

CLIENT_PATH = base / "GhostChatterClient.exe"
NEW_CLIENT_PATH = base / "GhostChatterClient_new.exe"
VERSION_PATH = base / "version.txt"
NEW_VERSION_PATH = base / "version_new.txt"


def download_new_client():
    print("Lade neue Version herunter...")
    r = requests.get(UPDATE_URL, stream=True)
    with open(NEW_CLIENT_PATH, "wb") as f:
        shutil.copyfileobj(r.raw, f)
    print("Client.exe heruntergeladen.")


def download_version_file():
    print("Lade neue Versionsdatei herunter...")
    r = requests.get(VERSION_URL)
    with open(NEW_VERSION_PATH, "w", encoding="utf-8") as f:
        f.write(r.text.strip())
    print("version.txt heruntergeladen.")


def replace_files():
    # Falls alte Client.exe noch nicht geschlossen -> etwas warten
    time.sleep(2)

    # Client ersetzen
    if os.path.exists(CLIENT_PATH):
        os.remove(CLIENT_PATH)
    os.rename(NEW_CLIENT_PATH, CLIENT_PATH)
    print("Client aktualisiert.")

    # Version.txt ersetzen
    if os.path.exists(VERSION_PATH):
        os.remove(VERSION_PATH)
    os.rename(NEW_VERSION_PATH, VERSION_PATH)
    print("Versionsdatei aktualisiert.")


if __name__ == "__main__":
    download_new_client()
    download_version_file()
    replace_files()
    print("Update abgeschlossen. Starten Sie den Client manuell neu.")
    # restart_client()  # Commented out to avoid path issues