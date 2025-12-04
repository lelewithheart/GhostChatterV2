"""Configuration constants and paths."""

from pathlib import Path

# Base directory
BASE_DIR = Path(__file__).resolve().parent.parent.parent

# App data directory
BASE_APPDATA = Path.home() / "GhostChat"
BASE_APPDATA.mkdir(parents=True, exist_ok=True)

# Default server settings
# Default host changed to local network IP requested by user
DEFAULT_HOST = "69.9.185.17"
DEFAULT_PORT = 19202

# Token TTL
TOKEN_TTL = 60 * 60  # 1 hour

# Chat servers (can be loaded from DB or config)
CHAT_SERVERS = [
    {"name": "main_chat", "host": "69.9.185.17", "port": 25603},
]