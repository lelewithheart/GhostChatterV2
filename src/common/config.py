"""Configuration constants and paths."""

from pathlib import Path

# Base directory
BASE_DIR = Path(__file__).resolve().parent.parent.parent

# App data directory
BASE_APPDATA = Path.home() / "GhostChat"
BASE_APPDATA.mkdir(parents=True, exist_ok=True)

# Default server settings
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 9000

# Token TTL
TOKEN_TTL = 60 * 60  # 1 hour

# Chat servers (can be loaded from DB or config)
CHAT_SERVERS = [
    {"name": "main_chat", "host": "127.0.0.1", "port": 9001},
]