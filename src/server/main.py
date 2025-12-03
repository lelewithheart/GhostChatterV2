"""Main entry point for the server (auth server)."""

import sys
from pathlib import Path

# Allow running this file directly
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.server.auth_server import main

if __name__ == "__main__":
    main()