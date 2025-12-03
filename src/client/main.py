"""Main entry point for the chat client."""

import sys
from pathlib import Path

# Allow running this file directly
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.client.gui import run_gui

if __name__ == "__main__":
    run_gui()