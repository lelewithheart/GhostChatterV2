"""Network client for chat connections."""

import json
import socket
from pathlib import Path
from typing import Dict, Optional

from src.common.config import BASE_APPDATA
from src.common.crypto import decrypt_message, encrypt_message
from src.common.network import connect_to_server


class ChatClient:
    def __init__(self):
        self.sock: Optional[socket.socket] = None
        self.file = None
        self.username: Optional[str] = None
        self.role: str = "user"
        self.running = False

        # message id -> text widget tag (used by UI)
        self.msg_id_tags: Dict[int, str] = {}

        # DM storage: {username: [ {from, to, message, ts, incoming} ] }
        self.dm_history: Dict[str, list] = {}
        self.recent_contacts: list[str] = []

        self._dm_file = BASE_APPDATA / "dms.json"
        self._load_dms()

        # runtime fields set after login
        self.token: Optional[str] = None
        self.servers: list[dict] = []
        self.dm_window = None  # reference to DM window if open

    # ---- network ------------------------------------------------------------

    def connect(self, host: str, port: int) -> None:
        self.sock = connect_to_server(host, port)
        if self.sock:
            # text-mode file object for reading newline-delimited JSON
            self.file = self.sock.makefile("r", encoding="utf-8", newline="\n")

    def send(self, obj: dict) -> None:
        """Send a JSON object as newline-delimited JSON."""
        if not self.sock:
            return
        data = json.dumps(obj, ensure_ascii=False) + "\n"
        try:
            self.sock.sendall(data.encode("utf-8"))
        except Exception:
            # ignore send errors (caller may close)
            pass

    def close(self) -> None:
        # mark not running and log close reason for debugging
        try:
            import logging
            logging.getLogger("ghostchatter.client").info("ChatClient.close() called")
        except Exception:
            pass
        self.running = False
        try:
            if self.file:
                self.file.close()
        except Exception:
            pass
        try:
            if self.sock:
                self.sock.close()
        except Exception:
            pass
        self.sock = None
        self.file = None

    # ---- DM persistence ----------------------------------------------------

    def _load_dms(self) -> None:
        try:
            if self._dm_file.exists():
                data = json.loads(self._dm_file.read_text(encoding="utf-8"))
                self.dm_history = data.get("dm_history", {})
                self.recent_contacts = data.get("recent_contacts", [])
        except Exception:
            self.dm_history = {}
            self.recent_contacts = []

    def _save_dms(self) -> None:
        try:
            data = {"dm_history": self.dm_history, "recent_contacts": self.recent_contacts}
            self._dm_file.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
        except Exception:
            pass

    def add_dm(self, to_user: str, from_user: str, message: str, incoming: bool = True) -> None:
        """Store a DM entry under the other party's username."""
        other = from_user if incoming else to_user
        entry = {
            "from": from_user,
            "to": to_user,
            "message": message,
            "ts": self._datetime_now(),
            "incoming": incoming,
        }
        self.dm_history.setdefault(other, []).append(entry)

        if other not in self.recent_contacts:
            self.recent_contacts.insert(0, other)
            self.recent_contacts = self.recent_contacts[:50]  # cap recent contacts

        self._save_dms()

    def _datetime_now(self) -> str:
        from datetime import datetime
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")