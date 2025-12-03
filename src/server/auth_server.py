"""Authentication server for user login/register and token validation."""

import json
import socket
import threading
import sqlite3
import sys
import secrets
import time
import hmac
import hashlib
from pathlib import Path
from typing import Dict, Tuple, Optional

from src.common.config import BASE_DIR, CHAT_SERVERS, TOKEN_TTL
from src.common.database import users_conn, users_cur, instances_conn, instances_cur


# Token store: token -> (username, role, expiry)
TOKENS: Dict[str, Tuple[str, str, float]] = {}

# Server version read from version.txt next to script
try:
    SERVER_VERSION = (BASE_DIR / "version.txt").read_text(encoding="utf-8").strip()
except Exception:
    SERVER_VERSION = "0.0"

print(f"[*] Auth server starting (version={SERVER_VERSION})")


class ClientInfo:
    def __init__(self, sock: socket.socket, addr: Tuple[str, int]):
        self.sock = sock
        self.addr = addr
        self.username: Optional[str] = None
        self.role: str = "user"
        self.lock = threading.Lock()

    def send_json(self, obj: dict) -> None:
        try:
            data = json.dumps(obj, ensure_ascii=False) + "\n"
            with self.lock:
                self.sock.sendall(data.encode("utf-8"))
        except Exception:
            pass


def handle_login(obj: dict, client: ClientInfo) -> None:
    username = obj.get("username")
    password = obj.get("password")
    if not username or not password:
        client.send_json({"type": "login_fail", "reason": "missing_fields"})
        return
    users_cur.execute("SELECT password, role, banned FROM users WHERE username=?", (username,))
    row = users_cur.fetchone()
    if not row:
        client.send_json({"type": "login_fail", "reason": "no_user"})
        return
    db_pw, role, banned = row[0], row[1] or "user", bool(row[2])
    if db_pw != password:
        client.send_json({"type": "login_fail", "reason": "bad_password"})
        return
    if banned:
        client.send_json({"type": "banned", "reason": "you_are_banned"})
        return
    # Issue a session token to be used with chat servers.
    token = secrets.token_urlsafe(32)
    expiry = time.time() + TOKEN_TTL
    TOKENS[token] = (username, role, expiry)
    client.send_json({"type": "login_ok", "version": SERVER_VERSION, "role": role, "token": token, "servers": CHAT_SERVERS})
    # Auth server does not keep chat client connections; close after reply
    try:
        client.sock.shutdown(socket.SHUT_RDWR)
    except Exception:
        pass
    try:
        client.sock.close()
    except Exception:
        pass


def handle_register(obj: dict, client: ClientInfo) -> None:
    username = obj.get("username")
    password = obj.get("password")
    if not username or not password:
        client.send_json({"type": "register_fail", "reason": "missing_fields"})
        return
    users_cur.execute("SELECT username FROM users WHERE username=?", (username,))
    if users_cur.fetchone():
        client.send_json({"type": "register_fail", "reason": "exists"})
        return
    users_cur.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
    users_conn.commit()
    client.send_json({"type": "register_ok"})


def handle_validate(obj: dict, client: ClientInfo) -> None:
    """Handle validation requests from chat servers.

    Expected: {"type":"validate", "token": "..."}
    Reply: {"type":"validate_ok","username":"...","role":"..."} or {"type":"validate_fail"}
    """
    token = obj.get("token")
    instance_id = obj.get("instance_id")
    recv_hmac = obj.get("hmac")
    if not token:
        client.send_json({"type": "validate_fail"})
        return

    # look up token
    tup = TOKENS.get(token)
    if not tup:
        client.send_json({"type": "validate_fail"})
        return
    username, role, expiry = tup
    if time.time() > expiry:
        TOKENS.pop(token, None)
        client.send_json({"type": "validate_fail"})
        return

    # If validate is requested by a registered instance, require HMAC
    if instance_id:
        try:
            instances_cur.execute("SELECT secret FROM instances WHERE instance_id=?", (instance_id,))
            row = instances_cur.fetchone()
            if not row:
                client.send_json({"type": "validate_fail"})
                return
            secret = row[0]
            # compute expected HMAC over token:instance_id
            mac = hmac.new(secret.encode("utf-8"), f"{token}:{instance_id}".encode("utf-8"), hashlib.sha256).hexdigest()
            if not recv_hmac or not hmac.compare_digest(mac, recv_hmac):
                client.send_json({"type": "validate_fail"})
                return
        except Exception:
            client.send_json({"type": "validate_fail"})
            return

    # token valid
    client.send_json({"type": "validate_ok", "username": username, "role": role})


def handle_version_check(obj: dict, client: ClientInfo) -> None:
    """Handle version check requests from clients.

    Reply: {"type":"version_ok","version":"..."}
    """
    client.send_json({"type": "version_ok", "version": SERVER_VERSION})
    # allow chat servers to request bans; require instance authentication if instance_id provided
    target = obj.get("target")
    instance_id = obj.get("instance_id")
    recv_hmac = obj.get("hmac")
    if not target:
        client.send_json({"type": "error", "reason": "missing_target"})
        return

    # verify instance if present
    if instance_id:
        try:
            instances_cur.execute("SELECT secret FROM instances WHERE instance_id=?", (instance_id,))
            row = instances_cur.fetchone()
            if not row:
                client.send_json({"type": "error", "reason": "invalid_instance"})
                return
            secret = row[0]
            mac = hmac.new(secret.encode("utf-8"), f"{target}:{instance_id}".encode("utf-8"), hashlib.sha256).hexdigest()
            if not recv_hmac or not hmac.compare_digest(mac, recv_hmac):
                client.send_json({"type": "error", "reason": "not_authorized"})
                return
        except Exception:
            client.send_json({"type": "error", "reason": "server_error"})
            return

    try:
        users_cur.execute("UPDATE users SET banned=1 WHERE username=?", (target,))
        users_conn.commit()
    except Exception:
        pass
    # Note: In auth server, we don't have clients list, so no disconnect
    client.send_json({"type": "ban_ok", "target": target})


def handle_client_connection(sock: socket.socket, addr: Tuple[str, int]) -> None:
    client = ClientInfo(sock, addr)
    print(f"[+] Auth connection from {addr}")
    f = sock.makefile("r", encoding="utf-8", newline="\n")
    try:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except Exception:
                client.send_json({"type": "error", "reason": "invalid_json"})
                continue

            t = obj.get("type")
            if t == "login":
                handle_login(obj, client)
            elif t == "register":
                handle_register(obj, client)
            elif t == "validate":
                handle_validate(obj, client)
            elif t == "ban_user":
                handle_ban_user(obj, client)
            elif t == "version_check":
                handle_version_check(obj, client)
            else:
                client.send_json({"type": "error", "reason": "unknown_type"})

    except Exception:
        pass
    finally:
        try:
            f.close()
        except Exception:
            pass
        try:
            sock.close()
        except Exception:
            pass


def main(host: str = "0.0.0.0", port: int = 9000) -> None:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((host, port))
    s.listen(50)
    print(f"[*] Auth server listening on {host}:{port}")
    try:
        while True:
            try:
                conn, addr = s.accept()
                threading.Thread(target=handle_client_connection, args=(conn, addr), daemon=True).start()
            except OSError:
                break
    finally:
        try:
            s.close()
        except Exception:
            pass


if __name__ == "__main__":
    main()