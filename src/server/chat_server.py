"""Chat server that validates session tokens with a central auth server."""

import json
import socket
import threading
import sqlite3
import os
import hmac
import hashlib
import argparse
import sys
from pathlib import Path

# Allow running this file directly
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from datetime import datetime
from typing import Tuple, List

from src.common.config import BASE_DIR
from src.common.database import chat_conn, chat_cur
from src.common.network import send_json


# channel-specific moderators stored per-instance
chat_cur.execute(
    """
    CREATE TABLE IF NOT EXISTS channel_mods (
        username TEXT PRIMARY KEY,
        is_mod INTEGER DEFAULT 1
    )
    """
)
chat_conn.commit()

clients: List = []
clients_lock = threading.Lock()
stop_flag = threading.Event()


class ClientInfo:
    def __init__(self, sock: socket.socket, addr: Tuple[str, int]):
        self.sock = sock
        self.addr = addr
        self.username = None
        self.role = "user"
        self.lock = threading.Lock()

    def send_json(self, obj: dict) -> None:
        send_json(self.sock, obj)


def validate_token_with_auth(auth_host: str, auth_port: int, token: str, timeout: float = 3.0):
    # attempt to include instance authentication if available in environment
    instance_id = os.getenv("GHOST_INSTANCE_ID")
    instance_secret = os.getenv("GHOST_INSTANCE_SECRET")
    try:
        s = socket.create_connection((auth_host, auth_port), timeout=timeout)
        f = s.makefile("r", encoding="utf-8", newline="\n")
        req = {"type": "validate", "token": token}
        if instance_id and instance_secret:
            mac = hmac.new(instance_secret.encode("utf-8"), f"{token}:{instance_id}".encode("utf-8"), hashlib.sha256).hexdigest()
            req["instance_id"] = instance_id
            req["hmac"] = mac
        send_json(s, req)
        line = f.readline()
        if not line:
            return None
        resp = json.loads(line)
        if resp.get("type") == "validate_ok":
            return {"username": resp.get("username"), "role": resp.get("role")}
        return None
    except Exception:
        return None
    finally:
        try:
            s.close()
        except Exception:
            pass


def save_chat(username: str, message: str) -> int:
    if not message or not message.strip():
        return 0
    chat_cur.execute("INSERT INTO chat (username, message) VALUES (?, ?)", (username, message))
    chat_conn.commit()
    return chat_cur.lastrowid


def broadcast(obj: dict, exclude=None) -> None:
    with clients_lock:
        for c in list(clients):
            if exclude and c.sock == exclude:
                continue
            c.send_json(obj)


def handle_client(conn: socket.socket, addr: Tuple[str, int], auth_host: str, auth_port: int):
    ci = ClientInfo(conn, addr)
    print(f"[+] Chat connection from {addr}")
    f = conn.makefile("r", encoding="utf-8", newline="\n")
    try:
        # expect a token_login as first message
        line = f.readline()
        if not line:
            conn.close()
            return
        try:
            obj = json.loads(line)
        except Exception:
            conn.close()
            return
        if obj.get("type") != "token_login":
            conn.close()
            return
        token = obj.get("token")
        res = validate_token_with_auth(auth_host, auth_port, token)
        if not res:
            ci.send_json({"type": "login_fail", "reason": "invalid_token"})
            conn.close()
            return
        # token valid
        ci.username = res.get("username")
        # role from auth server (global) or channel-specific override
        auth_role = res.get("role", "user")
        # check local channel_mods table for channel-level moderator rights
        try:
            chat_cur.execute("SELECT is_mod FROM channel_mods WHERE username=?", (ci.username,))
            row = chat_cur.fetchone()
            if row and int(row[0]):
                ci.role = "mod"
            else:
                ci.role = auth_role
        except Exception:
            ci.role = auth_role
        ci.send_json({"type": "login_ok", "role": ci.role})
        with clients_lock:
            clients.append(ci)
        # send history
        chat_cur.execute("SELECT id, username, message, timestamp FROM chat ORDER BY id ASC")
        for mid, uname, msg, ts in chat_cur.fetchall():
            ci.send_json({"type": "history", "id": mid, "username": uname, "message": msg, "timestamp": ts})

        # main loop
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except Exception:
                continue
            t = obj.get("type")
            if t == "message":
                msg = obj.get("message", "")
                if msg.startswith("/"):
                    # Handle commands
                    parts = msg[1:].split()
                    if not parts:
                        continue
                    cmd = parts[0].lower()
                    if cmd in ["cv", "change_version"]:
                        if len(parts) < 2:
                            ci.send_json({"type": "error", "reason": "usage: /cv <new_version>"})
                            continue
                        new_version = parts[1]
                        if send_change_version_to_auth(new_version, auth_host, auth_port):
                            ci.send_json({"type": "info", "message": f"Version changed to {new_version}"})
                        else:
                            ci.send_json({"type": "error", "reason": "Failed to change version"})
                    elif ci.role == "mod":
                        if cmd == "delete":
                            if len(parts) < 2:
                                ci.send_json({"type": "error", "reason": "usage: /delete <message_id>"})
                                continue
                            try:
                                mid = int(parts[1])
                                chat_cur.execute("DELETE FROM chat WHERE id=?", (mid,))
                                chat_conn.commit()
                                broadcast({"type": "delete", "id": mid})
                            except Exception:
                                ci.send_json({"type": "error", "reason": "Invalid message ID"})
                        elif cmd == "warn":
                            if len(parts) < 3:
                                ci.send_json({"type": "error", "reason": "usage: /warn <user> <reason>"})
                                continue
                            target = parts[1]
                            reason = " ".join(parts[2:])
                            with clients_lock:
                                for c in clients:
                                    if c.username == target:
                                        c.send_json({"type": "warn", "from": ci.username, "reason": reason})
                                        break
                        elif cmd == "ban":
                            if len(parts) < 2:
                                ci.send_json({"type": "error", "reason": "usage: /ban <user>"})
                                continue
                            target = parts[1]
                            if send_ban_to_auth(target, auth_host, auth_port):
                                with clients_lock:
                                    for c in list(clients):
                                        if c.username == target:
                                            c.send_json({"type": "banned", "reason": "You were banned by a moderator"})
                                            try:
                                                c.sock.shutdown(socket.SHUT_RDWR)
                                                c.sock.close()
                                            except Exception:
                                                pass
                            else:
                                ci.send_json({"type": "error", "reason": "Failed to ban user"})
                        else:
                            ci.send_json({"type": "error", "reason": "Unknown command"})
                    else:
                        ci.send_json({"type": "error", "reason": "Unknown command or insufficient permissions"})
                else:
                    # Regular message
                    mid = save_chat(ci.username, msg)
                    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    pkt = {"type": "message", "id": mid, "username": ci.username, "message": msg, "timestamp": now}
                    broadcast(pkt)
            elif t == "pm":
                target = obj.get("to")
                msg = obj.get("message", "")
                with clients_lock:
                    for c in clients:
                        if c.username == target:
                            c.send_json({"type": "pm", "from": ci.username, "message": msg})
                            break
            elif t == "mod":
                action = obj.get("action")
                if ci.role != "mod":
                    ci.send_json({"type": "error", "reason": "not_authorized"})
                    continue
                if action == "delete":
                    mid = obj.get("id")
                    try:
                        chat_cur.execute("DELETE FROM chat WHERE id=?", (mid,))
                        chat_conn.commit()
                    except Exception:
                        pass
                    broadcast({"type": "delete", "id": mid})
                elif action == "warn":
                    target = obj.get("target")
                    reason = obj.get("reason", "")
                    with clients_lock:
                        for c in clients:
                            if c.username == target:
                                c.send_json({"type": "warn", "from": ci.username, "reason": reason})
                                break
                elif action == "ban":
                    target = obj.get("target")
                    # No user DB here; chat-server asks auth server to ban instead
                    try:
                        # send a ban request to auth server, include instance HMAC if available
                        instance_id = os.getenv("GHOST_INSTANCE_ID")
                        instance_secret = os.getenv("GHOST_INSTANCE_SECRET")
                        req = {"type": "ban_user", "target": target}
                        if instance_id and instance_secret:
                            mac = hmac.new(instance_secret.encode("utf-8"), f"{target}:{instance_id}".encode("utf-8"), hashlib.sha256).hexdigest()
                            req["instance_id"] = instance_id
                            req["hmac"] = mac
                        s = socket.create_connection((auth_host, auth_port), timeout=3.0)
                        send_json(s, req)
                        s.close()
                    except Exception:
                        pass
                    with clients_lock:
                        for c in list(clients):
                            if c.username == target:
                                c.send_json({"type": "banned", "reason": "You were banned by a moderator"})
                                try:
                                    c.sock.shutdown(socket.SHUT_RDWR)
                                    c.sock.close()
                                except Exception:
                                    pass

    finally:
        try:
            f.close()
        except Exception:
            pass
        with clients_lock:
            clients[:] = [c for c in clients if c.sock != conn]
        try:
            conn.close()
        except Exception:
            pass


def send_change_version_to_auth(new_version: str, auth_host: str, auth_port: int) -> bool:
    """Send a change_version request to auth server, including instance HMAC if available."""
    try:
        instance_id = os.getenv("GHOST_INSTANCE_ID")
        instance_secret = os.getenv("GHOST_INSTANCE_SECRET")
        req = {"type": "change_version", "version": new_version}
        if instance_id and instance_secret:
            mac = hmac.new(instance_secret.encode("utf-8"), f"{new_version}:{instance_id}".encode("utf-8"), hashlib.sha256).hexdigest()
            req["instance_id"] = instance_id
            req["hmac"] = mac
        s = socket.create_connection((auth_host, auth_port), timeout=3.0)
        send_json(s, req)
        try:
            s.close()
        except Exception:
            pass
        return True
    except Exception:
        return False


def main(host: str = "0.0.0.0", port: int = 9001, auth_host: str = "127.0.0.1", auth_port: int = 9000):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((host, port))
    s.listen(50)
    print(f"[*] Chat server listening on {host}:{port} (auth={auth_host}:{auth_port})")
    try:
        while not stop_flag.is_set():
            try:
                conn, addr = s.accept()
                threading.Thread(target=handle_client, args=(conn, addr, auth_host, auth_port), daemon=True).start()
            except OSError:
                break
    finally:
        try:
            s.close()
        except Exception:
            pass


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Chat server that validates tokens with auth server")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=9001)
    parser.add_argument("--auth-host", default="127.0.0.1")
    parser.add_argument("--auth-port", type=int, default=9000)
    parser.add_argument("--instance-id", help="Instance ID to present to auth server")
    parser.add_argument("--instance-secret", help="Instance secret for HMAC")
    args = parser.parse_args()
    # Honor CLI-provided instance credentials by setting env vars used by validate/ban
    if args.instance_id:
        os.environ["GHOST_INSTANCE_ID"] = args.instance_id
    if args.instance_secret:
        os.environ["GHOST_INSTANCE_SECRET"] = args.instance_secret
    main(host=args.host, port=args.port, auth_host=args.auth_host, auth_port=args.auth_port)