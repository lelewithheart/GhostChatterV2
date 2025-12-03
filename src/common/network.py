"""Network utilities for TCP connections and JSON messaging."""

import json
import socket
from typing import Any, Dict, Optional, Tuple

def send_json(sock: socket.socket, data: Dict[str, Any]) -> bool:
    """Send JSON data over socket."""
    try:
        message = json.dumps(data).encode('utf-8')
        sock.sendall(message + b'\n')
        return True
    except Exception:
        return False

def receive_json(sock: socket.socket, timeout: float = 5.0) -> Optional[Dict[str, Any]]:
    """Receive JSON data from socket with timeout."""
    try:
        sock.settimeout(timeout)
        buffer = b''
        while True:
            chunk = sock.recv(1024)
            if not chunk:
                return None
            buffer += chunk
            if b'\n' in buffer:
                line, buffer = buffer.split(b'\n', 1)
                return json.loads(line.decode('utf-8'))
    except socket.timeout:
        return None
    except Exception:
        return None

def connect_to_server(host: str, port: int, timeout: float = 5.0) -> Optional[socket.socket]:
    """Connect to server with timeout."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        return sock
    except Exception:
        return None