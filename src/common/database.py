"""Database utilities for users, chat, and instances."""

import sqlite3
from pathlib import Path
from .config import BASE_DIR

# Database paths
USERS_DB = BASE_DIR / "users.db"
CHAT_DB = BASE_DIR / "chat.db"
INSTANCES_DB = BASE_DIR / "instances.db"

# Ensure directories
USERS_DB.parent.mkdir(parents=True, exist_ok=True)
CHAT_DB.parent.mkdir(parents=True, exist_ok=True)
INSTANCES_DB.parent.mkdir(parents=True, exist_ok=True)

# Connections
users_conn = sqlite3.connect(str(USERS_DB), check_same_thread=False)
users_cur = users_conn.cursor()

chat_conn = sqlite3.connect(str(CHAT_DB), check_same_thread=False)
chat_cur = chat_conn.cursor()

instances_conn = sqlite3.connect(str(INSTANCES_DB), check_same_thread=False)
instances_cur = instances_conn.cursor()

# Create tables
users_cur.execute("""
CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    password TEXT NOT NULL,
    role TEXT DEFAULT 'user',
    banned INTEGER DEFAULT 0
)
""")
users_conn.commit()

chat_cur.execute("""
CREATE TABLE IF NOT EXISTS chat (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    message TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
)
""")
chat_conn.commit()

instances_cur.execute("""
CREATE TABLE IF NOT EXISTS instances (
    instance_id TEXT PRIMARY KEY,
    secret TEXT NOT NULL,
    host TEXT,
    port INTEGER,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)
""")
instances_conn.commit()

# Default moderator
try:
    users_cur.execute("SELECT username FROM users WHERE username=?", ("moderator",))
    if not users_cur.fetchone():
        users_cur.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", ("moderator", "modpass", "mod"))
        users_conn.commit()
except Exception:
    pass

def save_chat(username: str, message: str) -> int:
    if not message or not message.strip():
        return 0
    chat_cur.execute("INSERT INTO chat (username, message) VALUES (?, ?)", (username, message))
    chat_conn.commit()
    return chat_cur.lastrowid