"""GUI components for the chat client using PyQt6."""

import datetime
import json
import subprocess
import sys
import threading
from pathlib import Path
from typing import Dict, Optional

# Allow running this file directly
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QTextEdit, QMessageBox, QInputDialog, QListWidget,
    QListWidgetItem, QTabWidget, QFrame, QSplitter
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt6.QtGui import QFont, QAction

from common.config import BASE_APPDATA, DEFAULT_HOST, DEFAULT_PORT
from common.network import connect_to_server, receive_json, send_json
from client.network import ChatClient

# Single client instance
client = ChatClient()


def datetime_now() -> str:
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def run_gui():
    """Start the application: show login/register window."""
    app = QApplication(sys.argv)
    login_win = LoginWindow()
    login_win.show()
    sys.exit(app.exec())


class LoginWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Login / Register")
        self.setFixedSize(320, 260)
        
        self.is_register_mode = False
        self.pw_confirm_label: Optional[QLabel] = None
        self.pw_confirm_entry: Optional[QLineEdit] = None
        self.menu: Optional[PostLoginMenu] = None
        
        self.setup_ui()
        
    def _set_login_mode(self):
        self.is_register_mode = False
        layout = self.layout()
        
        if self.pw_confirm_label is not None:
            layout.removeWidget(self.pw_confirm_label)
            self.pw_confirm_label.deleteLater()
            self.pw_confirm_label = None
            
        if self.pw_confirm_entry is not None:
            layout.removeWidget(self.pw_confirm_entry)
            self.pw_confirm_entry.deleteLater()
            self.pw_confirm_entry = None
            
        self.btn_register.setText("Register")
        self.btn_login.setText("Login")
        
    def _set_register_mode(self):
        self.is_register_mode = True
        layout = self.layout()
        
        self.pw_confirm_label = QLabel("Confirm Password:")
        self.pw_confirm_entry = QLineEdit()
        self.pw_confirm_entry.setEchoMode(QLineEdit.EchoMode.Password)
        
        layout.insertWidget(4, self.pw_confirm_label)
        layout.insertWidget(5, self.pw_confirm_entry)

        self.btn_register.setText("Back to Login")
        self.btn_login.setText("Register")


    def setup_ui(self):
        layout = QVBoxLayout()

        layout.addWidget(QLabel("Username:"))
        self.user_entry = QLineEdit()
        layout.addWidget(self.user_entry)

        layout.addWidget(QLabel("Password:"))
        self.pw_entry = QLineEdit()
        self.pw_entry.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addWidget(self.pw_entry)

        self.pw_confirm_entry = None
        self.msg_label = QLabel("")
        self.msg_label.setStyleSheet("color: red;")
        layout.addWidget(self.msg_label)

        btn_layout = QHBoxLayout()
        self.btn_login = QPushButton("Login")
        self.btn_login.clicked.connect(self.do_connect)
        btn_layout.addWidget(self.btn_login)

        self.btn_register = QPushButton("Register")
        self.btn_register.clicked.connect(self.toggle_register)
        btn_layout.addWidget(self.btn_register)

        layout.addLayout(btn_layout)
        self.setLayout(layout)

    def _norm_version(self, v: Optional[str]) -> str:
        import re
        return re.sub(r"[^0-9.]", "", (v or ""))

    def attempt_connect_and_register(self, username: str, password: str) -> bool:
        sock = connect_to_server(DEFAULT_HOST, DEFAULT_PORT)
        if not sock:
            self.msg_label.setText("Verbindung fehlgeschlagen")
            return False

        send_json(sock, {"type": "register", "username": username, "password": password})
        resp = receive_json(sock)
        sock.close()

        if resp and resp.get("type") == "register_ok":
            QMessageBox.information(self, "Erfolg", "Registrierung erfolgreich. Bitte einloggen.")
            return True
        else:
            reason = resp.get("reason", "register_failed") if resp else "Keine Antwort"
            self.msg_label.setText(reason)
            return False

    def attempt_connect_and_login(self, username: str, password: str):
        sock = connect_to_server(DEFAULT_HOST, DEFAULT_PORT)
        if not sock:
            self.msg_label.setText("Verbindung fehlgeschlagen")
            return

        send_json(sock, {"type": "login", "username": username, "password": password})
        resp = receive_json(sock)
        sock.close()

        if resp and resp.get("type") == "login_ok":
            server_version = resp.get("version")
            token = resp.get("token")
            servers = resp.get("servers") or []
            role = resp.get("role", "user")

            try:
                if getattr(sys, "frozen", False):
                    base_dir = Path(sys.executable).parent
                else:
                    base_dir = Path(__file__).resolve().parent.parent.parent
                local_version = (base_dir / "version.txt").read_text(encoding="utf-8").strip()
            except Exception:
                local_version = "0.0"

            # set client runtime fields ALWAYS on successful login
            client.token = token
            client.servers = servers
            client.role = role
            client.username = username

            # if version mismatch → show update dialog instead of going to menu
            if server_version and self._norm_version(server_version) != self._norm_version(local_version):
                self.show_update_dialog(server_version, local_version, username, token, servers, role)
                return

            # normal path: open menu, keep reference, hide login window
            self.menu = PostLoginMenu(username, token, servers, role)
            self.menu.show()
            self.hide()
        else:
            self.msg_label.setText(resp.get("reason", "login_failed") if resp else "Keine Antwort")
    
    def show_update_dialog(self, server_version, local_version, username, token, servers, role):
        update_win = QWidget()
        update_win.setWindowTitle("Update notwendig")
        update_win.setFixedSize(300, 150)

        layout = QVBoxLayout()
        layout.addWidget(QLabel(f"Deine Version: {local_version}\nServer-Version: {server_version}\n\nBitte updaten!"))

        btn_layout = QHBoxLayout()
        btn_update = QPushButton("Update starten")
        btn_update.clicked.connect(lambda: self.run_updater(update_win))
        btn_layout.addWidget(btn_update)

        btn_connect = QPushButton("Trotzdem verbinden")
        def _connect_anyway():
            update_win.close()
            # open menu and hide login; keep reference
            self.menu = PostLoginMenu(username, token, servers, role)
            self.menu.show()
            self.hide()
        btn_connect.clicked.connect(_connect_anyway)
        btn_layout.addWidget(btn_connect)

        layout.addLayout(btn_layout)
        update_win.setLayout(layout)
        update_win.show()

    def run_updater(self, win):
        try:
            if getattr(sys, "frozen", False):
                base = Path(sys.executable).parent
            else:
                base = Path(__file__).resolve().parent.parent.parent
            updater_exe = base / "Updater.exe"
            if not updater_exe.exists():
                import shutil
                if shutil.which("Updater.exe"):
                    cmd = ["Updater.exe"]
                else:
                    QMessageBox.critical(self, "Fehler", f"Updater.exe nicht gefunden im {base}")
                    return
            else:
                cmd = [str(updater_exe)]
            subprocess.Popen(cmd)
        except FileNotFoundError:
            QMessageBox.critical(self, "Fehler", "Updater.exe nicht gefunden!")
        finally:
            try:
                client.close()
            except Exception:
                pass
            sys.exit(0)

    def do_connect(self):
        username = self.user_entry.text().strip()
        password = self.pw_entry.text().strip()
        if not username or not password:
            self.msg_label.setText("Bitte Benutzername und Passwort eingeben")
            return

        if self.is_register_mode:
            if not self.pw_confirm_entry:
                self.msg_label.setText("Bestätigungskennwort fehlt.")
                return
            confirm_pw = self.pw_confirm_entry.text().strip()
            if password != confirm_pw:
                self.msg_label.setText("Passwörter stimmen nicht überein")
                return
            if self.attempt_connect_and_register(username, password):
                self.user_entry.clear()
                self.pw_entry.clear()
                self._set_login_mode()
                self.msg_label.setText("Registrierung erfolgreich. Bitte einloggen.")
                self.msg_label.setStyleSheet("color: green;")
            return

        self.attempt_connect_and_login(username, password)

    def toggle_register(self):
        if self.is_register_mode:
            self._set_login_mode()
        else:
            self._set_register_mode()


class PostLoginMenu(QWidget):
    def __init__(self, username: str, token: str, servers: list, role: str):
        super().__init__()
        self.username = username
        self.token = token
        self.servers = servers
        self.role = role
        self.setWindowTitle("Wähle Chat-Modus")
        self.setFixedSize(360, 200)
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout()
        layout.addWidget(QLabel(f"Angemeldet als: {self.username} ({self.role})"))

        btn_layout = QVBoxLayout()
        btn_global = QPushButton("Global Chat")
        btn_global.clicked.connect(self.do_global)
        btn_layout.addWidget(btn_global)

        btn_ip = QPushButton("Verbinden (IP/Port)")
        btn_ip.clicked.connect(self.do_connect_ip)
        btn_layout.addWidget(btn_ip)

        btn_dms = QPushButton("DMs")
        btn_dms.clicked.connect(self.do_dms)
        btn_layout.addWidget(btn_dms)

        layout.addLayout(btn_layout)
        self.setLayout(layout)

    def do_global(self):
        connected = False
        for srv in self.servers:
            try:
                host = srv.get("host")
                port = int(srv.get("port"))
            except Exception:
                continue
            sock = connect_to_server(host, port)
            if not sock:
                continue
            send_json(sock, {"type": "token_login", "token": self.token})
            resp = receive_json(sock)
            if resp and resp.get("type") in ("login_ok", "validate_ok"):
                client.username = self.username
                client.role = resp.get("role", self.role)
                client.sock = sock
                client.file = sock.makefile("r", encoding="utf-8", newline="\n")
                connected = True
                break
            else:
                sock.close()

        if not connected:
            QMessageBox.critical(self, "Verbindung", "Kein erreichbarer Chat-Server gefunden")
            return

        self.close()
        show_chat_window()

    def do_connect_ip(self):
        ip_win = QWidget()
        ip_win.setWindowTitle("Verbinden zu IP/Port")
        ip_win.setFixedSize(300, 150)

        layout = QVBoxLayout()
        layout.addWidget(QLabel("Host:"))
        host_entry = QLineEdit("10.0.29.119")
        layout.addWidget(host_entry)

        layout.addWidget(QLabel("Port:"))
        port_entry = QLineEdit("9001")
        layout.addWidget(port_entry)

        btn = QPushButton("Verbinden")
        btn.clicked.connect(lambda: self.connect_ip(host_entry.text().strip(), port_entry.text().strip(), ip_win))
        layout.addWidget(btn)

        ip_win.setLayout(layout)
        ip_win.show()

    def connect_ip(self, host, port_str, win):
        try:
            port = int(port_str)
        except ValueError:
            QMessageBox.critical(self, "Fehler", "Ungültiger Port")
            return
        sock = connect_to_server(host, port)
        if not sock:
            QMessageBox.critical(self, "Verbindung", "Verbindung fehlgeschlagen")
            return
        send_json(sock, {"type": "token_login", "token": self.token})
        resp = receive_json(sock)
        if resp and resp.get("type") in ("login_ok", "validate_ok"):
            client.username = self.username
            client.role = resp.get("role", self.role)
            client.sock = sock
            client.file = sock.makefile("r", encoding="utf-8", newline="\n")
            win.close()
            self.close()
            show_chat_window()
        else:
            sock.close()
            QMessageBox.critical(self, "Login", "Login fehlgeschlagen")

    def do_dms(self):
        if not self.connect_to_global():
            return
        self.close()
        show_dm_window()

    def connect_to_global(self):
        if client.sock:
            return True
        connected = False
        for srv in self.servers:
            try:
                host = srv.get("host")
                port = int(srv.get("port"))
            except Exception:
                continue
            sock = connect_to_server(host, port)
            if not sock:
                continue
            send_json(sock, {"type": "token_login", "token": self.token})
            resp = receive_json(sock)
            if resp and resp.get("type") in ("login_ok", "validate_ok"):
                client.username = self.username
                client.role = resp.get("role", self.role)
                client.sock = sock
                client.file = sock.makefile("r", encoding="utf-8", newline="\n")
                connected = True
                break
            else:
                sock.close()
        if not connected:
            QMessageBox.critical(self, "Verbindung", "Kein erreichbarer Chat-Server gefunden")
            return False
        return True


def show_post_login_menu(username: str, token: str, servers: list, role: str):
    menu = PostLoginMenu(username, token, servers, role)
    menu.show()


class ChatWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"GhostChatter - {client.username} ({client.role})")
        self.resize(900, 700)
        self.mid_to_tag = {}
        self.setup_ui()
        self.start_network_thread()

    def setup_ui(self):
        layout = QVBoxLayout()

        back_frame = QHBoxLayout()
        back_btn = QPushButton("Back to Menu")
        back_btn.clicked.connect(self.back_to_menu)
        back_frame.addStretch()
        back_frame.addWidget(back_btn)
        layout.addLayout(back_frame)

        self.txt = QTextEdit()
        self.txt.setReadOnly(True)
        layout.addWidget(self.txt)

        entry_frame = QHBoxLayout()
        self.entry = QLineEdit()
        self.entry.returnPressed.connect(self.on_send)
        entry_frame.addWidget(self.entry)

        send_btn = QPushButton("Send")
        send_btn.clicked.connect(self.on_send)
        entry_frame.addWidget(send_btn)

        layout.addLayout(entry_frame)
        self.setLayout(layout)

    def append_message(self, mid: int, username: str, message: str, timestamp: str):
        tag = f"mid_{mid}"
        self.mid_to_tag[mid] = tag
        self.txt.append(f"[{timestamp}] {username}: {message}")
        # For moderation, we can add context menu later

    def delete_message(self, mid: int):
        # PyQt6 QTextEdit doesn't have easy tag deletion, so this is simplified
        pass

    def on_send(self):
        txt_msg = self.entry.text().strip()
        if not txt_msg:
            return
        if not client.sock:
            QMessageBox.information(self, "Nicht verbunden", "Bitte zuerst mit einem Chat-Server verbinden.")
            return
        try:
            if txt_msg.startswith("/pm ") or txt_msg.startswith("/msg "):
                try:
                    _, to_user, pm_msg = txt_msg.split(" ", 2)
                    client.send({"type": "pm", "to": to_user, "message": pm_msg})
                except Exception:
                    QMessageBox.information(self, "PM Syntax", "Verwendung: /pm username Nachricht")
            else:
                client.send({"type": "message", "message": txt_msg})
            self.entry.clear()
        except Exception as e:
            QMessageBox.critical(self, "Send Error", f"Fehler beim Senden: {e}")

    def start_network_thread(self):
        def network_loop():
            client.running = True
            try:
                while client.running and client.file:
                    try:
                        line = client.file.readline()
                    except Exception:
                        break
                    if not line:
                        break
                    try:
                        obj = json.loads(line)
                    except Exception:
                        continue

                    t = obj.get("type")
                    if t in ("history", "message"):
                        mid = int(obj.get("id", 0) or 0)
                        uname = obj.get("username", "")
                        msg = obj.get("message", "")
                        ts = obj.get("timestamp", datetime_now())
                        QTimer.singleShot(0, lambda: self.append_message(mid, uname, msg, ts))

                    elif t == "pm":
                        frm = obj.get("from")
                        msg = obj.get("message")
                        client.add_dm(to_user=client.username or "", from_user=frm, message=msg, incoming=True)
                        QTimer.singleShot(0, lambda: QMessageBox.information(self, "Private Nachricht", f"Von {frm}: {msg}"))

                    elif t == "warn":
                        frm = obj.get("from")
                        reason = obj.get("reason", "")
                        QTimer.singleShot(0, lambda: QMessageBox.warning(self, "Warn", f"Moderator {frm} warns: {reason}"))

                    elif t == "delete":
                        mid = obj.get("id")
                        QTimer.singleShot(0, lambda: self.delete_message(int(mid)))

                    elif t == "banned":
                        reason = obj.get("reason", "")
                        QTimer.singleShot(0, lambda: (QMessageBox.critical(self, "Banned", f"You were banned: {reason}"), client.close(), self.close()))

                    elif t == "ban":
                        target = obj.get("target")
                        QTimer.singleShot(0, lambda: self.append_message(0, "*system*", f"User {target} was banned by a moderator", datetime_now()))

            finally:
                client.close()

        threading.Thread(target=network_loop, daemon=True).start()

    def back_to_menu(self):
        self.close()
        show_post_login_menu(client.username or "", client.token or "", client.servers or [], client.role)


def show_chat_window():
    win = ChatWindow()
    win.show()


class DMWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Direct Messages")
        self.resize(900, 600)
        self.dm_tabs = {}
        self.setup_ui()

    def setup_ui(self):
        layout = QHBoxLayout()

        left = QVBoxLayout()
        left.addWidget(QLabel("Recent Contacts"))
        self.contacts_lb = QListWidget()
        self.contacts_lb.itemDoubleClicked.connect(self.open_contact)
        left.addWidget(self.contacts_lb)

        layout.addLayout(left)

        self.nb = QTabWidget()
        layout.addWidget(self.nb)

        back_btn = QPushButton("Back to Menu")
        back_btn.clicked.connect(self.back_to_menu)
        left.addWidget(back_btn)

        self.setLayout(layout)
        self.refresh_contacts()

    def refresh_contacts(self):
        self.contacts_lb.clear()
        for c in client.recent_contacts:
            self.contacts_lb.addItem(QListWidgetItem(c))

    def open_contact(self, item):
        other = item.text()
        if other in self.dm_tabs:
            self.nb.setCurrentWidget(self.dm_tabs[other])
            return

        tab = QWidget()
        self.nb.addTab(tab, other)
        self.dm_tabs[other] = tab

        layout = QVBoxLayout()
        txt = QTextEdit()
        txt.setReadOnly(True)
        layout.addWidget(txt)

        for e in client.dm_history.get(other, []):
            txt.append(f"[{e.get('ts')}] {e.get('from')}: {e.get('message')}")

        entry_frame = QHBoxLayout()
        msg_entry = QLineEdit()
        msg_entry.returnPressed.connect(lambda: self.send_dm(other, msg_entry, txt))
        entry_frame.addWidget(msg_entry)

        send_btn = QPushButton("Send")
        send_btn.clicked.connect(lambda: self.send_dm(other, msg_entry, txt))
        entry_frame.addWidget(send_btn)

        layout.addLayout(entry_frame)
        tab.setLayout(layout)

    def send_dm(self, to_user, entry, txt):
        txt_msg = entry.text().strip()
        if not txt_msg:
            return
        client.send({"type": "pm", "to": to_user, "message": txt_msg})
        client.add_dm(to_user=to_user, from_user=client.username or "", message=txt_msg, incoming=False)
        txt.append(f"[{datetime_now()}] me: {txt_msg}")
        entry.clear()
        self.refresh_contacts()

    def append_dm(self, from_user, text):
        if from_user in self.dm_tabs:
            tab = self.dm_tabs[from_user]
            txt = tab.findChild(QTextEdit)
            if txt:
                txt.append(f"[{datetime_now()}] {from_user}: {text}")
        else:
            self.open_contact(QListWidgetItem(from_user))
            if from_user in self.dm_tabs:
                tab = self.dm_tabs[from_user]
                txt = tab.findChild(QTextEdit)
                if txt:
                    txt.append(f"[{datetime_now()}] {from_user}: {text}")
            else:
                QMessageBox.information(self, "Neue Nachricht", f"Von {from_user}: {text}")
        self.refresh_contacts()

    def back_to_menu(self):
        self.close()
        show_post_login_menu(client.username or "", client.token or "", client.servers or [], client.role)


def show_dm_window():
    dm_win = DMWindow()
    dm_win.show()