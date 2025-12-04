"""GUI components for the chat client."""

import datetime
import json
import subprocess
import sys
import threading
import tkinter as tk
from tkinter import messagebox, simpledialog
from tkinter import ttk
from pathlib import Path
from typing import Dict, Optional

from src.common.config import BASE_APPDATA, DEFAULT_HOST, DEFAULT_PORT
from src.common.network import connect_to_server, receive_json, send_json
from src.client.network import ChatClient

# Single client instance
client = ChatClient()


def datetime_now() -> str:
    from datetime import datetime
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def run_gui():
    """Start the application: show login/register window."""
    root = tk.Tk()
    root.title("Login / Register")
    root.geometry("320x260")
    root.protocol("WM_DELETE_WINDOW", lambda: sys.exit(0))

    tk.Label(root, text="Username:").pack(pady=(12, 0))
    user_entry = tk.Entry(root)
    user_entry.pack(fill="x", padx=12)

    tk.Label(root, text="Password:").pack(pady=(8, 0))
    pw_entry = tk.Entry(root, show="*")
    pw_entry.pack(fill="x", padx=12)

    # Confirm password entry for registration flow (created on demand)
    pw_confirm_entry: Optional[tk.Entry] = None

    msg = tk.Label(root, text="", fg="red")
    msg.pack(pady=8)

    def _norm_version(v: Optional[str]) -> str:
        import re
        return re.sub(r"[^0-9.]", "", (v or ""))

    def attempt_connect_and_register(username: str, password: str) -> bool:
        """Connect to bootstrap server and perform registration request."""
        sock = connect_to_server(DEFAULT_HOST, DEFAULT_PORT)
        if not sock:
            msg.config(text="Verbindung fehlgeschlagen")
            return False

        send_json(sock, {"type": "register", "username": username, "password": password})
        resp = receive_json(sock)
        sock.close()

        if resp and resp.get("type") == "register_ok":
            messagebox.showinfo("Erfolg", "Registrierung erfolgreich. Bitte einloggen.")
            return True
        else:
            reason = resp.get("reason", "register_failed") if resp else "Keine Antwort"
            msg.config(text=reason)
            return False

    def attempt_connect_and_login(username: str, password: str):
        """Connect to bootstrap server and perform login request."""
        sock = connect_to_server(DEFAULT_HOST, DEFAULT_PORT)
        if not sock:
            msg.config(text="Verbindung fehlgeschlagen")
            return

        send_json(sock, {"type": "login", "username": username, "password": password})
        resp = receive_json(sock)
        sock.close()

        if resp and resp.get("type") == "login_ok":
            server_version = resp.get("version")
            token = resp.get("token")
            servers = resp.get("servers") or []
            role = resp.get("role", "user")

            # try reading local version file (optional)
            try:
                if getattr(sys, "frozen", False):
                    base_dir = Path(sys.executable).parent
                else:
                    base_dir = Path(__file__).resolve().parent.parent.parent
                local_version = (base_dir / "version.txt").read_text(encoding="utf-8").strip()
            except Exception:
                local_version = "0.0"

            # if versions mismatch and server provided version, show update dialog
            if server_version and _norm_version(server_version) and _norm_version(server_version) != _norm_version(local_version):
                # set client runtime fields before showing post-login menu
                client.token = token
                client.servers = servers
                client.role = role
                client.username = username

                # open post-login menu and then show update modal
                root.destroy()
                show_post_login_menu(None, username, token, servers, role)

                def run_updater():
                    try:
                        if getattr(sys, "frozen", False):
                            base = Path(sys.executable).parent
                        else:
                            base = Path(__file__).resolve().parent.parent.parent
                        updater_exe = base / "Updater.exe"
                        if not updater_exe.exists():
                            # fallback to PATH
                            import shutil
                            if shutil.which("Updater.exe"):
                                cmd = ["Updater.exe"]
                            else:
                                messagebox.showerror("Fehler", f"Updater.exe nicht gefunden im {base}")
                                return
                        else:
                            cmd = [str(updater_exe)]
                        subprocess.Popen(cmd)
                    except FileNotFoundError:
                        messagebox.showerror("Fehler", "Updater.exe nicht gefunden!")
                    finally:
                        try:
                            client.close()
                        except Exception:
                            pass
                        sys.exit(0)

                def connect_anyway():
                    try:
                        update_win.destroy()
                    except Exception:
                        pass

                update_win = tk.Toplevel()
                update_win.title("Update notwendig")
                tk.Label(
                    update_win,
                    text=f"Deine Version: {local_version}\nServer-Version: {server_version}\n\nBitte updaten!",
                    font=("Segoe UI", 12),
                ).pack(padx=20, pady=20)

                btn_frame_u = tk.Frame(update_win)
                btn_frame_u.pack(pady=10)

                tk.Button(
                    btn_frame_u,
                    text="Update starten",
                    command=run_updater,
                    font=("Segoe UI", 12, "bold"),
                    bg="#4f8cff",
                    fg="white",
                    padx=8,
                    pady=6,
                ).pack(side="left", padx=6)

                tk.Button(
                    btn_frame_u,
                    text="Trotzdem verbinden",
                    command=connect_anyway,
                    font=("Segoe UI", 12),
                    bg="#e0e7ef",
                    fg="#333",
                    padx=8,
                    pady=6,
                ).pack(side="left", padx=6)

                update_win.protocol("WM_DELETE_WINDOW", run_updater)
                return

            # normal login flow
            root.withdraw()  # Hide the login window instead of destroying it
            show_post_login_menu(root, username, token, servers, role)
        else:
            msg.config(text=resp.get("reason", "login_failed") if resp else "Keine Antwort")

    def do_connect(is_register: bool = False):
        nonlocal pw_confirm_entry
        username = user_entry.get().strip()
        password = pw_entry.get().strip()
        if not username or not password:
            msg.config(text="Bitte Benutzername und Passwort eingeben")
            return

        if is_register:
            if not pw_confirm_entry:
                msg.config(text="Bestätigungskennwort fehlt.")
                return
            confirm_pw = pw_confirm_entry.get().strip()
            if password != confirm_pw:
                msg.config(text="Passwörter stimmen nicht überein")
                return
            # perform register sequence (connect -> register)
            if attempt_connect_and_register(username, password):
                # successful registration prompts the user to login
                user_entry.delete(0, "end")
                pw_entry.delete(0, "end")
                if pw_confirm_entry:
                    pw_confirm_entry.destroy()
                    pw_confirm_entry = None
                    btn_register.config(text="Register")
                msg.config(text="Registrierung erfolgreich. Bitte einloggen.", fg="green")
            return

        # login sequence
        attempt_connect_and_login(username, password)

    def toggle_register():
        nonlocal pw_confirm_entry
        if pw_confirm_entry:
            pw_confirm_entry.destroy()
            pw_confirm_entry = None
            btn_register.config(text="Register")
            btn_login.config(text="Login", command=lambda: do_connect(False))
        else:
            tk.Label(root, text="Confirm Password:").pack(pady=(6, 0))
            pw_confirm_entry = tk.Entry(root, show="*")
            pw_confirm_entry.pack(fill="x", padx=12)
            pw_confirm_entry.bind("<Return>", _on_enter)
            btn_register.config(text="Back to Login")
            btn_login.config(text="Register", command=lambda: do_connect(True))

    # Buttons
    btn_frame = tk.Frame(root)
    btn_frame.pack(pady=10)
    btn_login = tk.Button(btn_frame, text="Login", command=lambda: do_connect(False))
    btn_login.pack(side="left", padx=6)
    btn_register = tk.Button(btn_frame, text="Register", command=toggle_register)
    btn_register.pack(side="left", padx=6)

    # Convenience: Enter triggers the current login/register action
    def _on_enter(event=None):
        btn_login.invoke()

    user_entry.bind("<Return>", _on_enter)
    pw_entry.bind("<Return>", _on_enter)

    root.mainloop()


def show_post_login_menu(root_window, username: str, token: str, servers: list, role: str):
    """After a successful login (or when versions mismatched), let the user choose how to connect to actual chat server."""
    menu = tk.Toplevel(root_window) if root_window else tk.Toplevel()
    menu.title("Wähle Chat-Modus")
    menu.geometry("360x200")

    # Store for back buttons and later usage
    client.token = token
    client.servers = servers
    client.role = role
    client.username = username

    tk.Label(menu, text=f"Angemeldet als: {username} ({role})", font=("Segoe UI", 11)).pack(pady=8)

    def do_global():
        """Try connecting to listed servers in order using token_login."""
        connected = False
        for srv in servers:
            try:
                host = srv.get("host")
                port = int(srv.get("port"))
            except Exception:
                continue
            sock = connect_to_server(host, port)
            if not sock:
                continue
            send_json(sock, {"type": "token_login", "token": token})
            resp = receive_json(sock)
            if resp and resp.get("type") in ("login_ok", "validate_ok"):
                client.username = username
                client.role = resp.get("role", role)
                client.sock = sock
                client.file = sock.makefile("r", encoding="utf-8", newline="\n")
                connected = True
                break
            else:
                sock.close()

        if not connected:
            messagebox.showerror("Verbindung", "Kein erreichbarer Chat-Server gefunden")
            return

        menu.destroy()
        show_chat_window(root_window)

    def connect_to_global():
        """Connect to global chat server without opening window."""
        if client.sock:
            return True
        connected = False
        for srv in servers:
            try:
                host = srv.get("host")
                port = int(srv.get("port"))
            except Exception:
                continue
            sock = connect_to_server(host, port)
            if not sock:
                continue
            send_json(sock, {"type": "token_login", "token": token})
            resp = receive_json(sock)
            if resp and resp.get("type") in ("login_ok", "validate_ok"):
                client.username = username
                client.role = resp.get("role", role)
                client.sock = sock
                client.file = sock.makefile("r", encoding="utf-8", newline="\n")
                connected = True
                break
            else:
                sock.close()
        if not connected:
            messagebox.showerror("Verbindung", "Kein erreichbarer Chat-Server gefunden")
            return False
        return True

    def do_dms():
        """Open the DM UI. Connect to global if needed."""
        if not connect_to_global():
            return
        menu.destroy()
        show_dm_window(root_window)

    def do_connect_ip():
        """Manually connect to a specific IP/Port."""
        ip_win = tk.Toplevel(menu)
        ip_win.title("Verbinden zu IP/Port")
        ip_win.geometry("300x150")

        tk.Label(ip_win, text="Host:").pack(pady=(10, 0))
        host_entry = tk.Entry(ip_win)
        host_entry.pack(fill="x", padx=10)
        host_entry.insert(0, "10.0.29.119")  # default

        tk.Label(ip_win, text="Port:").pack(pady=(10, 0))
        port_entry = tk.Entry(ip_win)
        port_entry.pack(fill="x", padx=10)
        port_entry.insert(0, "9001")  # default chat port

        def connect():
            host = host_entry.get().strip()
            try:
                port = int(port_entry.get().strip())
            except ValueError:
                messagebox.showerror("Fehler", "Ungültiger Port")
                return
            sock = connect_to_server(host, port)
            if not sock:
                messagebox.showerror("Verbindung", "Verbindung fehlgeschlagen")
                return
            send_json(sock, {"type": "token_login", "token": token})
            resp = receive_json(sock)
            if resp and resp.get("type") in ("login_ok", "validate_ok"):
                client.username = username
                client.role = resp.get("role", role)
                client.sock = sock
                client.file = sock.makefile("r", encoding="utf-8", newline="\n")
                ip_win.destroy()
                menu.destroy()
                show_chat_window(root_window)
            else:
                sock.close()
                messagebox.showerror("Login", "Login fehlgeschlagen")

        tk.Button(ip_win, text="Verbinden", command=connect).pack(pady=10)

    # Buttons
    btn_frame = tk.Frame(menu)
    btn_frame.pack(pady=8)
    tk.Button(btn_frame, text="Global Chat", width=22, command=do_global).pack(pady=6)
    tk.Button(btn_frame, text="Verbinden (IP/Port)", width=22, command=do_connect_ip).pack(pady=6)
    tk.Button(btn_frame, text="DMs", width=22, command=do_dms).pack(pady=6)

    menu.protocol("WM_DELETE_WINDOW", lambda: sys.exit(0))


def show_chat_window(root_window):
    """Show main chat window (global chat). This function also starts the network thread."""
    win = tk.Toplevel(root_window)  # Create as child of root_window
    win.title(f"GhostChatter - {client.username} ({client.role})")
    win.geometry("900x700")

    # Top back frame
    back_frame = tk.Frame(win)
    back_frame.pack(side="top", fill="x", padx=6, pady=(6, 0))
    tk.Button(back_frame, text="Back to Menu", command=lambda: back_to_menu(root_window, win)).pack(side="right")

    # Message view text widget (read-only)
    txt = tk.Text(win, state="disabled", wrap="word")
    txt.pack(side="top", fill="both", expand=True, padx=6, pady=6)

    # mid -> tag mapping
    mid_to_tag: Dict[int, str] = {}

    def append_message(mid: int, username: str, message: str, timestamp: str):
        """Append a message to the main chat text view and attach moderation menu if appropriate."""
        tag = f"mid_{mid}"
        mid_to_tag[mid] = tag
        txt.configure(state="normal")
        start = txt.index("end-1c")
        txt.insert("end", f"[{timestamp}] {username}: {message}\n")
        end = txt.index("end-1c")
        txt.tag_add(tag, start, end)
        if client.role == "mod":
            # right-click menu for moderators to moderate this message
            txt.tag_bind(tag, "<ButtonPress-3>", lambda e, m=mid, u=username: show_mod_menu(e, m, u))
        txt.configure(state="disabled")
        txt.see("end")

    def delete_message(mid: int):
        """Remove a message from the text widget by mid tag."""
        tag = mid_to_tag.get(mid)
        if not tag:
            return
        txt.configure(state="normal")
        try:
            ranges = txt.tag_ranges(tag)
            if ranges:
                txt.delete(ranges[0], ranges[1])
            txt.tag_delete(tag)
        except Exception:
            pass
        txt.configure(state="disabled")

    def show_mod_menu(event, mid: int, target_user: str):
        menu = tk.Menu(win, tearoff=0)
        menu.add_command(label="Delete", command=lambda: send_mod_delete(mid))
        menu.add_command(label="Warn", command=lambda: send_mod_warn(target_user))
        menu.add_command(label="Ban", command=lambda: send_mod_ban(target_user))
        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()

    def send_mod_delete(mid: int):
        client.send({"type": "mod", "action": "delete", "id": mid})

    def send_mod_warn(target: str):
        reason = simpledialog.askstring("Warn", f"Warn {target} for:")
        if not reason:
            return
        client.send({"type": "mod", "action": "warn", "target": target, "reason": reason})

    def send_mod_ban(target: str):
        if not messagebox.askyesno("Ban", f"Ban {target}?"):
            return
        client.send({"type": "mod", "action": "ban", "target": target})

    # message entry & send button
    entry_frame = tk.Frame(win)
    entry_frame.pack(side="bottom", fill="x", padx=6, pady=6)
    entry = tk.Entry(entry_frame)
    entry.pack(side="left", fill="x", expand=True, padx=(0, 6))
    try:
        import logging
        entry.bind("<FocusOut>", lambda e: logging.getLogger("ghostchatter.ui").info("chat entry focus out"))
        entry.bind("<FocusIn>", lambda e: logging.getLogger("ghostchatter.ui").info("chat entry focus in"))
    except Exception:
        pass

    def on_send(event=None):
        txt_msg = entry.get().strip()
        if not txt_msg:
            return
        if not client.sock:
            messagebox.showinfo("Nicht verbunden", "Bitte zuerst mit einem Chat-Server verbinden.")
            return
        try:
            # support /pm username message
            if txt_msg.startswith("/pm ") or txt_msg.startswith("/msg "):
                try:
                    _, to_user, pm_msg = txt_msg.split(" ", 2)
                    client.send({"type": "pm", "to": to_user, "message": pm_msg})
                except Exception:
                    messagebox.showinfo("PM Syntax", "Verwendung: /pm username Nachricht")
            else:
                client.send({"type": "message", "message": txt_msg})
            entry.delete(0, "end")
        except Exception as e:
            messagebox.showerror("Send Error", f"Fehler beim Senden: {e}")

    send_btn = tk.Button(entry_frame, text="Send", command=on_send)
    send_btn.pack(side="right", padx=6)

    # convenience: Enter sends the message
    entry.bind("<Return>", on_send)

    # double-click a message to PM its author
    def on_message_doubleclick(event):
        try:
            idx = txt.index(f"@{event.x},{event.y}")
        except Exception:
            idx = txt.index("current")
        line_start = txt.index(f"{idx.split('.')[0]}.0")
        line_end = txt.index(f"{idx.split('.')[0]}.end")
        line = txt.get(line_start, line_end)
        try:
            after = line.split("] ", 1)[1]
            username_part = after.split(":", 1)[0].strip()
        except Exception:
            return
        if not username_part:
            return

        # DM quick window
        dm_quick = tk.Toplevel(win)
        dm_quick.title(f"DM to {username_part}")
        tk.Label(dm_quick, text=f"Nachricht an {username_part}:").pack(padx=8, pady=(8, 0))
        dm_entry = tk.Entry(dm_quick)
        dm_entry.pack(padx=8, pady=(4, 8), fill="x")

        def _send_quick():
            txt_msg = dm_entry.get().strip()
            if not txt_msg:
                return
            client.send({"type": "pm", "to": username_part, "message": txt_msg})
            client.add_dm(to_user=username_part, from_user=client.username or "", message=txt_msg, incoming=False)
            dm_quick.destroy()

        tk.Button(dm_quick, text="Senden", command=_send_quick).pack(pady=(0, 8))

    txt.bind("<Double-1>", on_message_doubleclick)

    # ---------- Networking loop ---------------------------------------------
    def network_loop():
        client.running = True
        try:
            while client.running and client.file:
                try:
                    line = client.file.readline()
                except Exception as e:
                    try:
                        import logging
                        logging.getLogger("ghostchatter.client").exception(
                            f"network_loop: exception reading from socket: {e}"
                        )
                    except Exception:
                        pass
                    break

                if not line:
                    try:
                        import logging
                        logging.getLogger("ghostchatter.client").info(
                            "network_loop: EOF from server / socket closed"
                        )
                    except Exception:
                        pass
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
                    win.after(0, append_message, mid, uname, msg, ts)

                elif t == "pm":
                    frm = obj.get("from")
                    msg = obj.get("message")
                    # store DM history and notify
                    client.add_dm(
                        to_user=client.username or "", from_user=frm, message=msg, incoming=True
                    )
                    try:
                        dmw = getattr(client, "dm_window", None)
                        if dmw:
                            win.after(0, dmw.append_dm, frm, msg)
                        else:
                            messagebox.showinfo("Private Nachricht", f"Von {frm}: {msg}")
                    except Exception:
                        messagebox.showinfo("Private Nachricht", f"Von {frm}: {msg}")

                elif t == "warn":
                    frm = obj.get("from")
                    reason = obj.get("reason", "")
                    messagebox.showwarning("Warn", f"Moderator {frm} warns: {reason}")

                elif t == "delete":
                    mid = obj.get("id")
                    try:
                        win.after(0, delete_message, int(mid))
                    except Exception:
                        pass

                elif t == "banned":
                    reason = obj.get("reason", "")
                    messagebox.showerror("Banned", f"You were banned: {reason}")
                    client.close()
                    win.quit()
                    break

                elif t == "ban":
                    target = obj.get("target")
                    win.after(0, append_message, 0, "*system*", f"User {target} was banned by a moderator", datetime_now())

        finally:
            try:
                import logging
                logging.getLogger("ghostchatter.client").info("network_loop: exiting, calling client.close()")
            except Exception:
                pass
            client.close()

    # start network thread
    threading.Thread(target=network_loop, daemon=True).start()

    # ---------- Back button action -----------------------------------------
    def back_to_menu(root_win, current_win):
        current_win.destroy()
        show_post_login_menu(root_win, client.username or "", client.token or "", client.servers or [], client.role)

    # keep window open
    win.protocol("WM_DELETE_WINDOW", lambda: (client.close(), sys.exit(0)))


def show_dm_window(root_window):
    dm_win = tk.Toplevel() if root_window is None else tk.Toplevel(root_window)
    dm_win.title("Direct Messages")
    dm_win.geometry("900x600")

    back_frame_dm = tk.Frame(dm_win)
    back_frame_dm.pack(side="top", fill="x", padx=6, pady=(6, 0))
    tk.Button(back_frame_dm, text="Back to Menu", command=lambda: (dm_win.destroy(), show_post_login_menu(root_window, client.username or "", client.token or "", client.servers or [], client.role))).pack(side="right")

    left = tk.Frame(dm_win, width=150)
    left.pack(side="left", fill="y", padx=6, pady=6)
    nb = ttk.Notebook(dm_win)
    nb.pack(side="right", fill="both", expand=True, padx=6, pady=6)

    tk.Label(left, text="Recent Contacts").pack()
    contacts_lb = tk.Listbox(left, height=20)
    contacts_lb.pack(fill="y", expand=True)

    dm_tabs = {}  # user -> tab_frame

    def refresh_contacts():
        contacts_lb.delete(0, "end")
        for c in client.recent_contacts:
            contacts_lb.insert("end", c)

    refresh_contacts()

    def open_contact(evt=None):
        sel = contacts_lb.curselection()
        if not sel:
            return
        other = contacts_lb.get(sel[0])
        if other in dm_tabs:
            nb.select(dm_tabs[other])
            return
        # Create new tab
        tab = tk.Frame(nb)
        nb.add(tab, text=other)
        dm_tabs[other] = tab

        # Chat text
        txt = tk.Text(tab, state="disabled", wrap="word")
        txt.pack(fill="both", expand=True)

        # Load history
        for e in client.dm_history.get(other, []):
            txt.configure(state="normal")
            txt.insert("end", f"[{e.get('ts')}] {e.get('from')}: {e.get('message')}\n")
            txt.configure(state="disabled")
            txt.see("end")

        # Entry frame
        ef = tk.Frame(tab)
        ef.pack(fill="x", side="bottom")
        msg_entry = tk.Entry(ef)
        msg_entry.pack(side="left", fill="x", expand=True)
        send_btn = tk.Button(ef, text="Send", command=lambda: send_dm(other, msg_entry))
        send_btn.pack(side="right")

        def send_dm(to_user, entry):
            txt_msg = entry.get().strip()
            if not txt_msg:
                return
            client.send({"type": "pm", "to": to_user, "message": txt_msg})
            client.add_dm(to_user=to_user, from_user=client.username or "", message=txt_msg, incoming=False)
            txt.configure(state="normal")
            txt.insert("end", f"[{datetime.datetime.now().strftime('%H:%M:%S')}] me: {txt_msg}\n")
            txt.configure(state="disabled")
            txt.see("end")
            entry.delete(0, "end")
            refresh_contacts()

        msg_entry.bind("<Return>", lambda e: send_dm(other, msg_entry))

    contacts_lb.bind("<<ListboxSelect>>", open_contact)

    def open_contact_for_user(user):
        if user in dm_tabs:
            nb.select(dm_tabs[user])
            return
        # Create new tab
        tab = tk.Frame(nb)
        nb.add(tab, text=user)
        dm_tabs[user] = tab

        # Chat text
        txt = tk.Text(tab, state="disabled", wrap="word")
        txt.pack(fill="both", expand=True)

        # Load history
        for e in client.dm_history.get(user, []):
            txt.configure(state="normal")
            txt.insert("end", f"[{e.get('ts')}] {e.get('from')}: {e.get('message')}\n")
            txt.configure(state="disabled")
            txt.see("end")

        # Entry frame
        ef = tk.Frame(tab)
        ef.pack(fill="x", side="bottom")
        msg_entry = tk.Entry(ef)
        msg_entry.pack(side="left", fill="x", expand=True)
        send_btn = tk.Button(ef, text="Send", command=lambda: send_dm(user, msg_entry))
        send_btn.pack(side="right")

        def send_dm(to_user, entry):
            txt_msg = entry.get().strip()
            if not txt_msg:
                return
            client.send({"type": "pm", "to": to_user, "message": txt_msg})
            client.add_dm(to_user=to_user, from_user=client.username or "", message=txt_msg, incoming=False)
            txt.configure(state="normal")
            txt.insert("end", f"[{datetime_now()}] me: {txt_msg}\n")
            txt.configure(state="disabled")
            txt.see("end")
            entry.delete(0, "end")
            refresh_contacts()

        msg_entry.bind("<Return>", lambda e: send_dm(user, msg_entry))

    # expose helper to main window so incoming PMs can append
    def append_dm_window(*args):
        """Robust incoming-PM handler.

        Accepts either (from_user, text) or (event,) (ignore) to avoid Tk callback mismatches.
        """
        if len(args) == 2:
            from_user, text = args
        else:
            return

        if from_user in dm_tabs:
            # Append to existing tab
            tab = dm_tabs[from_user]
            txt = None
            for child in tab.winfo_children():
                if isinstance(child, tk.Text):
                    txt = child
                    break
            if txt:
                txt.configure(state="normal")
                txt.insert("end", f"[{datetime.datetime.now().strftime('%H:%M:%S')}] {from_user}: {text}\n")
                txt.configure(state="disabled")
                txt.see("end")
        else:
            # Open new tab and append
            open_contact_for_user(from_user)
            if from_user in dm_tabs:
                tab = dm_tabs[from_user]
                txt = None
                for child in tab.winfo_children():
                    if isinstance(child, tk.Text):
                        txt = child
                        break
                if txt:
                    txt.configure(state="normal")
                    txt.insert("end", f"[{datetime.datetime.now().strftime('%H:%M:%S')}] {from_user}: {text}\n")
                    txt.configure(state="disabled")
                    txt.see("end")
            else:
                messagebox.showinfo("Neue Nachricht", f"Von {from_user}: {text}")
        refresh_contacts()

    def open_contact_for_user(user):
        if user in dm_tabs:
            nb.select(dm_tabs[user])
            return
        # Create new tab
        tab = tk.Frame(nb)
        nb.add(tab, text=user)
        dm_tabs[user] = tab

        # Chat text
        txt = tk.Text(tab, state="disabled", wrap="word")
        txt.pack(fill="both", expand=True)

        # Load history
        for e in client.dm_history.get(user, []):
            txt.configure(state="normal")
            txt.insert("end", f"[{e.get('ts')}] {e.get('from')}: {e.get('message')}\n")
            txt.configure(state="disabled")
            txt.see("end")

        # Entry frame
        ef = tk.Frame(tab)
        ef.pack(fill="x", side="bottom")
        msg_entry = tk.Entry(ef)
        msg_entry.pack(side="left", fill="x", expand=True)
        send_btn = tk.Button(ef, text="Send", command=lambda: send_dm(user, msg_entry))
        send_btn.pack(side="right")

        def send_dm(to_user, entry):
            txt_msg = entry.get().strip()
            if not txt_msg:
                return
            client.send({"type": "pm", "to": to_user, "message": txt_msg})
            client.add_dm(to_user=to_user, from_user=client.username or "", message=txt_msg, incoming=False)
            txt.configure(state="normal")
            txt.insert("end", f"[{datetime.datetime.now().strftime('%H:%M:%S')}] me: {txt_msg}\n")
            txt.configure(state="disabled")
            txt.see("end")
            entry.delete(0, "end")
            refresh_contacts()

        msg_entry.bind("<Return>", lambda e: send_dm(user, msg_entry))

    dm_win.append_dm = append_dm_window
    client.dm_window = dm_win
    dm_win.protocol("WM_DELETE_WINDOW", lambda: (client.close(), sys.exit(0)))