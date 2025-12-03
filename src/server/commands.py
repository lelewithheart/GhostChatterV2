"""Server commands for GhostChatter auth server."""

from typing import Dict, Callable, List
import secrets


def register_commands(context) -> Dict[str, Callable[[List[str]], str]]:
    users_conn = context.get("users_conn")
    users_cur = context.get("users_cur")
    stop_flag = context.get("stop_flag")
    clients_lock = context.get("clients_lock")
    clients = context.get("clients")

    def create_user(args):
        if len(args) < 2:
            return "Usage: create-user <username> <password> [role]"
        username = args[0]
        password = args[1]
        role = args[2] if len(args) >= 3 else "user"
        try:
            users_cur.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", (username, password, role))
            users_conn.commit()
            return f"User '{username}' created with role '{role}'"
        except Exception as e:
            return f"Error creating user: {e}"

    def list_users(args):
        try:
            users_cur.execute("SELECT username, role, banned FROM users ORDER BY username")
            rows = users_cur.fetchall()
            if not rows:
                return "(no users)"
            lines = [f"{r[0]} (role={r[1] or 'user'}, banned={bool(r[2])})" for r in rows]
            return "\n".join(lines)
        except Exception as e:
            return f"Error listing users: {e}"

    def set_role(args):
        if len(args) < 2:
            return "Usage: set-role <username> <role>"
        user, role = args[0], args[1]
        try:
            users_cur.execute("UPDATE users SET role=? WHERE username=?", (role, user))
            users_conn.commit()
            return f"Set role of {user} to {role}"
        except Exception as e:
            return f"Error setting role: {e}"

    def ban_user(args):
        if len(args) < 1:
            return "Usage: ban <username>"
        target = args[0]
        try:
            users_cur.execute("UPDATE users SET banned=1 WHERE username=?", (target,))
            users_conn.commit()
            # try to disconnect online (though auth server doesn't keep chat clients)
            return f"Banned {target}"
        except Exception as e:
            return f"Error banning user: {e}"

    def unban_user(args):
        if len(args) < 1:
            return "Usage: unban <username>"
        target = args[0]
        try:
            users_cur.execute("UPDATE users SET banned=0 WHERE username=?", (target,))
            users_conn.commit()
            return f"Unbanned {target}"
        except Exception as e:
            return f"Error unbanning user: {e}"

    def stop_server(args):
        stop_flag.set()
        return "Stopping server..."

    def create_instance(args):
        """create-instance [host] [port]

        Generates an instance_id and secret, stores it in the instances DB and
        prints the credentials. The host/port are optional metadata.
        """
        host = args[0] if len(args) >= 1 else None
        port = None
        if len(args) >= 2:
            try:
                port = int(args[1])
            except Exception:
                return "Usage: create-instance [host] [port]"
        try:
            iid = secrets.token_urlsafe(10)
            secret = secrets.token_urlsafe(24)
            # insert into instances table
            ins_cur = context.get("instances_cur")
            ins_conn = context.get("instances_conn")
            if not ins_cur or not ins_conn:
                return "Instances DB not available in server context"
            ins_cur.execute("INSERT INTO instances (instance_id, secret, host, port) VALUES (?, ?, ?, ?)", (iid, secret, host, port))
            ins_conn.commit()
            return f"Created instance:\n  id: {iid}\n  secret: {secret}\n  host: {host}\n  port: {port}"
        except Exception as e:
            return f"Error creating instance: {e}"

    def help_cmd(args):
        return ("Available commands: create-user, list-users, set-role, ban, unban, stop, help\n"
                "You can edit server-commands.py to add instance-specific commands.")

    return {
        "create-user": create_user,
        "list-users": list_users,
        "set-role": set_role,
        "ban": ban_user,
        "unban": unban_user,
        "stop": stop_server,
        "create-instance": create_instance,
        "help": help_cmd,
    }