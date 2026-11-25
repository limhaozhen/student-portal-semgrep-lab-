#!/usr/bin/env python3
"""Admin commands.

  python manage.py init-db [--force]     create the database with demo data (--force wipes it first)
  python manage.py unlock <username>     clear failed-login counters for one account
  python manage.py clear-failures        clear ALL failed-login / IP throttling counters
  python manage.py set-password <user>   set a new password (prompted, policy enforced)
  python manage.py reset-mfa <user>      remove a user's authenticator (e.g. lost phone)
  python manage.py verify-audit          check the audit log hash chain for tampering
"""
import argparse
import getpass
import sys

from werkzeug.security import generate_password_hash

from portal import create_app
from portal.audit import verify_chain
from portal.db import connect, now
from portal.seed import DEMO_PASSWORDS, seed
from portal.security import password_problems


def main():
    parser = argparse.ArgumentParser(description="UniPortal management")
    sub = parser.add_subparsers(dest="cmd", required=True)
    init = sub.add_parser("init-db")
    init.add_argument("--force", action="store_true")
    sub.add_parser("unlock").add_argument("username")
    sub.add_parser("clear-failures")
    sub.add_parser("set-password").add_argument("username")
    sub.add_parser("reset-mfa").add_argument("username")
    sub.add_parser("verify-audit")
    args = parser.parse_args()

    app = create_app()
    db_path = app.config["DATABASE"]

    if args.cmd == "init-db":
        if seed(db_path, app.config["UPLOAD_DIR"], force=args.force):
            print(f"[+] Database created at {db_path}")
            print("[+] Demo passwords: " + ", ".join(f"{role}s -> {pw}" for role, pw in DEMO_PASSWORDS.items()))
        else:
            print("[=] Database already exists. Use --force to wipe and re-create it.")
        return

    conn = connect(db_path)
    if args.cmd == "unlock":
        cur = conn.execute("DELETE FROM login_failures WHERE key = ?", (f"u:{args.username.lower()}",))
        conn.commit()
        print(f"[+] Cleared {cur.rowcount} failure record(s) for {args.username}")
    elif args.cmd == "clear-failures":
        cur = conn.execute("DELETE FROM login_failures")
        conn.commit()
        print(f"[+] Cleared {cur.rowcount} failure record(s)")
    elif args.cmd == "set-password":
        user = conn.execute("SELECT id, username FROM users WHERE username = ?", (args.username.lower(),)).fetchone()
        if not user:
            sys.exit("No such user")
        password = getpass.getpass("New password: ")
        with app.app_context():
            problems = password_problems(password, user["username"])
        if password != getpass.getpass("Repeat password: "):
            problems.append("Passwords do not match.")
        if problems:
            sys.exit("\n".join(problems))
        conn.execute("UPDATE users SET password_hash = ?, password_changed_at = ? WHERE id = ?",
                     (generate_password_hash(password), now(), user["id"]))
        conn.execute("DELETE FROM sessions WHERE user_id = ?", (user["id"],))
        conn.commit()
        print("[+] Password updated and sessions revoked")
    elif args.cmd == "reset-mfa":
        cur = conn.execute("UPDATE users SET mfa_enabled = 0, mfa_secret = NULL, mfa_pending_secret = NULL, "
                           "mfa_last_step = 0 WHERE username = ?", (args.username.lower(),))
        conn.execute("DELETE FROM sessions WHERE user_id = (SELECT id FROM users WHERE username = ?)",
                     (args.username.lower(),))
        conn.commit()
        print("[+] MFA reset; the user will enrol again at next sign-in" if cur.rowcount else "No such user")
    elif args.cmd == "verify-audit":
        ok, checked, bad_id = verify_chain(conn)
        print(f"[+] Audit chain intact ({checked} entries)" if ok
              else f"[!] Audit chain BROKEN at entry #{bad_id} (after {checked} good entries)")
        sys.exit(0 if ok else 1)
    conn.close()


if __name__ == "__main__":
    main()
