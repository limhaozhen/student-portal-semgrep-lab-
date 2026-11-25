"""Security audit logging (STRIDE: Repudiation; ASVS V16).

Every entry is chained to the previous one with SHA-256, so editing or deleting a
row breaks the chain and is detected by verify_chain(). The table also has
triggers that block UPDATE/DELETE from the application.
"""
import hashlib
import re
import threading

from flask import current_app, g, has_request_context, request

from .db import get_db, now

GENESIS = "0" * 64
_LOCK = threading.Lock()
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")


def _clean(value, limit=500):
    """Neutralise CR/LF and other control characters (log injection)."""
    if value is None:
        return None
    return _CONTROL_CHARS.sub(" ", str(value))[:limit]


def _entry_hash(ts, user_id, username, ip, action, outcome, target, detail, prev_hash):
    payload = "|".join(str(x) for x in (ts, user_id, username, ip, action, outcome, target, detail, prev_hash))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def log_event(action, outcome="success", target=None, detail=None, user=None, username=None):
    """Record a security-relevant event. Never pass passwords, codes or tokens here."""
    actor = user if user is not None else g.get("user")
    user_id = actor["id"] if actor is not None else None
    uname = _clean(actor["username"] if actor is not None else username, 64)
    ip = request.remote_addr if has_request_context() else "system"
    action, outcome = _clean(action, 64), _clean(outcome, 16)
    target, detail = _clean(target, 200), _clean(detail)
    ts = now()

    with _LOCK:
        conn = get_db()
        row = conn.execute("SELECT entry_hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
        prev_hash = row["entry_hash"] if row else GENESIS
        entry_hash = _entry_hash(ts, user_id, uname, ip, action, outcome, target, detail, prev_hash)
        conn.execute(
            "INSERT INTO audit_log (ts, user_id, username, ip, action, outcome, target, detail, prev_hash, entry_hash)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (ts, user_id, uname, ip, action, outcome, target, detail, prev_hash, entry_hash),
        )
        conn.commit()

    current_app.logger.info(
        "AUDIT action=%s outcome=%s user=%s ip=%s target=%s detail=%s",
        action, outcome, uname, ip, target, detail,
    )


def verify_chain(conn=None):
    """Return (ok, entries_checked, first_bad_id)."""
    conn = conn or get_db()
    prev = GENESIS
    count = 0
    for row in conn.execute("SELECT * FROM audit_log ORDER BY id"):
        expected = _entry_hash(row["ts"], row["user_id"], row["username"], row["ip"], row["action"],
                               row["outcome"], row["target"], row["detail"], prev)
        if row["prev_hash"] != prev or row["entry_hash"] != expected:
            return False, count, row["id"]
        prev = row["entry_hash"]
        count += 1
    return True, count, None
