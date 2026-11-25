"""Administration: account management, audit log review (Repudiation) and the email outbox."""
from flask import Blueprint, abort, flash, g, redirect, render_template, request, url_for

from . import audit, mailer, security
from .db import execute, query_all, query_one

bp = Blueprint("admin", __name__, url_prefix="/admin")


def _target(user_id):
    row = query_one("SELECT * FROM users WHERE id = ?", (user_id,))
    if row is None:
        abort(404)
    return row


@bp.route("/users")
@security.roles_required("admin")
def users():
    rows = query_all(
        "SELECT u.id, u.username, u.full_name, u.role, u.is_active, u.mfa_enabled, p.email, p.id_number, "
        "(SELECT COUNT(*) FROM sessions s WHERE s.user_id = u.id) AS n_sessions "
        "FROM users u LEFT JOIN profiles p ON p.user_id = u.id ORDER BY u.role, u.username")
    users_ = [dict(r, locked_for=security.lock_remaining(f"u:{r['username']}")) for r in rows]
    return render_template("admin_users.html", users=users_)


@bp.route("/users/<int:user_id>/unlock", methods=["POST"])
@security.roles_required("admin")
def unlock(user_id):
    target = _target(user_id)
    security.clear_failures(f"u:{target['username']}")
    audit.log_event("admin.account_unlocked", target=f"user:{user_id}")
    flash(f"{target['username']} unlocked.", "success")
    return redirect(url_for("admin.users"))


@bp.route("/users/<int:user_id>/reset-mfa", methods=["POST"])
@security.roles_required("admin")
def reset_mfa(user_id):
    target = _target(user_id)
    execute("UPDATE users SET mfa_enabled = 0, mfa_secret = NULL, mfa_pending_secret = NULL, mfa_last_step = 0 "
            "WHERE id = ?", (user_id,))
    execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
    audit.log_event("admin.mfa_reset", target=f"user:{user_id}")
    mailer.notify_user(user_id, "Your MFA was reset by an administrator",
                       "An administrator reset multi-factor authentication on your account. "
                       "You will be asked to enrol again if your role requires it.")
    flash(f"MFA reset for {target['username']}; their sessions were signed out.", "success")
    return redirect(url_for("admin.users"))


@bp.route("/users/<int:user_id>/toggle-active", methods=["POST"])
@security.roles_required("admin")
def toggle_active(user_id):
    target = _target(user_id)
    if user_id == g.user["id"]:
        flash("You cannot disable your own account.", "error")
        return redirect(url_for("admin.users"))
    new_state = 0 if target["is_active"] else 1
    execute("UPDATE users SET is_active = ? WHERE id = ?", (new_state, user_id))
    if not new_state:
        execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
    audit.log_event("admin.account_enabled" if new_state else "admin.account_disabled", target=f"user:{user_id}")
    flash(f"{target['username']} {'enabled' if new_state else 'disabled'}.", "success")
    return redirect(url_for("admin.users"))


@bp.route("/audit")
@security.roles_required("admin")
def audit_log():
    action = (request.args.get("action") or "").strip()[:64]
    username = (request.args.get("user") or "").strip().lower()[:64]
    outcome = request.args.get("outcome") if request.args.get("outcome") in ("success", "failure", "info") else ""
    sql, args = "SELECT * FROM audit_log WHERE 1 = 1", []
    if action:
        sql += " AND action LIKE ? ESCAPE '\\'"
        args.append(action.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%")
    if username:
        sql += " AND username = ?"
        args.append(username)
    if outcome:
        sql += " AND outcome = ?"
        args.append(outcome)
    rows = query_all(sql + " ORDER BY id DESC LIMIT 300", args)
    chain_ok, checked, bad_id = audit.verify_chain()
    return render_template("admin_audit.html", rows=rows, chain_ok=chain_ok, checked=checked, bad_id=bad_id,
                           f={"action": action, "user": username, "outcome": outcome})


@bp.route("/outbox")
@security.roles_required("admin")
def outbox():
    rows = query_all("SELECT * FROM mail_outbox ORDER BY id DESC LIMIT 50")
    return render_template("admin_outbox.html", rows=rows)
