"""Profile Update module (Lab 1 user story 4 / Lab 2 TB04).

Controls: allow-listed editable fields (mass-assignment defence), server-side input
validation, re-authentication before changing email/password/MFA, notification to the
old email address, session revocation after password change.
"""
import re

from flask import Blueprint, current_app, flash, g, redirect, render_template, request, url_for
from werkzeug.security import check_password_hash, generate_password_hash

from . import audit, mailer, security
from .auth import start_session
from .db import execute, now, query_all, query_one

bp = Blueprint("profile", __name__, url_prefix="/profile")

EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,24}$")
PHONE_RE = re.compile(r"^\+?[0-9 ()-]{7,20}$")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
EDITABLE_FIELDS = {"email", "phone", "address", "current_password", "csrf_token"}


def _profile(user_id):
    return query_one("SELECT * FROM profiles WHERE user_id = ?", (user_id,))


def _reauthenticate(password):
    """Re-check the current password; failures count towards the account lockout."""
    user_key = f"u:{g.user['username']}"
    if security.lock_remaining(user_key):
        return "Too many failed attempts. Try again later."
    if not check_password_hash(g.user["password_hash"], password or ""):
        security.record_failure(user_key, f"ip:{security.client_ip()}")
        audit.log_event("reauth.failed", outcome="failure")
        return "Your current password is incorrect."
    return None


@bp.route("/", methods=["GET"])
@security.login_required
def view():
    uid = g.user["id"]
    sessions = query_all("SELECT sid_hash, created_at, last_seen, ip, user_agent FROM sessions "
                         "WHERE user_id = ? ORDER BY last_seen DESC", (uid,))
    return render_template("profile.html", p=_profile(uid), sessions=sessions, current_sid=g.sid_hash,
                           mfa_enforced=g.user["role"] in current_app.config["MFA_ENFORCED_ROLES"],
                           min_len=current_app.config["PASSWORD_MIN_LENGTH"])


@bp.route("/", methods=["POST"])
@security.login_required
def update():
    uid = g.user["id"]
    unexpected = set(request.form.keys()) - EDITABLE_FIELDS
    if unexpected:
        # e.g. someone adding role=admin with a proxy: ignored, but logged.
        audit.log_event("profile.unexpected_fields", outcome="failure", detail=",".join(sorted(unexpected)))

    p = _profile(uid)
    email = (request.form.get("email") or "").strip()
    phone = (request.form.get("phone") or "").strip()
    address = (request.form.get("address") or "").strip()

    errors = []
    if len(email) > 254 or not EMAIL_RE.match(email):
        errors.append("Enter a valid email address.")
    if phone and not PHONE_RE.match(phone):
        errors.append("Phone number may contain digits, spaces, brackets, dashes and a leading +.")
    if len(address) > 200 or _CONTROL.search(address):
        errors.append("Address must be at most 200 characters on a single line.")

    email_changed = email.lower() != p["email"].lower()
    if not errors and email_changed:
        problem = _reauthenticate(request.form.get("current_password"))
        if problem:
            errors.append(problem + " (Required to change your email address.)")
    if errors:
        for e in errors:
            flash(e, "error")
        return redirect(url_for("profile.view"))

    changed = [name for name, old, new in (("email", p["email"], email), ("phone", p["phone"] or "", phone),
                                           ("address", p["address"] or "", address)) if old != new]
    if not changed:
        flash("No changes to save.", "info")
        return redirect(url_for("profile.view"))

    # Only these three columns can ever be written, and only for the signed-in user.
    execute("UPDATE profiles SET email = ?, phone = ?, address = ?, updated_at = ? WHERE user_id = ?",
            (email, phone or None, address or None, now(), uid))
    audit.log_event("profile.updated", target=f"user:{uid}", detail="changed: " + ", ".join(changed))
    body = (f"Hello {g.user['full_name']},\n\nThe following details on your UniPortal profile were changed: "
            f"{', '.join(changed)}.\n\nIf this wasn't you, contact the IT help desk immediately.")
    mailer.send_mail(p["email"], "Your UniPortal profile was updated", body)
    if email_changed:
        mailer.send_mail(email, "Email address added to UniPortal", body)
    flash("Profile updated. A confirmation email was sent.", "success")
    return redirect(url_for("profile.view"))


@bp.route("/password", methods=["POST"])
@security.login_required
def change_password():
    problem = _reauthenticate(request.form.get("current_password"))
    if problem:
        flash(problem, "error")
        return redirect(url_for("profile.view"))

    new = request.form.get("new_password") or ""
    problems = security.password_problems(new, g.user["username"])
    if new != (request.form.get("confirm_password") or ""):
        problems.append("The new passwords do not match.")
    if new == request.form.get("current_password"):
        problems.append("The new password must be different from the current one.")
    if problems:
        for p in problems:
            flash(p, "error")
        return redirect(url_for("profile.view"))

    uid = g.user["id"]
    execute("UPDATE users SET password_hash = ?, password_changed_at = ? WHERE id = ?",
            (generate_password_hash(new), now(), uid))
    execute("DELETE FROM sessions WHERE user_id = ? AND sid_hash != ?", (uid, g.sid_hash))
    start_session(g.user)
    audit.log_event("password.changed", detail="other sessions revoked")
    mailer.notify_user(uid, "Your UniPortal password was changed",
                       "Your password was changed and all other sessions were signed out.")
    flash("Password changed. All other sessions have been signed out.", "success")
    return redirect(url_for("profile.view"))


@bp.route("/sessions/revoke", methods=["POST"])
@security.login_required
def revoke_sessions():
    cur = execute("DELETE FROM sessions WHERE user_id = ? AND sid_hash != ?", (g.user["id"], g.sid_hash))
    audit.log_event("session.revoked_others", detail=f"{cur.rowcount} session(s)")
    flash(f"Signed out {cur.rowcount} other session(s).", "success")
    return redirect(url_for("profile.view"))


@bp.route("/mfa/disable", methods=["POST"])
@security.login_required
def mfa_disable():
    user = g.user
    if user["role"] in current_app.config["MFA_ENFORCED_ROLES"]:
        flash("MFA is mandatory for your role and cannot be disabled.", "error")
        return redirect(url_for("profile.view"))
    if not user["mfa_enabled"]:
        return redirect(url_for("profile.view"))
    problem = _reauthenticate(request.form.get("current_password"))
    if problem is None and security.verify_totp(user["mfa_secret"], request.form.get("code"),
                                                user["mfa_last_step"]) is None:
        problem = "The authenticator code is invalid."
        security.record_failure(f"u:{user['username']}", f"ip:{security.client_ip()}")
    if problem:
        flash(problem, "error")
        return redirect(url_for("profile.view"))
    execute("UPDATE users SET mfa_enabled = 0, mfa_secret = NULL, mfa_last_step = 0 WHERE id = ?", (user["id"],))
    audit.log_event("mfa.disabled")
    mailer.notify_user(user["id"], "Multi-factor authentication disabled",
                       "Multi-factor authentication was turned off for your UniPortal account.")
    flash("Multi-factor authentication has been disabled.", "success")
    return redirect(url_for("profile.view"))
