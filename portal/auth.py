"""Login module (Lab 1 user story 1 / Lab 2 trust boundary TB01).

Controls: generic errors (no username enumeration), constant-work password check,
CAPTCHA after repeated failures, account lockout, per-IP throttling, TOTP MFA,
server-side sessions with idle/absolute timeouts, session rotation on login.
"""
import hashlib
import io
import secrets

import pyotp
import qrcode
import qrcode.image.svg
from flask import (Blueprint, abort, current_app, flash, g, make_response, redirect,
                   render_template, request, session, url_for)
from markupsafe import Markup
from werkzeug.security import check_password_hash, generate_password_hash

from . import audit, mailer, security
from .db import execute, get_db, now, query_one

bp = Blueprint("auth", __name__)

# Used when the username does not exist so the response time is the same (anti-enumeration).
_DUMMY_HASH = generate_password_hash(secrets.token_hex(16))
MFA_PENDING_TTL = 300
_MFA_GATE_EXEMPT = {"auth.mfa_setup", "auth.logout", "auth.captcha", "static"}


# --------------------------------------------------------------------------- sessions (ASVS V7)

def _sid_hash(sid):
    return hashlib.sha256(sid.encode("utf-8")).hexdigest()


def start_session(user):
    """Create a fresh server-side session (new id on every authentication)."""
    cfg = current_app.config
    t = now()
    conn = get_db()
    old_sid = session.get("sid")
    if old_sid:
        conn.execute("DELETE FROM sessions WHERE sid_hash = ?", (_sid_hash(old_sid),))
    conn.execute("DELETE FROM sessions WHERE last_seen < ? OR created_at < ?",
                 (t - cfg["IDLE_TIMEOUT"], t - cfg["ABSOLUTE_TIMEOUT"]))
    session.clear()
    sid = secrets.token_urlsafe(32)
    conn.execute(
        "INSERT INTO sessions (sid_hash, user_id, created_at, last_seen, ip, user_agent) VALUES (?, ?, ?, ?, ?, ?)",
        (_sid_hash(sid), user["id"], t, t, security.client_ip(), (request.user_agent.string or "")[:200]),
    )
    conn.commit()
    session["sid"] = sid
    session.permanent = True
    return _sid_hash(sid)


def end_session():
    sid = session.get("sid")
    if sid:
        execute("DELETE FROM sessions WHERE sid_hash = ?", (_sid_hash(sid),))
    session.clear()


def load_logged_in_user():
    g.user = None
    g.sid_hash = None
    if request.endpoint == "static":
        return
    sid = session.get("sid")
    if not sid:
        return
    sid_hash = _sid_hash(sid)
    row = query_one(
        "SELECT s.created_at AS sess_created, s.last_seen AS sess_last_seen, u.* "
        "FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.sid_hash = ?",
        (sid_hash,),
    )
    if row is None:
        session.clear()
        return
    cfg = current_app.config
    t = now()
    if (not row["is_active"] or t - row["sess_last_seen"] > cfg["IDLE_TIMEOUT"]
            or t - row["sess_created"] > cfg["ABSOLUTE_TIMEOUT"]):
        execute("DELETE FROM sessions WHERE sid_hash = ?", (sid_hash,))
        audit.log_event("session.expired", outcome="info", user=row)
        session.clear()
        flash("Your session has expired. Please sign in again.", "info")
        return
    if t - row["sess_last_seen"] >= 30:
        execute("UPDATE sessions SET last_seen = ? WHERE sid_hash = ?", (t, sid_hash))
    g.user = row
    g.sid_hash = sid_hash


def enforce_mfa_enrollment():
    user = g.get("user")
    if user is None or user["mfa_enabled"]:
        return None
    if user["role"] in current_app.config["MFA_ENFORCED_ROLES"] and request.endpoint not in _MFA_GATE_EXEMPT:
        flash("Your role requires multi-factor authentication. Set it up to continue.", "warning")
        return redirect(url_for("auth.mfa_setup"))
    return None


# --------------------------------------------------------------------------- login

def _lock_message(seconds):
    minutes = max(1, (seconds + 59) // 60)
    return f"Too many failed sign-in attempts. Try again in {minutes} minute(s)."


@bp.route("/login", methods=["GET", "POST"])
def login():
    if g.user:
        return redirect(url_for("views.dashboard"))

    ip_key = f"ip:{security.client_ip()}"
    username_input = ""
    error = None
    status = 200

    if request.method == "POST":
        username_input = (request.form.get("username") or "").strip()[:64]
        password = request.form.get("password") or ""
        username = username_input.lower()
        user_key = f"u:{username}"

        if security.ip_blocked(ip_key):
            audit.log_event("login.ip_blocked", outcome="failure", username=username)
            abort(429, "Too many failed sign-in attempts from your network. Try again later.")

        locked_for = security.lock_remaining(user_key)
        if locked_for:
            # Same response for real and non-existent usernames; password is not checked.
            audit.log_event("login.locked", outcome="failure", username=username)
            error, status = _lock_message(locked_for), 429
        elif security.captcha_required(user_key, ip_key) and not security.verify_captcha(request.form.get("captcha")):
            security.record_failure(user_key, ip_key)
            audit.log_event("login.captcha_failed", outcome="failure", username=username)
            error, status = "Please type the characters shown in the CAPTCHA image.", 401
        else:
            user = query_one("SELECT * FROM users WHERE username = ?", (username,)) if username else None
            password_ok = check_password_hash(user["password_hash"] if user else _DUMMY_HASH, password)

            if user and password_ok and user["is_active"]:
                security.clear_failures(user_key)
                if user["mfa_enabled"]:
                    session.clear()
                    session["mfa_pending"] = {"uid": user["id"], "ts": now()}
                    audit.log_event("login.password_ok", detail="awaiting MFA", user=user)
                    return redirect(url_for("auth.login_mfa"))
                start_session(user)
                audit.log_event("login.success", user=user)
                return redirect(url_for("views.dashboard"))

            security.record_failure(user_key, ip_key)
            reason = "unknown user" if not user else ("inactive account" if not user["is_active"] else "bad password")
            audit.log_event("login.failed", outcome="failure", username=username, detail=reason)
            if user and security.lock_remaining(user_key):
                audit.log_event("account.locked", outcome="failure", username=username,
                                detail=f"{current_app.config['LOCKOUT_THRESHOLD']} failed attempts")
                mailer.notify_user(user["id"], "Your UniPortal account was temporarily locked",
                                   "We blocked sign-in to your account after several failed attempts.")
            # One generic message for every failure reason (ASVS V6.3 / anti-enumeration).
            error, status = "Invalid username or password.", 401

    need_captcha = security.captcha_required(f"u:{username_input.lower()}", ip_key)
    if need_captcha:
        security.new_captcha()
    return render_template("login.html", error=error, username=username_input,
                           need_captcha=need_captcha, captcha_v=secrets.token_hex(4)), status


@bp.route("/captcha.svg")
def captcha():
    svg = security.captcha_svg()
    if svg is None:
        abort(404)
    response = make_response(svg)
    response.mimetype = "image/svg+xml"
    return response


@bp.route("/login/mfa", methods=["GET", "POST"])
def login_mfa():
    pending = session.get("mfa_pending")
    if not pending or now() - pending.get("ts", 0) > MFA_PENDING_TTL:
        session.pop("mfa_pending", None)
        flash("Please sign in again.", "info")
        return redirect(url_for("auth.login"))
    user = query_one("SELECT * FROM users WHERE id = ?", (pending["uid"],))
    if user is None or not user["is_active"] or not user["mfa_enabled"]:
        session.clear()
        return redirect(url_for("auth.login"))

    user_key, ip_key = f"u:{user['username']}", f"ip:{security.client_ip()}"
    error = None
    if request.method == "POST":
        locked_for = security.lock_remaining(user_key)
        if locked_for:
            session.clear()
            flash(_lock_message(locked_for), "error")
            return redirect(url_for("auth.login"))
        step = security.verify_totp(user["mfa_secret"], request.form.get("code"), user["mfa_last_step"])
        if step is not None:
            execute("UPDATE users SET mfa_last_step = ? WHERE id = ?", (step, user["id"]))
            security.clear_failures(user_key)
            start_session(user)
            audit.log_event("login.success", detail="password + TOTP", user=user)
            return redirect(url_for("views.dashboard"))
        security.record_failure(user_key, ip_key)
        audit.log_event("mfa.failed", outcome="failure", user=user)
        if security.lock_remaining(user_key):
            audit.log_event("account.locked", outcome="failure", user=user, detail="MFA failures")
            session.clear()
            flash(_lock_message(security.lock_remaining(user_key)), "error")
            return redirect(url_for("auth.login"))
        error = "Invalid or already-used code."
    return render_template("login_mfa.html", error=error), (401 if error else 200)


@bp.route("/logout", methods=["POST"])
def logout():
    if g.user:
        audit.log_event("logout")
    end_session()
    flash("You have been signed out.", "info")
    return redirect(url_for("auth.login"))


# --------------------------------------------------------------------------- MFA enrolment

def _qr_svg(data):
    image = qrcode.make(data, image_factory=qrcode.image.svg.SvgPathImage, box_size=10, border=2)
    buf = io.BytesIO()
    image.save(buf)
    svg = buf.getvalue().decode("utf-8")
    return Markup(svg[svg.index("<svg"):])  # drop the XML declaration for inline use


@bp.route("/mfa/setup", methods=["GET", "POST"])
@security.login_required
def mfa_setup():
    user = g.user
    if user["mfa_enabled"]:
        flash("Multi-factor authentication is already enabled.", "info")
        return redirect(url_for("profile.view"))

    secret = user["mfa_pending_secret"]
    if not secret:
        secret = pyotp.random_base32()
        execute("UPDATE users SET mfa_pending_secret = ? WHERE id = ?", (secret, user["id"]))

    error = None
    if request.method == "POST":
        step = security.verify_totp(secret, request.form.get("code"), 0)
        if step is not None:
            execute("UPDATE users SET mfa_enabled = 1, mfa_secret = ?, mfa_pending_secret = NULL, "
                    "mfa_last_step = ? WHERE id = ?", (secret, step, user["id"]))
            audit.log_event("mfa.enabled")
            mailer.notify_user(user["id"], "Multi-factor authentication enabled",
                               "An authenticator app was linked to your UniPortal account.")
            start_session(user)  # rotate the session after the security level changes
            flash("Multi-factor authentication is now enabled.", "success")
            return redirect(url_for("views.dashboard"))
        audit.log_event("mfa.enrol_failed", outcome="failure")
        error = "That code did not match. Check the time on your phone and try again."

    uri = pyotp.TOTP(secret).provisioning_uri(name=user["username"], issuer_name=current_app.config["MFA_ISSUER"])
    enforced = user["role"] in current_app.config["MFA_ENFORCED_ROLES"]
    return render_template("mfa_setup.html", qr_svg=_qr_svg(uri), secret=secret, error=error, enforced=enforced)
