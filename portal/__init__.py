"""UniPortal - a secure-by-design student portal built from the Lab 1 (ATT&CK -> ASVS)
and Lab 2 (STRIDE threat model) exercises."""
import logging
import time
from datetime import timedelta
from logging.handlers import RotatingFileHandler
from pathlib import Path

from flask import Flask, g, render_template
from werkzeug.exceptions import HTTPException

from . import admin, assignments, auth, db, messages, profile, security, views
from .config import build_config, instance_dir

_ERROR_TITLES = {400: "Bad request", 403: "Access denied", 404: "Page not found", 405: "Method not allowed",
                 409: "Integrity check failed", 413: "File too large", 429: "Too many requests",
                 500: "Something went wrong"}


def create_app(overrides=None):
    folder = instance_dir()
    app = Flask(__name__, instance_path=str(folder))
    app.config.update(build_config(folder))
    if overrides:
        app.config.update(overrides)

    https = bool(app.config["USE_HTTPS"])
    app.config.update(
        # __Host- prefix: cookie is Secure, host-only and path=/ (only possible over HTTPS).
        SESSION_COOKIE_NAME="__Host-uniportal" if https else "uniportal_session",
        SESSION_COOKIE_SECURE=https,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_PATH="/",
        PERMANENT_SESSION_LIFETIME=timedelta(seconds=app.config["ABSOLUTE_TIMEOUT"]),
        DEBUG=False,
        PROPAGATE_EXCEPTIONS=False,
    )
    Path(app.config["UPLOAD_DIR"]).mkdir(parents=True, exist_ok=True)
    _configure_logging(app)

    db.init_app(app)
    # Order matters: identify the user, then CSRF, then the MFA-enrolment gate.
    app.before_request(auth.load_logged_in_user)
    app.before_request(security.csrf_protect)
    app.before_request(auth.enforce_mfa_enrollment)
    app.after_request(security.security_headers)

    for blueprint in (auth.bp, views.bp, assignments.bp, messages.bp, profile.bp, admin.bp):
        app.register_blueprint(blueprint)

    @app.context_processor
    def inject_globals():
        unread = 0
        user = g.get("user")
        if user is not None and user["role"] in ("student", "lecturer"):
            try:
                unread = db.query_one("SELECT COUNT(*) AS n FROM messages WHERE recipient_id = ? AND read_at IS NULL",
                                      (user["id"],))["n"]
            except Exception:  # never break error pages
                unread = 0
        return {"csrf_token": security.csrf_token, "csrf_field": security.csrf_field, "unread_count": unread,
                "idle_minutes": app.config["IDLE_TIMEOUT"] // 60}

    @app.template_filter("dt")
    def format_ts(ts):
        if not ts:
            return "-"
        return time.strftime("%d %b %Y, %H:%M", time.localtime(ts))

    @app.template_filter("filesize")
    def format_size(n):
        if n is None:
            return "-"
        return f"{n / 1024:.1f} KB" if n < 1024 * 1024 else f"{n / 1024 / 1024:.1f} MB"

    def handle_error(error):
        code = error.code if isinstance(error, HTTPException) else 500
        message = error.description if isinstance(error, HTTPException) and code != 500 else \
            "An unexpected error occurred. It has been logged."
        return render_template("error.html", code=code, title=_ERROR_TITLES.get(code, "Error"),
                               message=message), code

    for code in _ERROR_TITLES:
        app.register_error_handler(code, handle_error)

    return app


def _configure_logging(app):
    handler = RotatingFileHandler(app.config["LOG_FILE"], maxBytes=2_000_000, backupCount=3, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    handler.setLevel(logging.INFO)
    app.logger.addHandler(handler)
    app.logger.setLevel(logging.INFO)
