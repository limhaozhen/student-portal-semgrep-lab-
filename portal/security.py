"""Cross-cutting security controls: CSRF, security headers, access-control decorators,
brute-force throttling, CAPTCHA, password policy and TOTP verification."""
import hashlib
import hmac
import random
import re
import secrets
import threading
import time
from functools import wraps
from pathlib import Path

import pyotp
from flask import abort, current_app, g, redirect, request, session, url_for
from markupsafe import Markup

from . import audit
from .db import get_db, now, query_all, query_one

# --------------------------------------------------------------------------- helpers

def client_ip():
    # X-Forwarded-For is deliberately NOT trusted (it is attacker-controlled
    # unless a known reverse proxy sets it).
    return request.remote_addr or "unknown"


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# --------------------------------------------------------------------------- CSRF (ASVS V3.5)

def csrf_token():
    token = session.get("_csrf")
    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf"] = token
    return token


def csrf_field():
    return Markup('<input type="hidden" name="csrf_token" value="%s">') % csrf_token()


def csrf_protect():
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return None
    sent = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token", "")
    expected = session.get("_csrf", "")
    if not expected or not sent or not hmac.compare_digest(sent, expected):
        audit.log_event("csrf.rejected", outcome="failure", target=request.path)
        abort(400, "Your form has expired or is invalid (CSRF check failed). Reload the page and try again.")
    return None


# --------------------------------------------------------------------------- headers (ASVS V3.4)

CSP = ("default-src 'none'; style-src 'self'; img-src 'self'; form-action 'self'; "
       "frame-ancestors 'none'; base-uri 'none'")


def security_headers(response):
    h = response.headers
    h.setdefault("Content-Security-Policy", CSP)
    h["X-Content-Type-Options"] = "nosniff"
    h["X-Frame-Options"] = "DENY"
    h["Referrer-Policy"] = "no-referrer"
    h["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=()"
    h["Cross-Origin-Opener-Policy"] = "same-origin"
    h["Cross-Origin-Resource-Policy"] = "same-origin"
    # The "Server" banner is replaced at the HTTP-server level (see run.py) so the
    # framework and Python versions are not disclosed.
    if current_app.config.get("USE_HTTPS"):
        h["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    if request.endpoint != "static":
        h["Cache-Control"] = "no-store"
        h["Pragma"] = "no-cache"
    return response


# --------------------------------------------------------------------------- access control (ASVS V8)

def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if g.get("user") is None:
            return redirect(url_for("auth.login"))
        return view(*args, **kwargs)
    return wrapped


def roles_required(*roles):
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if g.get("user") is None:
                return redirect(url_for("auth.login"))
            if g.user["role"] not in roles:
                deny(f"role {g.user['role']} not in {','.join(roles)}")
            return view(*args, **kwargs)
        return wrapped
    return decorator


def deny(detail=None):
    """Log an authorisation failure and stop the request with 403."""
    audit.log_event("authz.denied", outcome="failure", target=request.path, detail=detail)
    abort(403)


# --------------------------------------------------------------------------- brute force (ASVS V6.3)

FAILURE_RETENTION = 24 * 60 * 60


def record_failure(*keys):
    t = now()
    conn = get_db()
    conn.executemany("INSERT INTO login_failures (key, ts) VALUES (?, ?)", [(k, t) for k in keys])
    conn.execute("DELETE FROM login_failures WHERE ts < ?", (t - FAILURE_RETENTION,))
    conn.commit()


def failure_count(key):
    window = current_app.config["LOCKOUT_SECONDS"]
    row = query_one("SELECT COUNT(*) AS n FROM login_failures WHERE key = ? AND ts > ?", (key, now() - window))
    return row["n"]


def lock_remaining(key):
    """Seconds until the account key unlocks (0 = not locked).

    Locked while there are >= LOCKOUT_THRESHOLD failures inside the LOCKOUT_SECONDS window.
    """
    cfg = current_app.config
    rows = query_all(
        "SELECT ts FROM login_failures WHERE key = ? AND ts > ? ORDER BY ts DESC LIMIT ?",
        (key, now() - cfg["LOCKOUT_SECONDS"], cfg["LOCKOUT_THRESHOLD"]),
    )
    if len(rows) < cfg["LOCKOUT_THRESHOLD"]:
        return 0
    return max(1, rows[-1]["ts"] + cfg["LOCKOUT_SECONDS"] - now())


def clear_failures(key):
    conn = get_db()
    conn.execute("DELETE FROM login_failures WHERE key = ?", (key,))
    conn.commit()


def captcha_required(user_key, ip_key):
    cfg = current_app.config
    return (failure_count(user_key) >= cfg["CAPTCHA_AFTER"]
            or failure_count(ip_key) >= cfg["IP_CAPTCHA_AFTER"])


def ip_blocked(ip_key):
    return failure_count(ip_key) >= current_app.config["IP_BLOCK_THRESHOLD"]


# --------------------------------------------------------------------------- CAPTCHA
# Self-hosted image CAPTCHA so the lab works offline. The answer never leaves the
# server (only a random nonce is stored in the signed session cookie).

_CAPTCHA_STORE = {}
_CAPTCHA_LOCK = threading.Lock()
_CAPTCHA_TTL = 300
_CAPTCHA_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
_rng = random.SystemRandom()


def new_captcha():
    answer = "".join(secrets.choice(_CAPTCHA_ALPHABET) for _ in range(5))
    nonce = secrets.token_urlsafe(16)
    t = time.time()
    with _CAPTCHA_LOCK:
        for key in [k for k, (_, exp) in _CAPTCHA_STORE.items() if exp < t]:
            del _CAPTCHA_STORE[key]
        if len(_CAPTCHA_STORE) > 10000:
            _CAPTCHA_STORE.clear()
        _CAPTCHA_STORE[nonce] = (answer, t + _CAPTCHA_TTL)
    session["captcha_nonce"] = nonce
    return nonce


def verify_captcha(user_answer):
    nonce = session.pop("captcha_nonce", None)
    if not nonce:
        return False
    with _CAPTCHA_LOCK:
        item = _CAPTCHA_STORE.pop(nonce, None)  # single use
    if not item or item[1] < time.time():
        return False
    return hmac.compare_digest((user_answer or "").strip().upper(), item[0])


def captcha_svg():
    nonce = session.get("captcha_nonce")
    with _CAPTCHA_LOCK:
        item = _CAPTCHA_STORE.get(nonce) if nonce else None
    if not item:
        return None
    text = item[0]
    width, height = 190, 64
    parts = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
             f'viewBox="0 0 {width} {height}">',
             f'<rect width="{width}" height="{height}" fill="#eef2f7"/>']
    for _ in range(8):
        parts.append(
            f'<line x1="{_rng.randint(0, width)}" y1="{_rng.randint(0, height)}" '
            f'x2="{_rng.randint(0, width)}" y2="{_rng.randint(0, height)}" '
            f'stroke="#{_rng.randint(0x777777, 0xBBBBBB):06x}" stroke-width="{_rng.randint(1, 2)}"/>')
    x = 16
    for ch in text:
        y = _rng.randint(38, 50)
        rot = _rng.randint(-28, 28)
        size = _rng.randint(28, 34)
        color = f"#{_rng.randint(0x10, 0x55):02x}{_rng.randint(0x10, 0x55):02x}{_rng.randint(0x40, 0x99):02x}"
        parts.append(f'<text x="{x}" y="{y}" font-family="monospace" font-size="{size}" font-weight="bold" '
                     f'fill="{color}" transform="rotate({rot} {x + 10} {y - 10})">{ch}</text>')
        x += 34
    for _ in range(40):
        parts.append(f'<circle cx="{_rng.randint(0, width)}" cy="{_rng.randint(0, height)}" r="1" fill="#556"/>')
    parts.append("</svg>")
    return "".join(parts)


# --------------------------------------------------------------------------- passwords (ASVS V6.2)

_COMMON_FILE = Path(__file__).with_name("common_passwords.txt")
_COMMON = set()
if _COMMON_FILE.exists():
    _COMMON = {line.strip().lower() for line in _COMMON_FILE.read_text(encoding="utf-8").splitlines()
               if line.strip() and not line.startswith("#")}
_CONTEXT_WORDS = ("password", "uniportal", "university")


def password_problems(password, username=""):
    """Length-based policy, no composition rules, block common/context-specific passwords."""
    min_len = current_app.config["PASSWORD_MIN_LENGTH"]
    problems = []
    if len(password) < min_len:
        problems.append(f"Password must be at least {min_len} characters long.")
    if len(password) > 128:
        problems.append("Password must be at most 128 characters long.")
    lowered = password.lower()
    if lowered in _COMMON:
        problems.append("That password is too common. Choose something less predictable.")
    if username and len(username) >= 3 and username.lower() in lowered:
        problems.append("Password must not contain your username.")
    for word in _CONTEXT_WORDS:
        if word in lowered:
            problems.append(f"Password must not contain the word '{word}'.")
    if password and len(set(password)) < 5:
        problems.append("Password uses too few different characters.")
    return problems


# --------------------------------------------------------------------------- TOTP (ASVS V6.5)

def verify_totp(secret, code, last_step):
    """Return the matched time-step, or None. Rejects re-use of an already used code."""
    code = (code or "").replace(" ", "").strip()
    if not secret or not re.fullmatch(r"\d{6}", code):
        return None
    totp = pyotp.TOTP(secret)
    current = int(time.time()) // totp.interval
    for step in (current - 1, current, current + 1):
        if step > (last_step or 0) and hmac.compare_digest(totp.generate_otp(step), code):
            return step
    return None
