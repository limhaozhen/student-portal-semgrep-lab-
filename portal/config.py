"""Configuration helpers. Every security knob can be overridden with an environment variable."""
import os
import secrets
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


def env_bool(name, default=False):
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def env_int(name, default):
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


def env_set(name, default):
    raw = os.environ.get(name, default)
    return {part.strip().lower() for part in raw.split(",") if part.strip()}


def instance_dir() -> Path:
    path = Path(os.environ.get("PORTAL_INSTANCE_DIR", BASE_DIR / "instance"))
    path.mkdir(parents=True, exist_ok=True)
    return path


def load_secret_key(folder: Path) -> str:
    """Secret used to sign the session cookie. Never hard-coded in source (ASVS V13)."""
    from_env = os.environ.get("PORTAL_SECRET_KEY")
    if from_env:
        return from_env
    key_file = folder / "secret_key"
    if key_file.exists():
        return key_file.read_text(encoding="utf-8").strip()
    key = secrets.token_hex(32)
    key_file.write_text(key, encoding="utf-8")
    try:
        os.chmod(key_file, 0o600)
    except OSError:
        pass
    return key


def build_config(folder: Path) -> dict:
    return {
        "DATABASE": str(folder / "portal.db"),
        "UPLOAD_DIR": str(folder / "uploads"),
        "LOG_FILE": str(folder / "portal.log"),
        "SECRET_KEY": load_secret_key(folder),
        "USE_HTTPS": env_bool("PORTAL_HTTPS", False),
        # Uploads (ASVS V5)
        "MAX_UPLOAD_BYTES": env_int("PORTAL_MAX_UPLOAD_MB", 5) * 1024 * 1024,
        "MAX_CONTENT_LENGTH": (env_int("PORTAL_MAX_UPLOAD_MB", 5) + 1) * 1024 * 1024,
        "AV_REQUIRED": env_bool("PORTAL_AV_REQUIRED", False),
        # Sessions (ASVS V7)
        "IDLE_TIMEOUT": env_int("PORTAL_IDLE_TIMEOUT", 15 * 60),
        "ABSOLUTE_TIMEOUT": env_int("PORTAL_ABSOLUTE_TIMEOUT", 8 * 60 * 60),
        # Brute-force protection (ASVS V6.3)
        "LOCKOUT_THRESHOLD": env_int("PORTAL_LOCKOUT_THRESHOLD", 5),
        "LOCKOUT_SECONDS": env_int("PORTAL_LOCKOUT_SECONDS", 15 * 60),
        "CAPTCHA_AFTER": env_int("PORTAL_CAPTCHA_AFTER", 3),
        "IP_CAPTCHA_AFTER": env_int("PORTAL_IP_CAPTCHA_AFTER", 10),
        "IP_BLOCK_THRESHOLD": env_int("PORTAL_IP_BLOCK_THRESHOLD", 50),
        # MFA (ASVS V6.5)
        "MFA_ENFORCED_ROLES": env_set("PORTAL_MFA_ENFORCED_ROLES", "lecturer,admin"),
        "MFA_ISSUER": os.environ.get("PORTAL_MFA_ISSUER", "UniPortal"),
        # Passwords (ASVS V6.2)
        "PASSWORD_MIN_LENGTH": env_int("PORTAL_PASSWORD_MIN_LENGTH", 12),
        # Messaging anti-automation
        "MESSAGE_RATE_PER_MIN": env_int("PORTAL_MESSAGE_RATE_PER_MIN", 5),
        # Email gateway (optional real SMTP; otherwise the outbox table is used)
        "SMTP_HOST": os.environ.get("PORTAL_SMTP_HOST", ""),
        "SMTP_PORT": env_int("PORTAL_SMTP_PORT", 587),
        "SMTP_USER": os.environ.get("PORTAL_SMTP_USER", ""),
        "SMTP_PASSWORD": os.environ.get("PORTAL_SMTP_PASSWORD", ""),
        "MAIL_FROM": os.environ.get("PORTAL_MAIL_FROM", "no-reply@uni.example.edu"),
    }
