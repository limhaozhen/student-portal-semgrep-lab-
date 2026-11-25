"""Email gateway (external service in the Lab 2 architecture).

Every notification is written to the mail_outbox table (viewable by the admin) so the
lab works offline. If PORTAL_SMTP_HOST is set, mail is also sent over SMTP + STARTTLS.
"""
import smtplib
import ssl
from email.message import EmailMessage

from flask import current_app

from .db import execute, now, query_one


def _one_line(text, limit=200):
    return " ".join(str(text).split())[:limit]


def send_mail(to_addr, subject, body):
    if not to_addr:
        return
    subject = _one_line(subject)
    to_addr = _one_line(to_addr, 254)
    execute("INSERT INTO mail_outbox (ts, to_addr, subject, body) VALUES (?, ?, ?, ?)",
            (now(), to_addr, subject, body))

    cfg = current_app.config
    if not cfg.get("SMTP_HOST"):
        return
    msg = EmailMessage()
    msg["From"] = cfg["MAIL_FROM"]
    msg["To"] = to_addr
    msg["Subject"] = subject
    msg.set_content(body)
    try:
        with smtplib.SMTP(cfg["SMTP_HOST"], cfg["SMTP_PORT"], timeout=10) as smtp:
            smtp.starttls(context=ssl.create_default_context())
            if cfg.get("SMTP_USER"):
                smtp.login(cfg["SMTP_USER"], cfg["SMTP_PASSWORD"])
            smtp.send_message(msg)
    except (OSError, smtplib.SMTPException) as exc:
        current_app.logger.warning("SMTP delivery failed: %s", exc)


def notify_user(user_id, subject, body):
    row = query_one(
        "SELECT p.email, u.full_name FROM profiles p JOIN users u ON u.id = p.user_id WHERE p.user_id = ?",
        (user_id,),
    )
    if row:
        send_mail(row["email"], subject, f"Hello {row['full_name']},\n\n{body}\n\n"
                  "If this wasn't you, contact the IT help desk immediately.\n- UniPortal")
