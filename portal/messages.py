"""Messaging module (Lab 1 user story 3 / Lab 2 TB03).

Controls: recipients limited to people you share a course with, output encoding of
message bodies (stored-XSS defence), sender identity shown from the server side,
object-level authorisation on read, length limits and send-rate limiting.
"""
import re

from flask import Blueprint, abort, current_app, flash, g, redirect, render_template, request, url_for

from . import audit, mailer, security
from .db import execute, now, query_all, query_one

bp = Blueprint("messages", __name__, url_prefix="/messages")
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def contacts(user):
    if user["role"] == "student":
        sql = ("SELECT u.id, u.full_name, u.role, GROUP_CONCAT(c.code, ', ') AS courses FROM enrollments e "
               "JOIN courses c ON c.id = e.course_id JOIN users u ON u.id = c.lecturer_id "
               "WHERE e.student_id = ? AND u.is_active = 1 GROUP BY u.id ORDER BY u.full_name")
    else:
        sql = ("SELECT u.id, u.full_name, u.role, GROUP_CONCAT(c.code, ', ') AS courses FROM courses c "
               "JOIN enrollments e ON e.course_id = c.id JOIN users u ON u.id = e.student_id "
               "WHERE c.lecturer_id = ? AND u.is_active = 1 GROUP BY u.id ORDER BY u.full_name")
    return query_all(sql, (user["id"],))


@bp.route("/")
@security.roles_required("student", "lecturer")
def index():
    box = "sent" if request.args.get("box") == "sent" else "inbox"
    if box == "inbox":
        rows = query_all(
            "SELECT m.id, m.subject, m.created_at, m.read_at, u.full_name AS other, u.role AS other_role "
            "FROM messages m JOIN users u ON u.id = m.sender_id WHERE m.recipient_id = ? "
            "ORDER BY m.created_at DESC, m.id DESC LIMIT 100", (g.user["id"],))
    else:
        rows = query_all(
            "SELECT m.id, m.subject, m.created_at, m.read_at, u.full_name AS other, u.role AS other_role "
            "FROM messages m JOIN users u ON u.id = m.recipient_id WHERE m.sender_id = ? "
            "ORDER BY m.created_at DESC, m.id DESC LIMIT 100", (g.user["id"],))
    return render_template("messages.html", rows=rows, box=box)


@bp.route("/<int:message_id>")
@security.roles_required("student", "lecturer")
def view(message_id):
    m = query_one(
        "SELECT m.*, s.full_name AS sender_name, s.role AS sender_role, r.full_name AS recipient_name "
        "FROM messages m JOIN users s ON s.id = m.sender_id JOIN users r ON r.id = m.recipient_id WHERE m.id = ?",
        (message_id,))
    if m is None:
        abort(404)
    uid = g.user["id"]
    if uid not in (m["sender_id"], m["recipient_id"]):
        security.deny(f"message {message_id}")
    if m["recipient_id"] == uid and m["read_at"] is None:
        execute("UPDATE messages SET read_at = ? WHERE id = ?", (now(), message_id))
    return render_template("message_view.html", m=m)


@bp.route("/new", methods=["GET", "POST"])
@security.roles_required("student", "lecturer")
def compose():
    user = g.user
    allowed = {c["id"]: c for c in contacts(user)}
    form = {"to": request.args.get("to", type=int), "subject": "", "body": ""}

    reply_to = request.args.get("reply", type=int)
    if reply_to and request.method == "GET":
        original = query_one("SELECT * FROM messages WHERE id = ? AND recipient_id = ?", (reply_to, user["id"]))
        if original:
            form["to"] = original["sender_id"]
            subject = original["subject"]
            form["subject"] = subject if subject.lower().startswith("re:") else f"Re: {subject}"[:120]

    if request.method == "POST":
        form = {
            "to": request.form.get("to", type=int),
            "subject": _CONTROL.sub("", (request.form.get("subject") or "").strip()),
            "body": _CONTROL.sub("", (request.form.get("body") or "").strip()),
        }
        errors = []
        if form["to"] not in allowed:
            audit.log_event("message.recipient_denied", outcome="failure", target=f"user:{form['to']}")
            errors.append("You can only message people who share a course with you.")
        if not 1 <= len(form["subject"]) <= 120:
            errors.append("Subject must be 1-120 characters.")
        if not 1 <= len(form["body"]) <= 5000:
            errors.append("Message must be 1-5000 characters.")
        recent = query_one("SELECT COUNT(*) AS n FROM messages WHERE sender_id = ? AND created_at > ?",
                           (user["id"], now() - 60))["n"]
        if recent >= current_app.config["MESSAGE_RATE_PER_MIN"]:
            audit.log_event("message.rate_limited", outcome="failure")
            errors.append("You are sending messages too quickly. Wait a minute and try again.")
        if not errors:
            cur = execute(
                "INSERT INTO messages (sender_id, recipient_id, subject, body, created_at) VALUES (?, ?, ?, ?, ?)",
                (user["id"], form["to"], form["subject"], form["body"], now()))
            audit.log_event("message.sent", target=f"message:{cur.lastrowid}", detail=f"to user:{form['to']}")
            mailer.notify_user(form["to"], "You have a new message on UniPortal",
                               f"{user['full_name']} sent you a message. Sign in to UniPortal to read it.\n"
                               "(Message content is not included in email for privacy.)")
            flash("Message sent.", "success")
            return redirect(url_for("messages.index", box="sent"))
        for e in errors:
            flash(e, "error")
    return render_template("message_new.html", contacts=list(allowed.values()), form=form)
