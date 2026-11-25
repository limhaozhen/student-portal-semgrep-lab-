"""Assignment Upload + View Assignment modules (Lab 1 user story 2 / Lab 2 TB02).

Controls: allow-listed types checked by extension AND content (magic bytes / structure),
size limit, active-content rejection, AV scan, random storage names outside the web
root, SHA-256 integrity hash + emailed receipt, object-level authorisation on download.
"""
import io
import math
import os
import re
import uuid
import zipfile
from datetime import datetime
from pathlib import Path

from flask import Blueprint, abort, current_app, flash, g, redirect, render_template, request, send_file, url_for
from werkzeug.utils import secure_filename

from . import audit, filescan, mailer, security
from .db import execute, get_db, now, query_all, query_one
from .views import lecturer_courses

bp = Blueprint("assignments", __name__, url_prefix="/assignments")

ALLOWED_TYPES = {
    "pdf": "application/pdf",
    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "txt": "text/plain",
}
_PDF_ACTIVE = re.compile(rb"/(?:JavaScript|JS|Launch|EmbeddedFile|RichMedia)(?![A-Za-z0-9])")
_STORED_NAME = re.compile(r"^[0-9a-f]{32}$")


# --------------------------------------------------------------------------- validation

def validate_upload(file_storage):
    """Return (error, ext, data). error is None when the file is acceptable."""
    if file_storage is None or not file_storage.filename:
        return "Choose a file to upload.", None, None
    name = file_storage.filename
    ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    if ext not in ALLOWED_TYPES:
        return "Only PDF, DOCX and TXT files are accepted.", None, None

    limit = current_app.config["MAX_UPLOAD_BYTES"]
    data = file_storage.stream.read(limit + 1)
    if len(data) > limit:
        return f"File is larger than {limit // (1024 * 1024)} MB.", None, None
    if not data:
        return "The file is empty.", None, None

    if ext == "pdf":
        if not data.startswith(b"%PDF-"):
            return "File content is not a valid PDF.", None, None
        if _PDF_ACTIVE.search(data):
            return "PDFs containing JavaScript, launch actions or embedded files are not accepted.", None, None
    elif ext == "docx":
        if not data.startswith(b"PK\x03\x04"):
            return "File content is not a valid DOCX document.", None, None
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                infos = archive.infolist()
                names = {i.filename for i in infos}
                if len(infos) > 1000 or sum(i.file_size for i in infos) > 50 * 1024 * 1024:
                    return "DOCX structure is suspicious (possible zip bomb).", None, None
                if "[Content_Types].xml" not in names or "word/document.xml" not in names:
                    return "File content is not a valid DOCX document.", None, None
                if any(n.lower().endswith("vbaproject.bin") for n in names):
                    return "Documents containing macros are not accepted.", None, None
        except zipfile.BadZipFile:
            return "File content is not a valid DOCX document.", None, None
    elif ext == "txt":
        if b"\x00" in data:
            return "Text files must not contain binary data.", None, None
        try:
            data.decode("utf-8")
        except UnicodeDecodeError:
            return "Text files must be UTF-8 encoded.", None, None
    return None, ext, data


def _display_name(raw_name, ext):
    base = secure_filename(raw_name.rsplit(".", 1)[0])[:100] or "submission"
    return f"{base}.{ext}"


# --------------------------------------------------------------------------- object-level authorisation

def _assignment_for_user(assignment_id):
    a = query_one(
        "SELECT a.*, c.code, c.name AS course_name, c.lecturer_id FROM assignments a "
        "JOIN courses c ON c.id = a.course_id WHERE a.id = ?", (assignment_id,))
    if a is None:
        abort(404)
    user = g.user
    if user["role"] == "lecturer" and a["lecturer_id"] == user["id"]:
        return a
    if user["role"] == "student" and query_one(
            "SELECT 1 FROM enrollments WHERE student_id = ? AND course_id = ?", (user["id"], a["course_id"])):
        return a
    security.deny(f"assignment {assignment_id}")


def _submission_for_user(submission_id):
    s = query_one(
        "SELECT s.*, a.title, a.max_score, a.course_id, c.lecturer_id FROM submissions s "
        "JOIN assignments a ON a.id = s.assignment_id JOIN courses c ON c.id = a.course_id WHERE s.id = ?",
        (submission_id,))
    if s is None:
        abort(404)
    user = g.user
    if (user["role"] == "student" and s["student_id"] == user["id"]) or \
            (user["role"] == "lecturer" and s["lecturer_id"] == user["id"]):
        return s
    security.deny(f"submission {submission_id}")


# --------------------------------------------------------------------------- routes

@bp.route("/")
@security.roles_required("student", "lecturer")
def index():
    uid = g.user["id"]
    if g.user["role"] == "student":
        rows = query_all(
            "SELECT a.id, a.title, a.due_at, a.max_score, c.code, s.submitted_at, s.score FROM assignments a "
            "JOIN courses c ON c.id = a.course_id "
            "JOIN enrollments e ON e.course_id = a.course_id AND e.student_id = ? "
            "LEFT JOIN submissions s ON s.assignment_id = a.id AND s.student_id = ? ORDER BY a.due_at", (uid, uid))
        return render_template("assignments.html", rows=rows, now_ts=now())
    rows = query_all(
        "SELECT a.id, a.title, a.due_at, a.max_score, c.code, "
        "(SELECT COUNT(*) FROM submissions s WHERE s.assignment_id = a.id) AS n_sub, "
        "(SELECT COUNT(*) FROM submissions s WHERE s.assignment_id = a.id AND s.score IS NULL) AS n_ungraded, "
        "(SELECT COUNT(*) FROM enrollments e WHERE e.course_id = a.course_id) AS n_students "
        "FROM assignments a JOIN courses c ON c.id = a.course_id WHERE c.lecturer_id = ? ORDER BY a.due_at", (uid,))
    return render_template("assignments.html", rows=rows, courses=lecturer_courses(uid), now_ts=now())


@bp.route("/new", methods=["POST"])
@security.roles_required("lecturer")
def create():
    form = request.form
    course_id = form.get("course_id", type=int)
    if course_id not in {c["id"] for c in lecturer_courses(g.user["id"])}:
        security.deny(f"create assignment in course {course_id}")

    title = (form.get("title") or "").strip()
    description = (form.get("description") or "").strip()
    errors = []
    if not 3 <= len(title) <= 120:
        errors.append("Title must be 3-120 characters.")
    if len(description) > 2000:
        errors.append("Description must be at most 2000 characters.")
    try:
        due_at = int(datetime.strptime(form.get("due_at", ""), "%Y-%m-%dT%H:%M").timestamp())
    except ValueError:
        errors.append("Enter a valid due date and time.")
        due_at = None
    try:
        max_score = float(form.get("max_score", "100"))
        if not math.isfinite(max_score) or not 1 <= max_score <= 1000:
            raise ValueError
    except ValueError:
        errors.append("Maximum score must be between 1 and 1000.")
        max_score = None
    if errors:
        for e in errors:
            flash(e, "error")
        return redirect(url_for("assignments.index"))

    cur = execute(
        "INSERT INTO assignments (course_id, title, description, due_at, max_score, created_by, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)", (course_id, title, description, due_at, max_score, g.user["id"], now()))
    audit.log_event("assignment.created", target=f"assignment:{cur.lastrowid}", detail=title)
    flash("Assignment published.", "success")
    return redirect(url_for("assignments.detail", assignment_id=cur.lastrowid))


@bp.route("/<int:assignment_id>")
@security.roles_required("student", "lecturer")
def detail(assignment_id):
    a = _assignment_for_user(assignment_id)
    if g.user["role"] == "student":
        sub = query_one("SELECT * FROM submissions WHERE assignment_id = ? AND student_id = ?",
                        (assignment_id, g.user["id"]))
        t = now()
        can_submit = sub is None or (sub["score"] is None and t <= a["due_at"])
        return render_template("assignment_detail.html", a=a, sub=sub, can_submit=can_submit, now_ts=t,
                               max_mb=current_app.config["MAX_UPLOAD_BYTES"] // (1024 * 1024))
    subs = query_all(
        "SELECT u.id AS student_id, u.full_name, p.id_number, s.id AS sub_id, s.original_name, s.size_bytes, "
        "s.sha256, s.scan_status, s.scan_detail, s.submitted_at, s.score, s.feedback FROM enrollments e "
        "JOIN users u ON u.id = e.student_id JOIN profiles p ON p.user_id = u.id "
        "LEFT JOIN submissions s ON s.assignment_id = ? AND s.student_id = u.id "
        "WHERE e.course_id = ? ORDER BY u.full_name", (assignment_id, a["course_id"]))
    return render_template("assignment_detail.html", a=a, subs=subs, now_ts=now())


@bp.route("/<int:assignment_id>/submit", methods=["POST"])
@security.roles_required("student")
def submit(assignment_id):
    a = _assignment_for_user(assignment_id)
    uid = g.user["id"]
    back = redirect(url_for("assignments.detail", assignment_id=assignment_id))
    existing = query_one("SELECT * FROM submissions WHERE assignment_id = ? AND student_id = ?", (assignment_id, uid))
    t = now()
    if existing and (existing["score"] is not None or t > a["due_at"]):
        flash("This submission can no longer be replaced.", "error")
        return back

    file_storage = request.files.get("file")
    error, ext, data = validate_upload(file_storage)
    if error:
        audit.log_event("submission.rejected", outcome="failure", target=f"assignment:{assignment_id}", detail=error)
        flash(error, "error")
        return back

    upload_dir = Path(current_app.config["UPLOAD_DIR"])
    upload_dir.mkdir(parents=True, exist_ok=True)
    stored_name = uuid.uuid4().hex          # never derived from user input, no extension
    path = upload_dir / stored_name

    verdict = filescan.builtin_check(data)
    if verdict:
        scan_status, scan_detail = verdict
    else:
        try:
            path.write_bytes(data)
            os.chmod(path, 0o600)
            scan_status, scan_detail = filescan.scan_file(path)
        except OSError as exc:  # e.g. host antivirus removed the file while it was being written
            scan_status, scan_detail = "infected", f"storage blocked: {exc.__class__.__name__}"
    if scan_status == "infected" or (scan_status != "clean" and current_app.config["AV_REQUIRED"]):
        path.unlink(missing_ok=True)
        action = "submission.malware_blocked" if scan_status == "infected" else "submission.scan_unavailable"
        audit.log_event(action, outcome="failure", target=f"assignment:{assignment_id}", detail=scan_detail)
        flash("The file was rejected by the malware scanner." if scan_status == "infected"
              else "Files cannot be accepted right now because the malware scanner is unavailable.", "error")
        return back

    digest = security.sha256_hex(data)
    display = _display_name(file_storage.filename, ext)
    values = (display, stored_name, ALLOWED_TYPES[ext], len(data), digest, scan_status, scan_detail, t)
    conn = get_db()
    if existing:
        conn.execute(
            "UPDATE submissions SET original_name = ?, stored_name = ?, mime_type = ?, size_bytes = ?, sha256 = ?, "
            "scan_status = ?, scan_detail = ?, submitted_at = ? WHERE id = ?", values + (existing["id"],))
        sub_id = existing["id"]
    else:
        cur = conn.execute(
            "INSERT INTO submissions (original_name, stored_name, mime_type, size_bytes, sha256, scan_status, "
            "scan_detail, submitted_at, assignment_id, student_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            values + (assignment_id, uid))
        sub_id = cur.lastrowid
    conn.commit()
    if existing:
        (upload_dir / existing["stored_name"]).unlink(missing_ok=True)

    late = t > a["due_at"]
    audit.log_event("submission.uploaded", target=f"submission:{sub_id}",
                    detail=f"sha256={digest} size={len(data)} scan={scan_status}{' LATE' if late else ''}")
    when = datetime.fromtimestamp(t).strftime("%d %b %Y %H:%M:%S")
    mailer.notify_user(uid, f"Submission receipt: {a['code']} - {a['title']}",
                       f"We received your submission for {a['code']} - {a['title']}.\n\n"
                       f"File: {display}\nSize: {len(data)} bytes\nSHA-256: {digest}\nReceived: {when}"
                       f"{' (LATE)' if late else ''}\n\nKeep this receipt as proof of submission.")
    flash("Submitted. A receipt with the file's SHA-256 fingerprint has been emailed to you.", "success")
    return back


@bp.route("/submissions/<int:submission_id>/download")
@security.roles_required("student", "lecturer")
def download(submission_id):
    s = _submission_for_user(submission_id)
    if not _STORED_NAME.match(s["stored_name"]):
        abort(404)
    path = Path(current_app.config["UPLOAD_DIR"]) / s["stored_name"]
    if not path.is_file():
        abort(404)
    if security.sha256_hex(path.read_bytes()) != s["sha256"]:
        audit.log_event("submission.integrity_failed", outcome="failure", target=f"submission:{submission_id}")
        abort(409, "This file failed its integrity check and has been withheld. The incident was logged.")
    audit.log_event("submission.downloaded", target=f"submission:{submission_id}")
    response = send_file(path, mimetype=s["mime_type"], as_attachment=True, download_name=s["original_name"],
                         max_age=0)
    response.headers["Content-Security-Policy"] = "default-src 'none'; sandbox"
    return response


@bp.route("/submissions/<int:submission_id>/grade", methods=["POST"])
@security.roles_required("lecturer")
def grade(submission_id):
    s = _submission_for_user(submission_id)
    back = redirect(url_for("assignments.detail", assignment_id=s["assignment_id"]))
    feedback = (request.form.get("feedback") or "").strip()
    try:
        score = float(request.form.get("score", ""))
        if not math.isfinite(score) or not 0 <= score <= s["max_score"]:
            raise ValueError
    except ValueError:
        flash(f"Score must be between 0 and {s['max_score']:g}.", "error")
        return back
    if len(feedback) > 2000:
        flash("Feedback must be at most 2000 characters.", "error")
        return back

    t = now()
    conn = get_db()
    conn.execute("UPDATE submissions SET score = ?, feedback = ?, graded_at = ?, graded_by = ? WHERE id = ?",
                 (score, feedback, t, g.user["id"], submission_id))
    conn.execute(
        "INSERT INTO grades (student_id, course_id, assessment, score, max_score, updated_at, updated_by) "
        "VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(student_id, course_id, assessment) DO UPDATE SET "
        "score = excluded.score, max_score = excluded.max_score, updated_at = excluded.updated_at, "
        "updated_by = excluded.updated_by",
        (s["student_id"], s["course_id"], s["title"], score, s["max_score"], t, g.user["id"]))
    conn.commit()
    previous = "none" if s["score"] is None else f"{s['score']:g}"
    audit.log_event("grade.updated", target=f"submission:{submission_id}",
                    detail=f"score {previous} -> {score:g}/{s['max_score']:g}")
    mailer.notify_user(s["student_id"], f"Graded: {s['title']}",
                       f"Your submission for '{s['title']}' has been graded. Sign in to UniPortal to see "
                       "your score and feedback.")
    flash("Grade saved and the student has been notified.", "success")
    return back
