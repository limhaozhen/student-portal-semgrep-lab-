"""Dashboard, grades and attendance (Lab 1 user story 1: "log in so I can view my grades")."""
from flask import Blueprint, g, render_template, request

from . import security
from .db import now, query_all, query_one

bp = Blueprint("views", __name__)


def lecturer_courses(user_id):
    return query_all("SELECT id, code, name FROM courses WHERE lecturer_id = ? ORDER BY code", (user_id,))


def _selected_course(courses):
    """Pick ?course=<id> but only from the lecturer's own courses (no IDOR)."""
    if not courses:
        return None
    wanted = request.args.get("course", type=int)
    if wanted is None:
        return courses[0]
    for course in courses:
        if course["id"] == wanted:
            return course
    security.deny(f"course {wanted} not taught by user")
    return None


@bp.route("/")
@security.login_required
def dashboard():
    user = g.user
    uid = user["id"]
    ctx = {}
    if user["role"] == "student":
        ctx["courses"] = query_all(
            "SELECT c.id, c.code, c.name, l.full_name AS lecturer FROM enrollments e "
            "JOIN courses c ON c.id = e.course_id JOIN users l ON l.id = c.lecturer_id "
            "WHERE e.student_id = ? ORDER BY c.code", (uid,))
        ctx["upcoming"] = query_all(
            "SELECT a.id, a.title, a.due_at, c.code, s.id AS sub_id FROM assignments a "
            "JOIN courses c ON c.id = a.course_id "
            "JOIN enrollments e ON e.course_id = a.course_id AND e.student_id = ? "
            "LEFT JOIN submissions s ON s.assignment_id = a.id AND s.student_id = ? "
            "WHERE a.due_at > ? ORDER BY a.due_at LIMIT 5", (uid, uid, now() - 3 * 86400))
        ctx["recent_grades"] = query_all(
            "SELECT gr.assessment, gr.score, gr.max_score, c.code FROM grades gr "
            "JOIN courses c ON c.id = gr.course_id WHERE gr.student_id = ? "
            "ORDER BY gr.updated_at DESC, gr.id DESC LIMIT 5", (uid,))
        ctx["attendance"] = query_one(
            "SELECT COUNT(*) AS total, SUM(CASE WHEN status IN ('present','late') THEN 1 ELSE 0 END) AS attended "
            "FROM attendance WHERE student_id = ?", (uid,))
    elif user["role"] == "lecturer":
        ctx["courses"] = query_all(
            "SELECT c.id, c.code, c.name, (SELECT COUNT(*) FROM enrollments e WHERE e.course_id = c.id) AS n_students "
            "FROM courses c WHERE c.lecturer_id = ? ORDER BY c.code", (uid,))
        ctx["to_grade"] = query_all(
            "SELECT s.id, s.submitted_at, a.id AS assignment_id, a.title, c.code, u.full_name FROM submissions s "
            "JOIN assignments a ON a.id = s.assignment_id JOIN courses c ON c.id = a.course_id "
            "JOIN users u ON u.id = s.student_id WHERE c.lecturer_id = ? AND s.score IS NULL "
            "ORDER BY s.submitted_at LIMIT 10", (uid,))
    else:
        since = now() - 86400
        ctx["stats"] = {
            "users": query_one("SELECT COUNT(*) AS n FROM users")["n"],
            "active_sessions": query_one("SELECT COUNT(*) AS n FROM sessions")["n"],
            "failed_logins": query_one(
                "SELECT COUNT(*) AS n FROM audit_log WHERE action IN ('login.failed','mfa.failed','login.captcha_failed') "
                "AND ts > ?", (since,))["n"],
            "lockouts": query_one("SELECT COUNT(*) AS n FROM audit_log WHERE action = 'account.locked' AND ts > ?",
                                  (since,))["n"],
            "authz_denied": query_one("SELECT COUNT(*) AS n FROM audit_log WHERE action = 'authz.denied' AND ts > ?",
                                      (since,))["n"],
        }
        ctx["recent"] = query_all("SELECT * FROM audit_log WHERE outcome = 'failure' ORDER BY id DESC LIMIT 10")
    return render_template("dashboard.html", **ctx)


@bp.route("/grades")
@security.roles_required("student", "lecturer")
def grades():
    user = g.user
    if user["role"] == "student":
        rows = query_all(
            "SELECT c.code, c.name, gr.assessment, gr.score, gr.max_score, gr.updated_at FROM grades gr "
            "JOIN courses c ON c.id = gr.course_id WHERE gr.student_id = ? ORDER BY c.code, gr.id", (user["id"],))
        return render_template("grades.html", rows=rows)

    courses = lecturer_courses(user["id"])
    course = _selected_course(courses)
    rows = []
    if course:
        rows = query_all(
            "SELECT u.full_name, p.id_number, gr.assessment, gr.score, gr.max_score FROM enrollments e "
            "JOIN users u ON u.id = e.student_id JOIN profiles p ON p.user_id = u.id "
            "LEFT JOIN grades gr ON gr.student_id = e.student_id AND gr.course_id = e.course_id "
            "WHERE e.course_id = ? ORDER BY u.full_name, gr.id", (course["id"],))
    return render_template("grades.html", rows=rows, courses=courses, course=course)


@bp.route("/attendance")
@security.roles_required("student", "lecturer")
def attendance():
    user = g.user
    summary_sql = ("COUNT(*) AS total, "
                   "SUM(CASE WHEN a.status IN ('present','late') THEN 1 ELSE 0 END) AS attended, "
                   "SUM(CASE WHEN a.status = 'absent' THEN 1 ELSE 0 END) AS absent")
    if user["role"] == "student":
        summary = query_all(
            f"SELECT c.id, c.code, c.name, {summary_sql} FROM attendance a JOIN courses c ON c.id = a.course_id "
            "WHERE a.student_id = ? GROUP BY c.id ORDER BY c.code", (user["id"],))
        records = query_all(
            "SELECT a.course_id, a.class_date, a.status FROM attendance a WHERE a.student_id = ? "
            "ORDER BY a.course_id, a.class_date", (user["id"],))
        return render_template("attendance.html", summary=summary, records=records)

    courses = lecturer_courses(user["id"])
    course = _selected_course(courses)
    summary = []
    if course:
        summary = query_all(
            f"SELECT u.full_name, p.id_number, {summary_sql} FROM attendance a JOIN users u ON u.id = a.student_id "
            "JOIN profiles p ON p.user_id = u.id WHERE a.course_id = ? GROUP BY u.id ORDER BY u.full_name",
            (course["id"],))
    return render_template("attendance.html", summary=summary, courses=courses, course=course)
