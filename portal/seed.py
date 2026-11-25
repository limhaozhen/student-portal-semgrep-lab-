"""Create the database and fill it with demo data for the lab."""
import random
import time
from datetime import date, timedelta
from pathlib import Path

from werkzeug.security import generate_password_hash

from .db import connect, init_schema

# Demo credentials (test values only - change them or re-seed for anything beyond the lab).
DEMO_PASSWORDS = {
    "admin": "Admin#Secure2026",
    "lecturer": "Lecturer#Pass2026",
    "student": "Student#Pass2026",
}

USERS = [
    # username, role, full name, id number, email, phone
    ("admin", "admin", "System Administrator", "STF-0001", "it-admin@uni.example.edu", "+60 3-7000 0001"),
    ("lecturer1", "lecturer", "Dr. Aisha Rahman", "STF-1001", "aisha.rahman@uni.example.edu", "+60 3-7000 1001"),
    ("lecturer2", "lecturer", "Dr. Daniel Tan", "STF-1002", "daniel.tan@uni.example.edu", "+60 3-7000 1002"),
    ("student1", "student", "Alex Wong", "S2301001", "alex.wong@student.uni.example.edu", "+60 12-300 1001"),
    ("student2", "student", "Priya Nair", "S2301002", "priya.nair@student.uni.example.edu", "+60 12-300 1002"),
    ("student3", "student", "Muhammad Hafiz", "S2301003", "hafiz@student.uni.example.edu", "+60 12-300 1003"),
]

COURSES = [
    ("ASC3013", "Application Security", "lecturer1"),
    ("SWE3011", "Secure Software Engineering", "lecturer1"),
    ("NET3021", "Network Security", "lecturer2"),
]

ENROLMENTS = {
    "student1": ["ASC3013", "NET3021"],
    "student2": ["ASC3013", "SWE3011"],
    "student3": ["SWE3011", "NET3021"],
}


def seed(db_path, upload_dir, force=False):
    """Create and populate the database. Returns False if it already existed (and force is False)."""
    db_path, upload_dir = Path(db_path), Path(upload_dir)
    if db_path.exists() and not force:
        return False
    if force:
        for suffix in ("", "-wal", "-shm"):
            Path(str(db_path) + suffix).unlink(missing_ok=True)
        if upload_dir.exists():
            for f in upload_dir.iterdir():
                if f.is_file():
                    f.unlink()
    upload_dir.mkdir(parents=True, exist_ok=True)

    rng = random.Random(2026)
    t = int(time.time())
    conn = connect(db_path)
    init_schema(conn)

    ids = {}
    for username, role, full_name, id_number, email, phone in USERS:
        cur = conn.execute(
            "INSERT INTO users (username, password_hash, role, full_name, password_changed_at, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (username, generate_password_hash(DEMO_PASSWORDS[role]), role, full_name, t, t))
        ids[username] = cur.lastrowid
        conn.execute("INSERT INTO profiles (user_id, id_number, email, phone, address, updated_at) "
                     "VALUES (?, ?, ?, ?, ?, ?)", (cur.lastrowid, id_number, email, phone, None, t))

    course_ids = {}
    for code, name, lecturer in COURSES:
        cur = conn.execute("INSERT INTO courses (code, name, lecturer_id) VALUES (?, ?, ?)",
                           (code, name, ids[lecturer]))
        course_ids[code] = cur.lastrowid

    first_class = date(2026, 9, 7)
    for student, codes in ENROLMENTS.items():
        for code in codes:
            sid, cid = ids[student], course_ids[code]
            conn.execute("INSERT INTO enrollments (student_id, course_id) VALUES (?, ?)", (sid, cid))
            for assessment, max_score in (("Quiz 1", 20), ("Quiz 2", 20), ("Mid-term Test", 100)):
                score = round(rng.uniform(0.55, 0.97) * max_score, 1)
                conn.execute("INSERT INTO grades (student_id, course_id, assessment, score, max_score, updated_at, "
                             "updated_by) VALUES (?, ?, ?, ?, ?, ?, NULL)", (sid, cid, assessment, score, max_score, t))
            for week in range(8):
                status = rng.choices(["present", "late", "absent", "excused"], weights=[78, 8, 10, 4])[0]
                conn.execute("INSERT INTO attendance (student_id, course_id, class_date, status) VALUES (?, ?, ?, ?)",
                             (sid, cid, (first_class + timedelta(weeks=week)).isoformat(), status))

    day = 86400
    assignments = [
        ("ASC3013", "Lab 1 - ATT&CK to ASVS mapping", "Map each user story to ATT&CK techniques and ASVS 5.0 "
         "Level 2 controls. Submit as PDF or DOCX.", t + 7 * day, 100, "lecturer1"),
        ("ASC3013", "Lab 2 - STRIDE threat model", "Draw the Level 1 DFD, mark trust boundaries and complete "
         "the STRIDE tables.", t + 14 * day, 100, "lecturer1"),
        ("SWE3011", "Secure code review", "Review the provided module and report findings.", t + 10 * day, 50,
         "lecturer1"),
        ("NET3021", "Firewall rule-set report", "Explain each rule in your rule-set.", t - 2 * day, 40, "lecturer2"),
    ]
    for code, title, desc, due, max_score, lecturer in assignments:
        conn.execute("INSERT INTO assignments (course_id, title, description, due_at, max_score, created_by, "
                     "created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                     (course_ids[code], title, desc, due, max_score, ids[lecturer], t - 5 * day))

    conn.execute("INSERT INTO messages (sender_id, recipient_id, subject, body, created_at) VALUES (?, ?, ?, ?, ?)",
                 (ids["lecturer1"], ids["student1"], "Welcome to ASC3013",
                  "Hi Alex,\n\nWelcome to Application Security. Lab 1 is now open - submit it through the "
                  "Assignments page before the deadline.\n\nDr. Aisha", t - 2 * day))
    conn.execute("INSERT INTO messages (sender_id, recipient_id, subject, body, created_at) VALUES (?, ?, ?, ?, ?)",
                 (ids["lecturer2"], ids["student1"], "Firewall report",
                  "Reminder: the firewall report deadline has passed. Late submissions are flagged.", t - day))
    conn.commit()
    conn.close()
    return True
