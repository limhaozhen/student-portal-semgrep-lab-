-- UniPortal schema (SQLite)
-- Data stores from the Lab 2 DFD: User, Profile, Assignment, Message (+ supporting tables).

PRAGMA foreign_keys = ON;

-- D1: User store ---------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    username            TEXT    NOT NULL UNIQUE,          -- stored lower-case
    password_hash       TEXT    NOT NULL,                 -- scrypt (Werkzeug), never plaintext
    role                TEXT    NOT NULL CHECK (role IN ('student', 'lecturer', 'admin')),
    full_name           TEXT    NOT NULL,
    is_active           INTEGER NOT NULL DEFAULT 1,
    mfa_enabled         INTEGER NOT NULL DEFAULT 0,
    mfa_secret          TEXT,
    mfa_pending_secret  TEXT,
    mfa_last_step       INTEGER NOT NULL DEFAULT 0,       -- TOTP replay protection
    password_changed_at INTEGER NOT NULL,
    created_at          INTEGER NOT NULL
);

-- Server-side sessions: only a SHA-256 of the session id is stored.
CREATE TABLE IF NOT EXISTS sessions (
    sid_hash   TEXT    PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL,
    last_seen  INTEGER NOT NULL,
    ip         TEXT,
    user_agent TEXT
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);

-- Failed authentication attempts, keyed by "u:<username>" and "ip:<address>".
-- Drives throttling, CAPTCHA and lockout (works the same for unknown usernames).
CREATE TABLE IF NOT EXISTS login_failures (
    id  INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT    NOT NULL,
    ts  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_login_failures_key_ts ON login_failures(key, ts);

-- D4: Profile store ------------------------------------------------------
CREATE TABLE IF NOT EXISTS profiles (
    user_id    INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    id_number  TEXT    NOT NULL UNIQUE,                   -- matric / staff number (read-only)
    email      TEXT    NOT NULL,
    phone      TEXT,
    address    TEXT,
    updated_at INTEGER NOT NULL
);

-- Academic data ----------------------------------------------------------
CREATE TABLE IF NOT EXISTS courses (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    code        TEXT    NOT NULL UNIQUE,
    name        TEXT    NOT NULL,
    lecturer_id INTEGER NOT NULL REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS enrollments (
    student_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    course_id  INTEGER NOT NULL REFERENCES courses(id) ON DELETE CASCADE,
    PRIMARY KEY (student_id, course_id)
);

CREATE TABLE IF NOT EXISTS grades (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    student_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    course_id  INTEGER NOT NULL REFERENCES courses(id) ON DELETE CASCADE,
    assessment TEXT    NOT NULL,
    score      REAL    NOT NULL,
    max_score  REAL    NOT NULL,
    updated_at INTEGER NOT NULL,
    updated_by INTEGER REFERENCES users(id),
    UNIQUE (student_id, course_id, assessment)
);

CREATE TABLE IF NOT EXISTS attendance (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    student_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    course_id  INTEGER NOT NULL REFERENCES courses(id) ON DELETE CASCADE,
    class_date TEXT    NOT NULL,
    status     TEXT    NOT NULL CHECK (status IN ('present', 'late', 'absent', 'excused')),
    UNIQUE (student_id, course_id, class_date)
);

-- D2: Assignment store ---------------------------------------------------
CREATE TABLE IF NOT EXISTS assignments (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    course_id   INTEGER NOT NULL REFERENCES courses(id) ON DELETE CASCADE,
    title       TEXT    NOT NULL,
    description TEXT    NOT NULL DEFAULT '',
    due_at      INTEGER NOT NULL,
    max_score   REAL    NOT NULL DEFAULT 100,
    created_by  INTEGER NOT NULL REFERENCES users(id),
    created_at  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS submissions (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    assignment_id INTEGER NOT NULL REFERENCES assignments(id) ON DELETE CASCADE,
    student_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    original_name TEXT    NOT NULL,
    stored_name   TEXT    NOT NULL UNIQUE,                -- random name, no extension
    mime_type     TEXT    NOT NULL,
    size_bytes    INTEGER NOT NULL,
    sha256        TEXT    NOT NULL,                       -- integrity + submission receipt
    scan_status   TEXT    NOT NULL,                       -- clean | unscanned | error
    scan_detail   TEXT,
    submitted_at  INTEGER NOT NULL,
    score         REAL,
    feedback      TEXT,
    graded_at     INTEGER,
    graded_by     INTEGER REFERENCES users(id),
    UNIQUE (assignment_id, student_id)
);

-- D3: Message store ------------------------------------------------------
CREATE TABLE IF NOT EXISTS messages (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    recipient_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    subject      TEXT    NOT NULL,
    body         TEXT    NOT NULL,
    created_at   INTEGER NOT NULL,
    read_at      INTEGER
);
CREATE INDEX IF NOT EXISTS idx_messages_recipient ON messages(recipient_id, created_at);
CREATE INDEX IF NOT EXISTS idx_messages_sender ON messages(sender_id, created_at);

-- Security audit log (Repudiation): append-only + hash-chained ----------
CREATE TABLE IF NOT EXISTS audit_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ts         INTEGER NOT NULL,
    user_id    INTEGER,
    username   TEXT,
    ip         TEXT,
    action     TEXT    NOT NULL,
    outcome    TEXT    NOT NULL,
    target     TEXT,
    detail     TEXT,
    prev_hash  TEXT    NOT NULL,
    entry_hash TEXT    NOT NULL
);

CREATE TRIGGER IF NOT EXISTS audit_log_no_update
BEFORE UPDATE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit_log is append-only');
END;

CREATE TRIGGER IF NOT EXISTS audit_log_no_delete
BEFORE DELETE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit_log is append-only');
END;

-- Email gateway outbox (lab stand-in for SMTP) ---------------------------
CREATE TABLE IF NOT EXISTS mail_outbox (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    ts      INTEGER NOT NULL,
    to_addr TEXT    NOT NULL,
    subject TEXT    NOT NULL,
    body    TEXT    NOT NULL
);
