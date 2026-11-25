#!/usr/bin/env python3
"""Automated verification of UniPortal's security controls (Lab 1 Part 4: "Verifiable").

Usage (against YOUR OWN lab instance only):
    python3 tools/check_controls.py https://127.0.0.1:8443
    python3 tools/check_controls.py http://127.0.0.1:5000

Needs the 'requests' package (pre-installed on Kali). It deliberately locks the
'student3' account and a fake username, and leaves your IP needing a CAPTCHA for
15 minutes. Reset afterwards with:  python3 manage.py clear-failures
"""
import re
import sys

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)  # self-signed lab certificate

BASE = (sys.argv[1] if len(sys.argv) > 1 else "https://127.0.0.1:8443").rstrip("/")
HTTPS = BASE.startswith("https://")
STUDENT_PW = "Student#Pass2026"
CSRF_RE = re.compile(r'name="csrf_token" value="([^"]+)"')
EICAR = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + "EICAR-STANDARD-" + "ANTIVIRUS-TEST-FILE!$H+H*"
results = []


def check(story, name, ok, detail=""):
    results.append(ok)
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f"  ({detail})" if detail and not ok else ""))


def section(title):
    print(f"\n== {title}")


def session():
    s = requests.Session()
    s.verify = False
    return s


def token(s, path):
    match = CSRF_RE.search(s.get(BASE + path).text)
    return match.group(1) if match else ""


def login(s, username, password, extra=None):
    data = {"csrf_token": token(s, "/login"), "username": username, "password": password}
    data.update(extra or {})
    return s.post(BASE + "/login", data=data, allow_redirects=False)


def main():
    try:
        first = session().get(BASE + "/login", timeout=10)
    except requests.RequestException as exc:
        sys.exit(f"Cannot reach {BASE}: {exc}")

    section("Transport and browser hardening (ASVS V3, V12)")
    h = first.headers
    check(0, "Content-Security-Policy set", "default-src 'none'" in h.get("Content-Security-Policy", ""))
    check(0, "X-Frame-Options DENY (clickjacking)", h.get("X-Frame-Options") == "DENY")
    check(0, "X-Content-Type-Options nosniff", h.get("X-Content-Type-Options") == "nosniff")
    check(0, "Referrer-Policy no-referrer", h.get("Referrer-Policy") == "no-referrer")
    check(0, "Server banner hides framework/version", "werkzeug" not in h.get("Server", "").lower(), h.get("Server"))
    cookie = h.get("Set-Cookie", "")
    check(0, "Session cookie HttpOnly + SameSite", "HttpOnly" in cookie and "SameSite=Lax" in cookie, cookie)
    if HTTPS:
        check(0, "HSTS header present", "max-age" in h.get("Strict-Transport-Security", ""))
        check(0, "Session cookie Secure + __Host- prefix", "Secure" in cookie and cookie.startswith("__Host-"), cookie)
    else:
        print("  [SKIP] HSTS / Secure cookie checks need HTTPS")
    r = session().get(BASE + "/does-not-exist")
    check(0, "Error pages have no stack trace", r.status_code == 404 and "Traceback" not in r.text)

    section("Story 1 - Login (T1110 Brute Force, T1589 identity gathering)")
    r = session().get(BASE + "/", allow_redirects=False)
    check(1, "Unauthenticated access redirected to login", r.status_code == 302 and "/login" in r.headers.get("Location", ""))
    r = session().post(BASE + "/login", data={"username": "student1", "password": STUDENT_PW}, allow_redirects=False)
    check(1, "Login POST without CSRF token rejected", r.status_code == 400, r.status_code)
    r = login(session(), "' OR '1'='1' --", "x")
    check(1, "SQL injection in username fails safely", r.status_code == 401 and "Invalid username or password" in r.text)
    real = login(session(), "student1", "wrong-password-123")
    fake = login(session(), "no_such_user_x", "wrong-password-123")
    same = (real.status_code == fake.status_code and "Invalid username or password." in real.text
            and "Invalid username or password." in fake.text)
    check(1, "Same error for wrong password and unknown user (no enumeration)", same)

    s1 = session()
    s1.get(BASE + "/login")
    before = s1.cookies.copy()
    r = login(s1, "student1", STUDENT_PW)
    check(1, "Valid student login succeeds", r.status_code == 302 and r.headers.get("Location", "").endswith("/"))
    check(1, "Session cookie rotated on login (no session fixation)",
          any(c.value != before.get(c.name) for c in s1.cookies))

    section("Access control / IDOR (ASVS V8)")
    s2 = session()
    login(s2, "student2", STUDENT_PW)
    check(4, "student2 cannot read student1's message", s2.get(BASE + "/messages/1").status_code == 403)
    check(4, "student cannot open admin pages", s2.get(BASE + "/admin/users").status_code == 403)
    check(4, "student cannot open assignment of a course they don't take",
          s2.get(BASE + "/assignments/4").status_code == 403)

    section("Story 2 - Assignment upload (T1505.003 Web Shell, T1204.002 Malicious File)")
    def upload(sess, filename, content, mime="application/octet-stream"):
        t = token(sess, "/assignments/1")
        return sess.post(BASE + "/assignments/1/submit", data={"csrf_token": t},
                         files={"file": (filename, content, mime)}, allow_redirects=True)
    r = upload(s1, "shell.php", b"<?php system($_GET['c']); ?>")
    check(2, "PHP web shell rejected (extension allow-list)", "Only PDF, DOCX and TXT" in r.text)
    r = upload(s1, "shell.pdf", b"<?php system($_GET['c']); ?>")
    check(2, "Renamed .php -> .pdf rejected (magic-byte check)", "not a valid PDF" in r.text)
    r = upload(s1, "bad.pdf", b"%PDF-1.7\n1 0 obj << /OpenAction << /S /JavaScript /JS (app.alert(1)) >> >>")
    check(2, "PDF with embedded JavaScript rejected", "JavaScript" in r.text and "not accepted" in r.text)
    r = upload(s1, "eicar.txt", EICAR.encode())
    check(2, "EICAR malware test file blocked by AV scan", "rejected by the malware scanner" in r.text)
    r = upload(s1, "my-lab1.txt", "Lab 1 answers\n".encode(), "text/plain")
    check(2, "Valid TXT submission accepted with SHA-256 receipt", "SHA-256" in r.text and "Submitted" in r.text)
    match = re.search(r"/assignments/submissions/(\d+)/download", r.text)
    if match:
        url = BASE + match.group(0)
        d = s1.get(url)
        check(2, "Owner can download; served as attachment",
              d.status_code == 200 and "attachment" in d.headers.get("Content-Disposition", ""))
        check(2, "Other student cannot download the submission (IDOR)", s2.get(url).status_code == 403)
    else:
        check(2, "Submission download link present", False)

    section("Story 3 - Messaging (T1189 stored XSS, T1534 internal phishing)")
    page = s1.get(BASE + "/messages/new").text
    lecturer = re.search(r'<option value="(\d+)"[^>]*>Dr\. Aisha', page)
    if lecturer:
        payload = "<script>alert('xss')</script><img src=x onerror=alert(1)>"
        r = s1.post(BASE + "/messages/new", data={"csrf_token": token(s1, "/messages/new"), "to": lecturer.group(1),
                                                  "subject": "XSS test", "body": payload})
        sent = s1.get(BASE + "/messages/?box=sent").text
        mid = re.search(r"/messages/(\d+)\">XSS test", sent)
        body = s1.get(BASE + f"/messages/{mid.group(1)}").text if mid else ""
        check(3, "Stored XSS payload is HTML-encoded", "&lt;script&gt;" in body and "<script>alert" not in body)
    else:
        check(3, "Lecturer contact available", False)
    r = s1.post(BASE + "/messages/new", data={"csrf_token": token(s1, "/messages/new"), "to": "1",
                                              "subject": "hi", "body": "hi"})
    check(3, "Cannot message users outside your courses (e.g. admin)", "only message people" in r.text)

    section("Story 4 - Profile update (T1098 Account Manipulation)")
    t = token(s1, "/profile/")
    s1.post(BASE + "/profile/", data={"csrf_token": t, "email": "alex.wong@student.uni.example.edu",
                                      "phone": "+60 12-300 1001", "address": "Block A", "role": "admin",
                                      "user_id": "1"})
    check(4, "Mass assignment (role=admin) ignored", s1.get(BASE + "/admin/users").status_code == 403)
    t = token(s1, "/profile/")
    r = s1.post(BASE + "/profile/", data={"csrf_token": t, "email": "attacker@evil.example", "phone": "",
                                          "address": ""})
    check(4, "Email change requires current password", "current password is incorrect" in r.text)

    section("Session management (ASVS V7)")
    old_cookies = s1.cookies.copy()
    s1.post(BASE + "/logout", data={"csrf_token": token(s1, "/")})
    replay = session()
    replay.cookies.update(old_cookies)
    r = replay.get(BASE + "/", allow_redirects=False)
    check(0, "Old session cookie is dead after logout", r.status_code == 302)

    section("Brute-force protection: CAPTCHA + lockout (ASVS V6.3)")
    attacker = session()
    for _ in range(3):
        login(attacker, "student3", "guess-123456")
    r = attacker.get(BASE + "/login")
    r = login(attacker, "student3", "guess-123456")
    check(1, "CAPTCHA demanded after 3 failures", 'name="captcha"' in r.text)
    login(attacker, "student3", "guess-123456")
    r = login(attacker, "student3", STUDENT_PW)
    check(1, "Account locked: even the correct password is refused",
          r.status_code == 429 and "Too many failed sign-in attempts" in r.text)
    for _ in range(6):
        fake = login(attacker, "ghost_account", "guess-123456")
    check(1, "Unknown usernames get the identical lockout (no enumeration)",
          fake.status_code == 429 and "Too many failed sign-in attempts" in fake.text)

    passed = sum(results)
    print(f"\n{passed}/{len(results)} checks passed.")
    print("Note: student3 is now locked and this IP needs a CAPTCHA for 15 min. "
          "Reset with: python3 manage.py clear-failures")
    sys.exit(0 if passed == len(results) else 1)


if __name__ == "__main__":
    main()
