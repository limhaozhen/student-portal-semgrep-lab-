# Student Portal Secure App 
This repository contains the secured reference version of the student portal application. 

## Features 
- Login 
- Assignment submission 
- Messaging 
- Profile update 

## Stack 
- Python Flask 
- MySQL / MariaDB 

## Security Testing 
This repository is configured to run Semgrep automatically using GitHub Actions.

# UniPortal – Secure Student Web Portal

A working student portal built from your two lab exercises:

* **Lab 1** – user stories → MITRE ATT&CK threats → OWASP ASVS 5.0 controls
* **Lab 2** – STRIDE threat model (DFD Level 1, trust boundaries, STRIDE per boundary)

Every control from those labs is implemented in code and can be tested from Kali.
See **[SECURITY_CONTROLS.md](SECURITY_CONTROLS.md)** for the full traceability
(threat → control → feature → file → how to verify).

Stack: Python 3 + Flask, SQLite, server-rendered HTML (no JavaScript at all, so the
Content-Security-Policy can be very strict).

**Lab 5 (SAST with Semgrep):** follow **[LAB5_GUIDE.md](LAB5_GUIDE.md)**. It covers the
pre-scan checks, the scan commands, building the HTML/JSON/CSV report with
`tools/semgrep_report.py`, and the triage of every finding.

---

## Features (the 4 user stories + the Lab 2 modules)

| Lab module | What you can do | Who |
|---|---|---|
| Login Module | Sign in with password + TOTP MFA, CAPTCHA after failures, lockout | everyone |
| Grades / Attendance | View your own grades & attendance; lecturers see their courses | student, lecturer |
| Assignment Upload | Upload PDF/DOCX/TXT (≤ 5 MB), virus-scanned, SHA-256 emailed receipt | student |
| View Assignment | Publish assignments, download submissions, grade + feedback | lecturer |
| Messaging | Lecturer ↔ student messages (only within shared courses) | student, lecturer |
| Update Profile | Change email/phone/address, password, MFA, sign out other sessions | everyone |
| Admin | Unlock / disable accounts, reset MFA, **audit log** (tamper-evident), email outbox | admin |

External services from the Lab 2 architecture:
* **Email gateway** – every notification is stored in an outbox (Admin → Email outbox). Set
  `PORTAL_SMTP_HOST` etc. to send real email.
* **Malware/AV for files** – built-in EICAR check + ClamAV when installed (`--with-clamav`).

## Demo accounts

| Username | Password | Role | Notes |
|---|---|---|---|
| `student1` | `Student#Pass2026` | student | Alex Wong – ASC3013, NET3021 |
| `student2` | `Student#Pass2026` | student | Priya Nair – ASC3013, SWE3011 |
| `student3` | `Student#Pass2026` | student | Muhammad Hafiz – SWE3011, NET3021 |
| `lecturer1` | `Lecturer#Pass2026` | lecturer | teaches ASC3013, SWE3011 |
| `lecturer2` | `Lecturer#Pass2026` | lecturer | teaches NET3021 |
| `admin` | `Admin#Secure2026` | admin | |

**Lecturers and admin must set up MFA on first sign-in** (scan the QR code with Google
Authenticator / Microsoft Authenticator / Authy). Students can turn it on from their
Profile. These are lab test credentials only.

---

## Moving it to Kali Linux

### 1. Copy the project into the Kali VM

Use `student-portal.zip`. Pick whichever transfer method suits your VM:

* **Drag-and-drop / shared folder** (VirtualBox Guest Additions or VMware Tools): copy
  `student-portal.zip` into `~/` on Kali.
* **Quick HTTP transfer from Windows**: in the folder that contains the zip, run
  `python -m http.server 8000` on Windows, then on Kali:
  ```bash
  wget http://<windows-ip>:8000/student-portal.zip
  ```
  (VirtualBox NAT: the Windows host is usually `10.0.2.2`. Allow the Windows Firewall prompt.
  Stop the server with Ctrl+C afterwards.)
* **GitHub**: push the `student-portal` folder to a *private* repo and `git clone` it on Kali.

### 2. Install and start (on Kali)

```bash
cd ~
unzip student-portal.zip
cd student-portal
bash setup_kali.sh                 # add --with-clamav for real antivirus scanning
bash run_kali.sh
```

Open Firefox in Kali at **https://127.0.0.1:8443**. The certificate is self-signed, so click
**Advanced → Accept the Risk and Continue**.

To reach it from your Windows host, put the VM on a *Bridged* or *Host-only* network (or add
a NAT port-forward for 8443) and browse to `https://<kali-ip>:8443` (`ip a` shows the IP).

### 3. Useful commands (run inside `student-portal/` on Kali)

```bash
.venv/bin/python manage.py clear-failures        # undo lockouts / CAPTCHA after testing
.venv/bin/python manage.py unlock student3       # unlock one account
.venv/bin/python manage.py reset-mfa lecturer1   # lost authenticator
.venv/bin/python manage.py verify-audit          # check the audit log hash chain
.venv/bin/python manage.py init-db --force       # wipe everything and re-seed demo data
PORTAL_MFA_ENFORCED_ROLES= bash run_kali.sh      # demo mode: don't force MFA on staff
```

**MFA tip:** TOTP codes depend on the clock. If codes are always rejected, sync the VM clock:
`sudo timedatectl set-ntp true` (and make sure your phone's time is automatic).

**Troubleshooting:** `$'\r': command not found` means the scripts got Windows line endings.
Fix with `sed -i 's/\r$//' *.sh` and run again. `Address already in use` → another copy is
running; stop it or use `PORTAL_PORT=9443 bash run_kali.sh`.

---

## Verifying the controls with Kali (Lab 1 Part 4 – "Verifiable")

Only test your own lab instance. Afterwards run `manage.py clear-failures`.

| What to verify | Kali command / action | Expected result |
|---|---|---|
| All controls at once | `python3 tools/check_controls.py https://127.0.0.1:8443` | 33/33 checks pass |
| Security headers | `curl -skI https://127.0.0.1:8443/login` | CSP, HSTS, X-Frame-Options, nosniff, no Werkzeug banner |
| TLS 1.2+ only | `sslscan 127.0.0.1:8443` or `nmap --script ssl-enum-ciphers -p 8443 127.0.0.1` | No SSLv3 / TLS 1.0 / 1.1 |
| Web scanner | `nikto -h https://127.0.0.1:8443` | No injection/XSS findings (self-signed cert notice is expected) |
| SQL injection | `sqlmap -u https://127.0.0.1:8443/login --data "username=a&password=b&csrf_token=x" --csrf-token=csrf_token --csrf-url=https://127.0.0.1:8443/login -p username --batch` | Not injectable (parameterised queries) |
| Brute force (T1110) | 3 wrong passwords in the browser, then more | CAPTCHA after 3, lock after 5 for 15 min, alert email in outbox |
| Username enumeration (T1589) | Wrong password for `student1` vs. user `nobody` | Identical message, status and lockout behaviour |
| Mass assignment | Burp Suite: intercept *Profile → Save*, add `&role=admin` | Ignored; `profile.unexpected_fields` in the audit log |
| IDOR | As `student2`, open `/messages/1` or another student's download link | 403 + `authz.denied` in the audit log |
| Malicious upload | Upload `shell.php`, or a PHP file renamed `.pdf` | Rejected by extension / magic-byte checks |
| Malware (EICAR) | `printf '%s%s' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$' 'EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > eicar.txt`, upload it | "rejected by the malware scanner" |
| Stored XSS | Send a message containing `<script>alert(1)</script>` | Shown as text, never executed |
| Audit log tampering (Repudiation) | `sudo apt install sqlite3`, then `sqlite3 instance/portal.db "DROP TRIGGER audit_log_no_update; UPDATE audit_log SET detail='edited' WHERE id=3;"` | Admin → Audit log shows **Hash chain BROKEN**; `manage.py verify-audit` exits 1 |

Note: Hydra's `http-post-form` module can't fetch the per-form CSRF token, so every Hydra
attempt is rejected with HTTP 400. That is the CSRF control working. Use Burp Intruder
(with a macro that fetches the token) or `tools/check_controls.py` to show the throttling.

---

## Running on Windows (optional, for development)

```bash
pip install -r requirements.txt
python run.py --http
```

Then open http://127.0.0.1:5000. Plain HTTP is for local testing only. Kali uses HTTPS.

## Project layout

```
student-portal/
├── run.py                 start the server (HTTPS with certs/, or --http)
├── manage.py              admin CLI (init-db, unlock, reset-mfa, verify-audit, ...)
├── setup_kali.sh          one-time Kali setup (venv, TLS cert, DB, optional ClamAV)
├── run_kali.sh            start on Kali (0.0.0.0:8443)
├── requirements.txt       Flask, pyotp, qrcode
├── tools/check_controls.py   automated security control tests (DAST-style)
├── tools/semgrep_report.py   Semgrep JSON -> HTML / JSON / CSV report (Lab 5)
├── tools/semgrep_triage.json triage verdicts for the Semgrep findings (Lab 5)
├── .semgrepignore         keeps .venv/, instance/, certs/ out of SAST scans
├── SECURITY_CONTROLS.md   Lab 1 + Lab 2 traceability
├── LAB5_GUIDE.md          Lab 5 step-by-step (Semgrep SAST)
└── portal/
    ├── __init__.py        app factory, cookie flags, error pages
    ├── auth.py            Login module, MFA, sessions          (story 1, TB01)
    ├── views.py           dashboard, grades, attendance        (story 1)
    ├── assignments.py     Assignment Upload + View Assignment  (story 2, TB02)
    ├── messages.py        Messaging                            (story 3, TB03)
    ├── profile.py         Update Profile                       (story 4, TB04)
    ├── admin.py           users, audit log, email outbox
    ├── security.py        CSRF, headers, RBAC, lockout, CAPTCHA, password policy, TOTP
    ├── audit.py           hash-chained, append-only audit log
    ├── filescan.py        AV scanning (EICAR + ClamAV)
    ├── mailer.py          email gateway (outbox + optional SMTP)
    ├── schema.sql         database (User, Assignment, Message, Profile stores)
    ├── seed.py            demo data
    ├── templates/         HTML (Jinja2, auto-escaped)
    └── static/style.css
```

Runtime data lives in `instance/` (database, uploads, `portal.log`, secret key) and is
created on first run.
