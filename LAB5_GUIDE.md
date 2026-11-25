# Lab 5 – Secure Testing with SAST (Semgrep) on UniPortal

This guide walks through Lab 5 on Kali using this project. In the lab sheet the app file is
called `app_secure.py`. UniPortal is split into a `portal/` package instead, so you scan the
whole project folder.

> SAST reads the **source code**, so Semgrep must run where the code is: inside
> `~/student-portal` on Kali. If you have been running the portal on Windows, copy
> `student-portal.zip` into Kali first (README → *Moving it to Kali Linux*).

Use two terminal tabs on Kali:
**Tab A** runs the portal, **Tab B** is for testing and scanning.

---

## Step 0 – Get the project ready on Kali (first time only)

```bash
cd ~
unzip -o student-portal.zip
cd student-portal
bash setup_kali.sh
```

If you already set it up before, `unzip -o` just updates the files. The setup keeps your
certificate and database.

## Step 1 – Confirm the secured application works

**Tab A** – start the portal and leave it running:

```bash
cd ~/student-portal
bash run_kali.sh
```

**Tab B / Firefox** – open https://127.0.0.1:8443 (accept the self-signed certificate) and
check each point from the lab sheet. Take a screenshot of each for your report.

| Lab check | What to do | Expected result |
|---|---|---|
| Login works with valid credentials | Sign in as `student1` / `Student#Pass2026` | Dashboard: *Welcome, Alex Wong* |
| Wrong login returns a generic error | Sign out. Try `student1` + a wrong password, then `nobody` + any password | Both show exactly *Invalid username or password.* |
| Upload accepts allowed file types | As `student1`: **Assignments → Lab 1 – ATT&CK to ASVS mapping**, upload a `.pdf` or `.txt` | *Submitted…* and a SHA-256 receipt appear. (Uploading `test.php` is rejected: only PDF/DOCX/TXT are allowed) |
| Messaging works | **Messages → New message →** Dr. Aisha Rahman, send. Check **Sent**. The inbox already has 2 messages from lecturers | Message shown in *Sent*. As `lecturer1` it appears in the inbox |
| Profile update only edits the logged-in user | **Profile →** change Phone → *Save changes* | Only your own profile changes. The form has no user-ID field. Adding `user_id=2&role=admin` with Burp is ignored and logged |

Optional automated proof (33 checks, including all five above):

```bash
python3 tools/check_controls.py https://127.0.0.1:8443
```

That script deliberately locks `student3` and triggers the CAPTCHA, so reset afterwards:

```bash
.venv/bin/python manage.py clear-failures
```

## Step 2 – Install Semgrep in the virtual environment

```bash
cd ~/student-portal
source .venv/bin/activate
pip install semgrep
semgrep --version
```

Your prompt now starts with `(.venv)`. The install takes a few minutes and needs internet.

## Step 3 – Run the scan

Readable output in the terminal (screenshot this for the report):

```bash
semgrep scan --config auto .
```

Save the full results as JSON (this is the file your report is built from):

```bash
semgrep scan --config auto . --json -o semgrep-results.json
```

Optional extra formats:

```bash
semgrep scan --config auto . --sarif -o semgrep-results.sarif
```
```bash
semgrep scan --config auto . --text -o semgrep-results.txt
```

What you will see:
* The banner shows *Semgrep Code (SAST) ✗* and *Supply Chain ✗*. Those are the paid cloud
  products. The free **Semgrep OSS** rules still run, exactly as in the lab screenshots.
  `semgrep login` is not needed.
* `.semgrepignore` excludes `.venv/`, `instance/` (database, uploads, logs, secret key) and
  `certs/`. Without it Semgrep would scan thousands of library files (the lab screenshot shows
  5753 files because its venv was scanned).
* Warnings like *Syntax error … `{% extends "base.html" %}` was unexpected* are normal. The
  HTML parser does not understand Jinja tags, so it partially parses those templates.
* Expect roughly **20 findings (about 3 High / 17 Medium)**. In a test scan with Semgrep 1.186
  I got exactly 20. `--config auto` picks rules from the registry, so your count may differ a
  little.

Quick summary in the terminal with `jq` (install it with `sudo apt install jq` if missing):

```bash
jq '.results | length' semgrep-results.json
```
```bash
jq -r '.results[].extra.severity' semgrep-results.json | sort | uniq -c
```
```bash
jq -r '.results[].path' semgrep-results.json | sort | uniq -c | sort -rn
```
```bash
jq -r '.results[].check_id' semgrep-results.json | sort | uniq -c | sort -rn
```

## Step 4 – Build the detailed report (Task 1)

```bash
python3 tools/semgrep_report.py semgrep-results.json --triage tools/semgrep_triage.json
```

It creates three files in the project folder:

| File | What it is |
|---|---|
| `semgrep-report.html` | Full report: summary, findings by severity and verdict, affected files, top rule IDs, remediation focus, and every finding with the code lines, CWE, OWASP, confidence and triage |
| `semgrep-summary.json` | The same summary as structured JSON (what the lab means by "export … nicely in a file using JSON") |
| `semgrep-findings.csv` | One row per finding, which you can open in LibreOffice Calc / Excel |

Open the report, and save it as PDF for Moodle (Ctrl+P → *Save to PDF*):

```bash
firefox semgrep-report.html &
```

Without `--triage`, every finding shows **Not triaged**. That's useful if you want to do the
triage yourself from scratch.

## Step 5 – Review the findings (triage)

SAST reports *patterns*, not proven vulnerabilities. For each finding, open the code and decide:
**true positive** (real bug → fix it), **false positive** (the pattern matched but it isn't
exploitable), or **accepted risk** (low risk, documented). Open a finding's code like this:

```bash
sed -n '140,150p' portal/assignments.py
```

What the scan of UniPortal finds, and why:

| Rule (count) | Severity | Where | Verdict | Why |
|---|---|---|---|---|
| `tainted-sql-string` (2: Flask + Django variants) | High | `assignments.py:146` | False positive | The line is a **log message** `f"create assignment in course {course_id}"`. The rule matched the SQL keyword *create*. Real queries all use `?` placeholders (`db.py`) and `course_id` is already an int |
| `nan-injection` (1) | High | `assignments.py:299` | False positive (mitigated) | `float()` of the score is followed by `math.isfinite()` and a range check, so `nan`/`inf` are rejected |
| `make-response-with-unknown-content` (1) | Medium | `auth.py:181` | False positive | CAPTCHA SVG is built on the server from a fixed alphabet. No user input, served as `image/svg+xml` with a strict CSP |
| `explicit-unescape-with-markup` (1) | Medium | `auth.py:240` | Accepted risk (low) | `Markup()` on the QR-code SVG from the `qrcode` library. Input becomes QR geometry, not HTML. Hardening option: serve it via `<img src="/mfa/qr.svg">` |
| `django-no-csrf-token` (15) | Medium | every POST form in `templates/` | False positive | A **Django** rule looking for `{% csrf_token %}`. This Flask app uses `{{ csrf_field() }}` and rejects POSTs without a token. The DAST check *Login POST without CSRF token rejected* proves it |

Points worth making in your report:
* **SAST vs DAST together:** Semgrep raised 15 CSRF warnings, and the live test (Step 1 /
  `check_controls.py`) proves CSRF protection works. Each tool covers the other's blind spots.
* **Wrong-framework rules:** `--config auto` ran Django rules on a Flask project. Tuning the
  rule set (`--exclude-rule …`) reduces noise.
* **Metadata quality:** Semgrep labels `tainted-sql-string` with CWE-915 / CWE-704, but SQL
  injection is **CWE-89**. Checking tool output critically is part of the job.
* **Result:** 0 confirmed vulnerabilities. The secure design (parameterised SQL, escaping,
  CSRF, strict CSP) already prevents the patterns Semgrep looks for.

The verdicts are pre-filled in `tools/semgrep_triage.json`. Check each one against the
code and rewrite the reasons in your own words before you submit. If your scan shows a rule
not listed in that file, it appears as **Not triaged**. Analyse it yourself and add an entry.

### Optional: show that Semgrep does catch real bugs

To show how SAST helps "detect issues early before deployment", scan a deliberately insecure
version of the same features. It goes in a separate folder so it doesn't mix with the portal's
results:

```bash
mkdir -p ~/sast-demo && cat > ~/sast-demo/insecure_portal.py <<'EOF'
# Deliberately INSECURE example - for comparing SAST results only. Never run or deploy.
import sqlite3
import subprocess

from flask import Flask, render_template_string, request

app = Flask(__name__)
app.secret_key = "supersecret123"


@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"]
    db = sqlite3.connect("portal.db")
    row = db.execute(f"SELECT * FROM users WHERE username = '{username}'").fetchone()
    if row is None:
        return render_template_string("<p>No account called " + username + "</p>")
    return "ok"


@app.route("/ping")
def ping():
    host = request.args.get("host")
    return subprocess.check_output("ping -c 1 " + host, shell=True)


@app.route("/profile/update", methods=["POST"])
def update_profile():
    user_id = request.form["user_id"]
    email = request.form["email"]
    db = sqlite3.connect("portal.db")
    db.execute("UPDATE profiles SET email = '%s' WHERE user_id = %s" % (email, user_id))
    db.commit()
    return "updated"


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)
EOF
```
```bash
semgrep scan --config auto ~/sast-demo/insecure_portal.py --json -o ~/sast-demo/semgrep-results.json
```
```bash
python3 tools/semgrep_report.py ~/sast-demo/semgrep-results.json --root ~/sast-demo --title "SAST Report - insecure demo"
```

In my test run this 38-line file produced **19 findings (9 High)**. All of them are real: SQL
injection (`tainted-sql-string`, `formatted-sql-query`), command injection
(`subprocess-shell-true`), template injection / XSS (`render-template-string`,
`raw-html-format`), `debug-enabled` and binding to `0.0.0.0`. Comparing it with UniPortal (20
findings, none exploitable) shows the difference between insecure code and secure-by-design code.

## Step 6 – Fill in the Moodle form (Task 2)

Where to find each value:

| Form field (typical) | Where to get it |
|---|---|
| Tool and version | `semgrep --version`, or the report header |
| Command used | `semgrep scan --config auto . --json -o semgrep-results.json` |
| Scan date | Report header |
| Scope / target | `student-portal` (Python `portal/*.py`, Jinja templates, shell scripts). Excluded: `.venv/`, `instance/`, `certs/` (see `.semgrepignore`) |
| Files scanned | Report → *Files scanned* card |
| Total findings | Report → *Total findings* |
| Findings by severity | Report → severity cards (High / Medium / Low) |
| Affected files | Report section 3 |
| Most important rule IDs | Report section 4 (sorted by severity, then count) |
| CWE / OWASP | Report section 4 and each finding in section 6 |
| True vs false positives | Report section 2 (verdict table) |
| Remediation focus | Report section 5 |
| Conclusion | e.g. "No confirmed vulnerabilities. All High findings were false positives caused by keyword heuristics (log message containing 'create') or already-mitigated input (NaN check). 15 Medium findings came from a Django-only CSRF rule. CSRF protection was verified with DAST." |

Attach: `semgrep-report.pdf` (printed from the HTML), `semgrep-results.json`, and your
terminal screenshots from Steps 1 and 3.

---

### Troubleshooting

| Problem | Fix |
|---|---|
| `semgrep: command not found` | Run `source .venv/bin/activate` first (prompt shows `(.venv)`) |
| `--config auto` fails / asks about metrics | It needs internet and anonymous metrics. Alternative: `semgrep scan --config p/default --config p/python --config p/flask --metrics off .` |
| Scan includes thousands of files | You're not in `~/student-portal`, or `.semgrepignore` is missing |
| Report shows no code lines | Run `semgrep_report.py` from the project folder, or pass `--root ~/student-portal` |
| Can't sign in after `check_controls.py` | `.venv/bin/python manage.py clear-failures` |
