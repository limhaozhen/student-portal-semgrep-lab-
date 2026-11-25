#!/usr/bin/env python3
"""Turn Semgrep JSON output into a readable SAST report (Lab 5).

    semgrep scan --config auto . --json -o semgrep-results.json
    python3 tools/semgrep_report.py semgrep-results.json --triage tools/semgrep_triage.json

Writes three files next to the input (or into --out-dir):
    semgrep-report.html    full report to open in a browser / print to PDF
    semgrep-summary.json   structured summary (totals, severity, files, rules, findings)
    semgrep-findings.csv   one row per finding, for spreadsheets / the Moodle form

Only the Python standard library is used.
"""
import argparse
import csv
import html
import json
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

SEVERITY_ORDER = {"CRITICAL": 0, "ERROR": 1, "HIGH": 1, "WARNING": 2, "MEDIUM": 2, "INFO": 3, "LOW": 3}
SEVERITY_LABEL = {"CRITICAL": "Critical", "ERROR": "High", "HIGH": "High", "WARNING": "Medium",
                  "MEDIUM": "Medium", "INFO": "Low", "LOW": "Low"}


def as_list(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def sev_rank(sev):
    return SEVERITY_ORDER.get(str(sev).upper(), 9)


def sev_label(sev):
    return SEVERITY_LABEL.get(str(sev).upper(), str(sev).title())


def short_rule(check_id):
    return check_id.rsplit(".", 1)[-1]


def load_triage(path):
    if not path:
        return {}
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return data.get("rules", data)


def triage_for(check_id, triage):
    """Match by full rule id first, then by the last segment of the id."""
    return triage.get(check_id) or triage.get(short_rule(check_id)) or {}


def snippet(root, path, start, end, context=2):
    file = root / path
    try:
        lines = file.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    lo, hi = max(1, start - context), min(len(lines), end + context)
    return [(n, lines[n - 1], start <= n <= end) for n in range(lo, hi + 1)]


def first_sentences(text, n=2):
    parts = text.replace("\n", " ").split(". ")
    out = ". ".join(parts[:n]).strip()
    return out if out.endswith(".") else out + "."


def build(data, triage, root):
    findings = []
    for r in data.get("results", []):
        extra = r.get("extra", {})
        meta = extra.get("metadata", {})
        path = r["path"].replace("\\", "/")
        start, end = r["start"]["line"], r["end"]["line"]
        t = triage_for(r["check_id"], triage)
        findings.append({
            "rule_id": r["check_id"],
            "rule": short_rule(r["check_id"]),
            "severity": extra.get("severity", "UNKNOWN"),
            "severity_label": sev_label(extra.get("severity", "")),
            "file": path,
            "line": start,
            "end_line": end,
            "message": " ".join(extra.get("message", "").split()),
            "cwe": as_list(meta.get("cwe")),
            "owasp": as_list(meta.get("owasp")),
            "confidence": meta.get("confidence", ""),
            "likelihood": meta.get("likelihood", ""),
            "impact": meta.get("impact", ""),
            "subcategory": ", ".join(as_list(meta.get("subcategory"))),
            "vulnerability_class": ", ".join(as_list(meta.get("vulnerability_class"))),
            "references": as_list(meta.get("references"))[:3],
            "rule_url": meta.get("shortlink") or meta.get("source", ""),
            "verdict": t.get("verdict", "Not triaged"),
            "triage_reason": t.get("reason", ""),
            "remediation": t.get("remediation") or first_sentences(extra.get("message", "")),
            "code": snippet(root, path, start, end),
        })
    findings.sort(key=lambda f: (sev_rank(f["severity"]), f["file"], f["line"]))

    by_sev = Counter(f["severity_label"] for f in findings)
    by_file = Counter(f["file"] for f in findings)
    rules = defaultdict(list)
    for f in findings:
        rules[f["rule_id"]].append(f)
    rule_rows = sorted(
        ({"rule_id": rid, "rule": fs[0]["rule"], "severity": fs[0]["severity"],
          "severity_label": fs[0]["severity_label"], "count": len(fs), "cwe": fs[0]["cwe"],
          "owasp": fs[0]["owasp"], "confidence": fs[0]["confidence"], "verdict": fs[0]["verdict"],
          "remediation": fs[0]["remediation"], "files": sorted({x["file"] for x in fs})}
         for rid, fs in rules.items()),
        key=lambda r: (sev_rank(r["severity"]), -r["count"], r["rule_id"]))
    verdicts = Counter(f["verdict"] for f in findings)
    scanned = data.get("paths", {}).get("scanned", [])
    return {
        "generated": datetime.now().strftime("%Y-%m-%d %H:%M"),
        "semgrep_version": data.get("version", "unknown"),
        "total_findings": len(findings),
        "files_scanned": len(scanned),
        "scan_errors": len(data.get("errors", [])),
        "by_severity": {k: by_sev.get(k, 0) for k in ("Critical", "High", "Medium", "Low") if by_sev.get(k, 0)}
                       | {k: v for k, v in by_sev.items() if k not in ("Critical", "High", "Medium", "Low")},
        "by_file": dict(by_file.most_common()),
        "rules": rule_rows,
        "verdicts": dict(verdicts.most_common()),
        "findings": findings,
        "errors": [{"type": str(e.get("type", ""))[:80], "message": str(e.get("message", "")).splitlines()[0][:200]}
                   for e in data.get("errors", [])],
    }


# --------------------------------------------------------------------------- outputs

def write_json(summary, out):
    clean = dict(summary)
    clean["findings"] = [{k: v for k, v in f.items() if k != "code"} for f in summary["findings"]]
    out.write_text(json.dumps(clean, indent=2), encoding="utf-8")


def write_csv(summary, out):
    cols = ["severity_label", "rule_id", "file", "line", "cwe", "owasp", "confidence", "verdict", "message",
            "remediation"]
    with out.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["#", "Severity", "Rule ID", "File", "Line", "CWE", "OWASP", "Confidence", "Verdict", "Message",
                    "Remediation"])
        for i, f in enumerate(summary["findings"], 1):
            w.writerow([i] + ["; ".join(f[c]) if isinstance(f[c], list) else f[c] for c in cols])


def e(text):
    return html.escape(str(text))


def badge(label):
    cls = {"Critical": "crit", "High": "high", "Medium": "med", "Low": "low"}.get(label, "low")
    return f'<span class="sev {cls}">{e(label)}</span>'


def verdict_badge(v):
    low = v.lower()
    cls = "tp" if "true" in low else ("fp" if "false" in low else ("ar" if "accept" in low else "nt"))
    return f'<span class="verdict {cls}">{e(v)}</span>'


def write_html(summary, out, title, target):
    s = summary
    sev_cards = "".join(f'<div class="card"><div class="k">{e(k)}</div><div class="v">{v}</div></div>'
                        for k, v in s["by_severity"].items())
    actionable = sum(v for k, v in s["verdicts"].items()
                     if "false" not in k.lower() and "accept" not in k.lower())
    files_rows = "".join(f"<tr><td><code>{e(f)}</code></td><td class='n'>{n}</td></tr>" for f, n in s["by_file"].items())
    rule_rows = "".join(
        f"<tr><td>{badge(r['severity_label'])}</td><td><code>{e(r['rule_id'])}</code></td><td class='n'>{r['count']}</td>"
        f"<td>{e('; '.join(r['cwe']))}</td><td>{verdict_badge(r['verdict'])}</td></tr>" for r in s["rules"])
    focus = "".join(
        f"<li><strong>{e(r['rule'])}</strong> ({r['count']}&times;, {e(r['severity_label'])}, {e(r['verdict'])}): "
        f"{e(r['remediation'])}</li>" for r in s["rules"])
    verdict_rows = "".join(f"<tr><td>{verdict_badge(k)}</td><td class='n'>{v}</td></tr>" for k, v in s["verdicts"].items())

    details = []
    for i, f in enumerate(s["findings"], 1):
        code = "".join(f'<div class="ln{" hit" if hit else ""}"><span class="no">{n}</span>{e(src) or " "}</div>'
                       for n, src, hit in f["code"]) or "<div class='ln'>(source not available)</div>"
        refs = "".join(f'<li><a href="{e(u)}">{e(u)}</a></li>' for u in f["references"])
        rule_link = f' &middot; <a href="{e(f["rule_url"])}">rule</a>' if f["rule_url"] else ""
        details.append(f"""
<article class="finding" id="f{i}">
  <header><span class="idx">#{i}</span>{badge(f['severity_label'])}{verdict_badge(f['verdict'])}
    <code class="rid">{e(f['rule_id'])}</code></header>
  <p class="loc"><code>{e(f['file'])}:{f['line']}</code>{rule_link}</p>
  <pre class="code">{code}</pre>
  <table class="kv">
    <tr><th>Message</th><td>{e(f['message'])}</td></tr>
    <tr><th>CWE</th><td>{e('; '.join(f['cwe']) or '-')}</td></tr>
    <tr><th>OWASP</th><td>{e('; '.join(f['owasp']) or '-')}</td></tr>
    <tr><th>Confidence / Likelihood / Impact</th><td>{e(f['confidence'] or '-')} / {e(f['likelihood'] or '-')} / {e(f['impact'] or '-')}</td></tr>
    <tr><th>Rule type</th><td>{e(f['subcategory'] or '-')} {('&middot; ' + e(f['vulnerability_class'])) if f['vulnerability_class'] else ''}</td></tr>
    {'<tr><th>Triage</th><td>' + e(f['triage_reason']) + '</td></tr>' if f['triage_reason'] else ''}
    <tr><th>Remediation</th><td>{e(f['remediation'])}</td></tr>
    {'<tr><th>References</th><td><ul>' + refs + '</ul></td></tr>' if refs else ''}
  </table>
</article>""")

    errors = "".join(f"<li><code>{e(x['type'])}</code> {e(x['message'])}</li>" for x in s["errors"])
    page = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{e(title)}</title>
<style>
:root{{--bg:#f5f6f9;--card:#fff;--text:#1c2230;--muted:#5e6779;--border:#dde1ea;--code:#f3f4f8;--hit:#fff4cc;
--crit:#7a1020;--high:#b42318;--med:#a15c00;--low:#2459a8;--tp:#b42318;--fp:#11703f;--ar:#6b4bb5;--nt:#5e6779}}
@media (prefers-color-scheme:dark){{:root{{--bg:#10141b;--card:#171c25;--text:#e4e8ef;--muted:#9aa3b4;--border:#2b3341;
--code:#1d2330;--hit:#3a3214;--crit:#ff8a99;--high:#ff7b6e;--med:#f2b24c;--low:#7fb0ff;--tp:#ff7b6e;--fp:#5fd39a;--ar:#b9a3ff;--nt:#9aa3b4}}}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--text);font:14px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,Ubuntu,sans-serif}}
main{{max-width:1100px;margin:0 auto;padding:24px 16px 48px}}h1{{margin:0 0 4px;font-size:24px}}h2{{margin:32px 0 10px;font-size:18px}}
.muted{{color:var(--muted)}}code{{font-family:ui-monospace,"DejaVu Sans Mono",Menlo,monospace;font-size:12.5px}}
.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:10px;margin:16px 0}}
.card{{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:12px 14px}}.k{{color:var(--muted);font-size:12px}}.v{{font-size:26px;font-weight:650}}
table{{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--border);border-radius:10px;overflow:hidden}}
th,td{{text-align:left;padding:7px 10px;border-bottom:1px solid var(--border);vertical-align:top}}th{{color:var(--muted);font-size:12px;font-weight:600}}
td.n{{text-align:right;font-variant-numeric:tabular-nums}}.wrap{{overflow-x:auto}}
.sev,.verdict{{display:inline-block;padding:1px 8px;border-radius:99px;font-size:11.5px;font-weight:650;border:1px solid currentColor;margin-right:6px;white-space:nowrap}}
.crit{{color:var(--crit)}}.high{{color:var(--high)}}.med{{color:var(--med)}}.low{{color:var(--low)}}
.verdict.tp{{color:var(--tp)}}.verdict.fp{{color:var(--fp)}}.verdict.ar{{color:var(--ar)}}.verdict.nt{{color:var(--nt)}}
.finding{{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:14px;margin:12px 0;break-inside:avoid}}
.finding header{{display:flex;flex-wrap:wrap;align-items:center;gap:4px}}.idx{{font-weight:700;margin-right:6px}}.rid{{overflow-wrap:anywhere}}
.loc{{margin:6px 0}}pre.code{{background:var(--code);border-radius:8px;padding:8px 0;overflow-x:auto;margin:8px 0}}
.ln{{white-space:pre;padding:0 10px;font-family:ui-monospace,"DejaVu Sans Mono",Menlo,monospace;font-size:12.5px}}.ln.hit{{background:var(--hit)}}
.no{{display:inline-block;width:42px;color:var(--muted);user-select:none}}.kv th{{width:210px}}.kv{{font-size:13px}}
ul{{margin:4px 0;padding-left:20px}}a{{color:var(--low);overflow-wrap:anywhere}}
@media print{{body{{background:#fff}}.finding,table,.card{{border-color:#ccc}}a{{color:#000}}}}
</style></head><body><main>
<h1>{e(title)}</h1>
<p class="muted">Target: <code>{e(target)}</code> &middot; Semgrep {e(s['semgrep_version'])} &middot; Report generated {e(s['generated'])}</p>

<h2>1. Executive summary</h2>
<div class="cards">
  <div class="card"><div class="k">Total findings</div><div class="v">{s['total_findings']}</div></div>
  {sev_cards}
  <div class="card"><div class="k">Affected files</div><div class="v">{len(s['by_file'])}</div></div>
  <div class="card"><div class="k">Files scanned</div><div class="v">{s['files_scanned'] or '-'}</div></div>
  <div class="card"><div class="k">Need action</div><div class="v">{actionable}</div></div>
</div>
<p>"Need action" counts findings that are true positives or not yet triaged. False positives and accepted risks are
listed with the reason in section 6.</p>

<h2>2. Findings by severity and triage verdict</h2>
<div class="wrap"><table><tr><th>Verdict</th><th class="n">Findings</th></tr>{verdict_rows}</table></div>

<h2>3. Affected files</h2>
<div class="wrap"><table><tr><th>File</th><th class="n">Findings</th></tr>{files_rows}</table></div>

<h2>4. Most important rule IDs</h2>
<div class="wrap"><table><tr><th>Severity</th><th>Rule ID</th><th class="n">Count</th><th>CWE</th><th>Verdict</th></tr>{rule_rows}</table></div>

<h2>5. Remediation focus</h2>
<ul>{focus or '<li>No findings.</li>'}</ul>

<h2>6. Detailed findings</h2>
{''.join(details) or '<p>No findings.</p>'}

<h2>7. Scan warnings</h2>
<p class="muted">Files Semgrep could only partly parse (common for Jinja templates; the rest of the file is still scanned).</p>
<ul>{errors or '<li>None</li>'}</ul>
</main></body></html>"""
    out.write_text(page, encoding="utf-8")


def main():
    ap = argparse.ArgumentParser(description="Build an HTML/JSON/CSV report from Semgrep JSON output")
    ap.add_argument("results", help="semgrep JSON file (semgrep scan --json -o semgrep-results.json)")
    ap.add_argument("--triage", help="optional JSON file with verdicts per rule (see tools/semgrep_triage.json)")
    ap.add_argument("--root", default=".", help="folder that was scanned (to show code snippets); default: .")
    ap.add_argument("--out-dir", help="where to write the reports; default: next to the results file")
    ap.add_argument("--title", default="SAST Report - UniPortal Student Web Portal (Semgrep)")
    args = ap.parse_args()

    results = Path(args.results)
    try:
        data = json.loads(results.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        sys.exit(f"Cannot read {results}: {exc}")
    out_dir = Path(args.out_dir) if args.out_dir else results.resolve().parent
    out_dir.mkdir(parents=True, exist_ok=True)
    root = Path(args.root).resolve()

    summary = build(data, load_triage(args.triage), root)
    write_html(summary, out_dir / "semgrep-report.html", args.title, root.name)
    write_json(summary, out_dir / "semgrep-summary.json")
    write_csv(summary, out_dir / "semgrep-findings.csv")

    print(f"Semgrep {summary['semgrep_version']}: {summary['total_findings']} findings in "
          f"{len(summary['by_file'])} files ({summary['files_scanned']} files scanned)")
    print("  by severity: " + ", ".join(f"{k}={v}" for k, v in summary["by_severity"].items()))
    print("  by verdict:  " + ", ".join(f"{k}={v}" for k, v in summary["verdicts"].items()))
    print("  top rules:")
    for r in summary["rules"][:5]:
        print(f"    {r['count']:>3}  {r['severity_label']:<7} {r['rule_id']}")
    for name in ("semgrep-report.html", "semgrep-summary.json", "semgrep-findings.csv"):
        print(f"  wrote {out_dir / name}")


if __name__ == "__main__":
    main()
