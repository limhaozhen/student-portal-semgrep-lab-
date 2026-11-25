"""Malware / AV scanning for uploaded files (external service in the Lab 2 architecture).

1. Built-in check for the EICAR antivirus test signature (so the control can be
   demonstrated even without an AV engine installed).
2. ClamAV (clamdscan, falling back to clamscan) when installed - e.g. on Kali:
   sudo apt install clamav clamav-daemon
"""
import shutil
import subprocess
from pathlib import Path

# The EICAR test string is assembled at runtime so this source file itself is not
# flagged by antivirus software.
_EICAR = ("X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + "EICAR-STANDARD-" + "ANTIVIRUS-TEST-FILE!$H+H*").encode("ascii")


def _run(engine, path):
    cmd = [engine, "--no-summary", str(path)]
    if Path(engine).name.startswith("clamdscan"):
        cmd.insert(1, "--fdpass")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=180, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return None, f"{Path(engine).name}: {exc}"
    output = (result.stdout or result.stderr).strip().replace(str(path), "<upload>")
    if result.returncode == 0:
        return "clean", Path(engine).name
    if result.returncode == 1:
        return "infected", output[-200:] or "malware detected"
    return None, f"{Path(engine).name} exit {result.returncode}: {output[-150:]}"


def builtin_check(data):
    """In-memory signature check, run before the file ever touches the disk."""
    if _EICAR in data:
        return "infected", "Eicar-Test-Signature (built-in check)"
    return None


def scan_file(path):
    """Scan a stored file with ClamAV. Returns (status, detail): clean | infected | unscanned | error."""
    path = Path(path)
    engines = [e for e in (shutil.which("clamdscan"), shutil.which("clamscan")) if e]
    if not engines:
        return "unscanned", "No antivirus engine installed (install ClamAV)"

    errors = []
    for engine in engines:
        status, detail = _run(engine, path)
        if status:
            return status, detail
        errors.append(detail)
    return "error", "; ".join(errors)[:300]
