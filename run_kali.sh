#!/usr/bin/env bash
# Start UniPortal over HTTPS on Kali. Stop it with Ctrl+C.
#   PORTAL_PORT=9443 bash run_kali.sh            # different port
#   PORTAL_HOST=127.0.0.1 bash run_kali.sh       # only reachable from inside the VM
#   PORTAL_MFA_ENFORCED_ROLES= bash run_kali.sh  # don't force MFA on lecturers/admin (quick demos)
set -euo pipefail
cd "$(dirname "$0")"

if [[ ! -x .venv/bin/python ]]; then
  echo "Run 'bash setup_kali.sh' first."
  exit 1
fi

HOST="${PORTAL_HOST:-0.0.0.0}"
PORT="${PORTAL_PORT:-8443}"
IP="$(hostname -I 2>/dev/null | awk '{print $1}')"

echo "UniPortal -> https://127.0.0.1:${PORT}   (inside Kali)"
[[ -n "$IP" && "$HOST" == "0.0.0.0" ]] && echo "           https://${IP}:${PORT}   (from other machines on the VM network)"
exec .venv/bin/python run.py --host "$HOST" --port "$PORT"
