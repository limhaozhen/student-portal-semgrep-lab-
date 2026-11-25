#!/usr/bin/env bash
# One-time setup of UniPortal on Kali Linux.
#
#   bash setup_kali.sh                 # Python venv + self-signed HTTPS certificate + demo database
#   bash setup_kali.sh --with-clamav   # ...and install ClamAV for real malware scanning of uploads
#
set -euo pipefail
cd "$(dirname "$0")"

WITH_CLAMAV=0
[[ "${1:-}" == "--with-clamav" ]] && WITH_CLAMAV=1

say() { printf '\n\033[1;34m[*]\033[0m %s\n' "$*"; }
ok()  { printf '\033[1;32m[+]\033[0m %s\n' "$*"; }

# Files copied from Windows can carry CRLF line endings; fix the other script just in case.
sed -i 's/\r$//' run_kali.sh 2>/dev/null || true

# ---------------------------------------------------------------- system packages
NEED=()
python3 -c 'import ensurepip' 2>/dev/null || NEED+=(python3-venv)
command -v openssl >/dev/null 2>&1 || NEED+=(openssl)
if (( WITH_CLAMAV )); then
  command -v clamscan  >/dev/null 2>&1 || NEED+=(clamav)
  command -v clamdscan >/dev/null 2>&1 || NEED+=(clamav-daemon)
fi
if (( ${#NEED[@]} )); then
  say "Installing system packages: ${NEED[*]}"
  sudo apt-get update
  sudo apt-get install -y "${NEED[@]}"
fi

# ---------------------------------------------------------------- Python environment
say "Creating Python virtual environment (.venv) and installing requirements"
python3 -m venv .venv
.venv/bin/pip install --quiet --upgrade pip
.venv/bin/pip install --quiet -r requirements.txt
ok "Python $(.venv/bin/python -c 'import sys; print(sys.version.split()[0])') ready"

# ---------------------------------------------------------------- TLS certificate
mkdir -p certs
if [[ ! -f certs/cert.pem || ! -f certs/key.pem ]]; then
  say "Generating a self-signed TLS certificate (certs/)"
  IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
  SAN="DNS:localhost,DNS:uniportal.local,IP:127.0.0.1"
  [[ -n "$IP" ]] && SAN="$SAN,IP:$IP"
  openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 365 \
    -keyout certs/key.pem -out certs/cert.pem \
    -subj "/CN=uniportal.local/O=UniPortal Lab" \
    -addext "subjectAltName=$SAN" 2>/dev/null
  chmod 600 certs/key.pem
  ok "Certificate valid for: $SAN"
else
  ok "Existing certificate kept (delete certs/ to regenerate)"
fi

# ---------------------------------------------------------------- ClamAV
if (( WITH_CLAMAV )); then
  say "Updating ClamAV signatures (first run downloads ~200 MB, please wait)"
  sudo systemctl stop clamav-freshclam 2>/dev/null || true
  sudo freshclam || echo "    freshclam failed - check the VM's internet connection and re-run."
  sudo systemctl enable --now clamav-freshclam 2>/dev/null || true
  sudo systemctl enable --now clamav-daemon 2>/dev/null || true
  ok "ClamAV installed (the portal uses clamdscan, falling back to clamscan)"
fi

# ---------------------------------------------------------------- database
say "Initialising the database with demo data"
.venv/bin/python manage.py init-db
chmod 700 instance 2>/dev/null || true

IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
cat <<EOF

=====================================================================
 Setup complete. Start the portal with:   bash run_kali.sh

 Then open in Firefox:  https://127.0.0.1:8443
 From your host PC:     https://${IP:-<kali-ip>}:8443   (needs bridged / host-only network)

 The certificate is self-signed: click "Advanced" -> "Accept the Risk".
 Demo accounts are listed in README.md.
=====================================================================
EOF
