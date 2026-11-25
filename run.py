#!/usr/bin/env python3
"""Start UniPortal.

  python run.py                 # HTTPS if certs/cert.pem + certs/key.pem exist, else asks for --http
  python run.py --http          # plain HTTP on 127.0.0.1:5000 (local testing only)
  python run.py --host 0.0.0.0  # listen on all interfaces (e.g. Kali VM reachable from the host)
"""
import argparse
import os
import ssl
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parent


def quiet_handler():
    """Request handler that hides the 'Werkzeug/x.y Python/x.y' Server banner (information disclosure)."""
    from werkzeug.serving import WSGIRequestHandler

    class QuietHandler(WSGIRequestHandler):
        def version_string(self):
            return "UniPortal"

    return QuietHandler


def main():
    parser = argparse.ArgumentParser(description="Run the UniPortal student portal")
    parser.add_argument("--host", default=os.environ.get("PORTAL_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=None)
    parser.add_argument("--cert", default=os.environ.get("PORTAL_TLS_CERT", str(BASE / "certs" / "cert.pem")))
    parser.add_argument("--key", default=os.environ.get("PORTAL_TLS_KEY", str(BASE / "certs" / "key.pem")))
    parser.add_argument("--http", action="store_true", help="serve plain HTTP (no TLS) - local testing only")
    args = parser.parse_args()

    have_cert = Path(args.cert).is_file() and Path(args.key).is_file()
    if not args.http and not have_cert:
        sys.exit("No TLS certificate found in certs/. Run 'bash setup_kali.sh' (Kali) to create one,\n"
                 "or start with --http for local testing only.")
    use_https = not args.http
    os.environ["PORTAL_HTTPS"] = "1" if use_https else "0"
    port = args.port or int(os.environ.get("PORTAL_PORT", 8443 if use_https else 5000))

    from portal import create_app
    from portal.seed import seed

    app = create_app()
    if seed(app.config["DATABASE"], app.config["UPLOAD_DIR"]):
        print("[+] Created a new database with demo data (see README.md for the demo accounts).")

    ssl_context = None
    if use_https:
        ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2  # ASVS V12: TLS 1.2+ only
        ssl_context.load_cert_chain(args.cert, args.key)
    else:
        print("[!] Running WITHOUT TLS. Use HTTPS (setup_kali.sh) for anything other than local testing.")

    scheme = "https" if use_https else "http"
    print(f"[+] UniPortal listening on {scheme}://{args.host}:{port}")
    app.run(host=args.host, port=port, ssl_context=ssl_context, debug=False, use_reloader=False, threaded=True,
            request_handler=quiet_handler())


if __name__ == "__main__":
    main()
