#!/usr/bin/env python3
"""Torven Ordnance - CSCTF 2026 crypto (easy).

Recovers the ECDSA (secp256k1) private key from two release receipts signed
with the same nonce k (identical r), then forges the master authorization
signature required by /authorize. NOTE: the CTF instance is retired; this
PoC documents the exploit path.
Usage: signing_authority.py [BASE_URL] [--receipts FILE] [--pubkey HEX]
       [--z1 HEX --z2 HEX]
BASE_URL defaults to http://<instance> and may also come from CSCTF_BASE_URL.
Receipt messages are hashed with SHA-256 mod n; if the receipts file carries
no message, supply --z1/--z2 directly.
"""

import argparse
import hashlib
import json
import os
import sys

import requests

# secp256k1 domain parameters
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G = (Gx, Gy)

MASTER_MESSAGE = b"TORVEN-AUTHZ-V1\noperation=promote-master-arming\nartifact=master-arming-image\n"
LOW_S_N = N // 2


def point_add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if p1 == p2:
        lam = (3 * x1 * x1) * pow(2 * y1, -1, P) % P
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, P) % P
    x3 = (lam * lam - x1 - x2) % P
    return (x3, (lam * (x1 - x3) - y1) % P)


def scalar_mul(k, point=G):
    result = None
    addend = point
    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1
    return result


def pubkey_from_hex(hexstr):
    raw = bytes.fromhex(hexstr.strip())
    if raw[0] == 4:
        return (int.from_bytes(raw[1:33], "big"), int.from_bytes(raw[33:65], "big"))
    if raw[0] in (2, 3):
        x = int.from_bytes(raw[1:33], "big")
        y_sq = (pow(x, 3, P) + 7) % P
        y = pow(y_sq, (P + 1) // 4, P)
        if (y & 1) != (raw[0] & 1):
            y = P - y
        return (x, y)
    if len(raw) == 32:  # x-only pubkey
        return pubkey_from_hex("02" + raw.hex())
    raise ValueError("unsupported pubkey encoding")


def z_of(message):
    return int.from_bytes(hashlib.sha256(message).digest(), "big") % N


def recover_key(r, s1, s2, z1, z2):
    """Nonce-reuse recovery; identical r means identical k."""
    k = (z1 - z2) * pow(s1 - s2, -1, N) % N
    d = (s1 * k - z1) * pow(r, -1, N) % N
    return k, d


def sign_with_nonce(z, r, d, k):
    s = pow(k, -1, N) * (z + r * d) % N
    if s > LOW_S_N:  # /authorize requires low-s
        s = N - s
    return s


def receipt_z(receipt):
    for field in ("message_hex", "message"):
        if field in receipt:
            msg = bytes.fromhex(receipt[field]) if field == "message_hex" else receipt[field].encode()
            return z_of(msg)
    if "z" in receipt:
        return int(str(receipt["z"]), 16) % N
    return None


def load_receipts(args, base):
    if args.receipts:
        return json.load(open(args.receipts))
    resp = requests.get(f"{base}/receipts", timeout=10)
    resp.raise_for_status()
    data = resp.json()
    return data if isinstance(data, list) else data.get("receipts", [data])


def load_pubkey_hex(args, base):
    if args.pubkey:
        return args.pubkey
    resp = requests.get(f"{base}/pubkey", timeout=10)
    resp.raise_for_status()
    data = resp.json()
    if isinstance(data, str):
        return data
    for field in ("pubkey", "public_key", "q", "Q"):
        if field in data:
            return str(data[field])
    raise ValueError("could not locate pubkey in /pubkey response; pass --pubkey")


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    ap.add_argument("base_url", nargs="?", default=os.environ.get("CSCTF_BASE_URL", "http://<instance>"))
    ap.add_argument("--receipts", help="JSON file with the two receipts (default: GET /receipts)")
    ap.add_argument("--pubkey", help="published pubkey hex (default: GET /pubkey)")
    ap.add_argument("--z1", help="precomputed z for receipt 1 (hex)")
    ap.add_argument("--z2", help="precomputed z for receipt 2 (hex)")
    args = ap.parse_args()
    base = args.base_url.rstrip("/")
    if "<instance>" in base:
        print("note: no BASE_URL given; remote calls will fail (instance retired).", file=sys.stderr)

    # TODO: if the receipts carry no message/z, recompute z_i = sha256(message_i)
    # from the receipt payloads and pass --z1/--z2.
    receipts = load_receipts(args, base)
    if len(receipts) < 2:
        raise SystemExit("need exactly the two signed receipts")
    rec1, rec2 = receipts[0], receipts[1]
    r1, r2 = int(str(rec1["r"]), 16), int(str(rec2["r"]), 16)
    if r1 != r2:
        raise SystemExit("receipts do not share r; not the nonce-reuse case")
    r = r1
    s1, s2 = int(str(rec1["s"]), 16), int(str(rec2["s"]), 16)
    z1 = int(args.z1, 16) % N if args.z1 else receipt_z(rec1)
    z2 = int(args.z2, 16) % N if args.z2 else receipt_z(rec2)
    if z1 is None or z2 is None:
        raise SystemExit("receipts carry no message/z; pass --z1 and --z2 (hex)")

    k, d = recover_key(r, s1, s2, z1, z2)
    print(f"k = {k:#x}")
    print(f"d = {d:#x}")

    q_pub = scalar_mul(d)
    published = pubkey_from_hex(load_pubkey_hex(args, base))
    if q_pub != published:
        raise SystemExit("recovered key does NOT match published pubkey; wrong inputs?")
    print("d*G matches published pubkey")

    z_m = z_of(MASTER_MESSAGE)
    s_m = sign_with_nonce(z_m, r, d, k)
    payload = {
        "message_hex": MASTER_MESSAGE.hex(),
        "r": f"{r:064x}",
        "s": f"{s_m:064x}",
    }
    print("POST /authorize", json.dumps(payload))
    resp = requests.post(f"{base}/authorize", json=payload,
                         headers={"Content-Type": "application/json"}, timeout=10)
    print(resp.status_code, resp.text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
