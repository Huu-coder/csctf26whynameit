#!/usr/bin/env python3
"""
Onion Deanon 2 - favicon MurmurHash3 (CSCTF 2026, OSINT - Easy)

Reproduces the Shodan favicon-hash convention for a favicon captured from the
retired onion service: base64 the raw bytes with 76-char MIME lines and a
trailing newline, then MurmurHash3 x86 32-bit (seed 0) over that text,
interpreted as a signed 32-bit integer.

Usage: python3 onion_deanon_favicon.py <favicon.ico>

The CTF instance is retired; this PoC documents the exploit path.
"""
import base64
import hashlib
import struct
import sys

MASK32 = 0xFFFFFFFF
C1 = 0xCC9E2D51
C2 = 0x1B873593


def rotl32(x: int, r: int) -> int:
    return ((x << r) | (x >> (32 - r))) & MASK32


def gmul32(a: int, b: int) -> int:
    return (a * b) & MASK32


def mmh3_x86_32(data: bytes, seed: int = 0) -> int:
    length = len(data)
    h = seed & MASK32
    nblocks = length // 4
    for i in range(nblocks):
        k = struct.unpack_from("<I", data, i * 4)[0]
        k = gmul32(k, C1)
        k = rotl32(k, 15)
        k = gmul32(k, C2)
        h ^= k
        h = rotl32(h, 13)
        h = (gmul32(h, 5) + 0xE6546B64) & MASK32
    tail = data[nblocks * 4:]
    k1 = 0
    for idx, byte in enumerate(tail):
        k1 ^= byte << (8 * idx)
    if tail:
        k1 = gmul32(k1, C1)
        k1 = rotl32(k1, 15)
        k1 = gmul32(k1, C2)
        h ^= k1
    h ^= length
    h ^= h >> 16
    h = gmul32(h, 0x85EBCA6B)
    h ^= h >> 13
    h = gmul32(h, 0xC2B2AE35)
    h ^= h >> 16
    return h


def to_signed32(h: int) -> int:
    return h - 0x100000000 if h >= 0x80000000 else h


def shodan_favicon_hash(raw: bytes):
    # Shodan wraps base64 at 76 chars with a trailing newline (MIME style),
    # which is what base64.encodebytes produces.
    b64 = base64.encodebytes(raw).decode("ascii")
    return hashlib.sha256(raw).hexdigest(), len(b64), to_signed32(mmh3_x86_32(b64.encode("ascii"), 0))


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit(__doc__)
    raw = open(sys.argv[1], "rb").read()
    sha256_hex, b64_len, mmh3_signed = shodan_favicon_hash(raw)
    print(f"[*] favicon sha256: {sha256_hex}")
    print(f"[*] base64 input length (MIME wrapped, trailing newline): {b64_len}")
    print(f"[*] murmurhash3 x86 32-bit (seed 0, signed): {mmh3_signed}")


if __name__ == "__main__":
    main()
