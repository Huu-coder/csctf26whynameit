#!/usr/bin/env python3
"""
Onion Deanon 2 (cert fingerprint) (CSCTF 2026, OSINT - Easy)

Computes the SHA-256 fingerprint of a DER-captured TLS certificate exactly as
`openssl x509 -inform DER -noout -fingerprint -sha256` would print it:
uppercase, colon-separated bytes.

Usage: python3 onion_deanon_cert_fingerprint.py <cert.der>

The CTF instance is retired; this PoC documents the exploit path.
"""
import hashlib
import sys


def sha256_fingerprint(der: bytes) -> str:
    digest = hashlib.sha256(der).digest()
    return ":".join(f"{b:02X}" for b in digest)


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit(__doc__)
    der = open(sys.argv[1], "rb").read()
    print(f"sha256 Fingerprint={sha256_fingerprint(der)}")


if __name__ == "__main__":
    main()
