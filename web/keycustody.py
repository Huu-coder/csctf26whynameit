#!/usr/bin/env python3
"""
Keycustody (CSCTF 2026, Web - Easy)

The writeup records only a credential artifact, not a solve narrative: an
outer object claiming role=admin wrapping an HS256 JWT (kid="session") whose
payload asserts role=analyst. This PoC implements the documented read-only
analysis: parse the artifact, decode the JWT header/payload without verifying,
and report the role discrepancy a naive verifier would miss.

Usage: python3 keycustody.py <credential_artifact.json>

The CTF instance is retired; this PoC documents the exploit path as far as the
writeup records it. The source does not document the steps from the artifact
to the solution, the instance interaction, or the flag.
"""
import sys
import json
import base64


def b64url_decode(segment: str) -> bytes:
    pad = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + pad)


def decode_jwt(token: str) -> tuple:
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("not a compact JWS/JWT (expected 3 segments)")
    header = json.loads(b64url_decode(parts[0]))
    payload = json.loads(b64url_decode(parts[1]))
    signature = b64url_decode(parts[2])
    return header, payload, signature


def main() -> None:
    artifact_path = sys.argv[1] if len(sys.argv) > 1 else "<credential artifact json>"
    with open(artifact_path) as f:
        artifact = json.load(f)

    outer_sub = artifact.get("sub")
    outer_role = artifact.get("role")
    token = artifact.get("token")
    print(f"[*] outer claims: sub={outer_sub!r} role={outer_role!r}")

    header, payload, signature = decode_jwt(token)
    print(f"[*] jwt header: {header}")
    print(f"[*] jwt payload: {payload}")
    print(f"[*] signature present: {len(signature)} bytes (HS256, kid={header.get('kid')!r})")

    token_role = payload.get("role")
    if outer_role != token_role:
        print(f"[!] role discrepancy: outer object claims {outer_role!r}, "
              f"signed token asserts {token_role!r}")
        print("[!] a verifier that trusts the token sees the token's role, "
              "not the surrounding claim")
    else:
        print("[*] no role discrepancy detected")

    # TODO: supply the instance interaction and exploitation steps - the
    # writeup does not record them (no flag, no solve narrative). In
    # particular: how the artifact is presented to the service, how the JWT
    # is verified (key source/algorithm handling), and what the flag endpoint
    # is. Do not invent these; fill in from the challenge source if available.


if __name__ == "__main__":
    main()
