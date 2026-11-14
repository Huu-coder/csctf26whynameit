#!/usr/bin/env python3
"""
Shadow Dispatch — forensics.

A malicious Lambda layer (auth-utils v10) shipped bytecode diverging from its
source: it read SSM secrets (including /gridlink/order-hmac-key) and trickled
the order-HMAC key out in correlation tokens, two beacon bytes per order, for
orders whose IDs were divisible by five. Tokens were decoded with
SHA256(request_id + salt)[:2] as a repeating XOR key and verified with the
token's CRC-16; fragments were ordered by token index 0..7 to reassemble the
key.

Usage:
    python3 shadow_dispatch.py <cloudtrail.json> <tokens.json>

The CTF instance is retired; this PoC documents the exploit path. Input files
are analyst-supplied excerpts of the CloudTrail log and of the captured
correlation tokens.

NOTE: the writeup does not record the exact token wire format, salt source, or
CRC-16 variant, so those are parameterised below with clear TODOs and the
decode path is written against a documented-assumption layout. Never fabricate
token data to fill the gaps.
"""

import hashlib
import json
import sys

# --- CRC-16 (variant not recorded in the writeup; CCITT-FALSE shown) --------
def crc16_ccitt_false(data: bytes, crc: int = 0xFFFF) -> int:
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc


CRC16 = crc16_ccitt_false  # TODO: substitute the exact CRC-16 variant if known


def beacon_key(request_id: str, salt: str) -> bytes:
    """Decode key from the logged request ID and salt, per the writeup."""
    return hashlib.sha256((request_id + salt).encode()).digest()[:2]


def xor_repeating(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def find_layer_deployment(events: list) -> list:
    """Locate the auth-utils v10 deployment / alias movement (~22:30 UTC)."""
    interesting = []
    for ev in events:
        name = ev.get("eventName", "")
        blob = json.dumps(ev)
        if "auth-utils" in blob and name in (
            "UpdateFunctionCode20150331", "UpdateFunctionConfiguration20150331",
            "PublishVersion20150331", "UpdateAlias20150331", "CreateAlias20150331",
        ):
            interesting.append(ev)
    return interesting


def recover_fragments(tokens: list) -> dict[int, bytes]:
    """
    Decode each token's two beacon bytes and keep verified fragments.

    Documented token assumptions (writeup redacts the wire format):
      token = {
        "token_index": int,          # 0..7 ordering key for reassembly
        "order_id": int,             # fragments emitted for IDs % 5 == 0
        "request_id": str,           # CloudTrail request ID
        "salt": str,                 # logged salt
        "ciphertext": hex str,       # two beacon bytes
        "crc16": int                 # CRC-16 of the plaintext fragment
      }
    # TODO: align field names / CRC coverage with the captured token format.
    """
    fragments = {}
    for tok in tokens:
        order_id = int(tok["order_id"])
        if order_id % 5 != 0:
            continue  # beacons ride on orders whose IDs are divisible by five
        key = beacon_key(tok["request_id"], tok["salt"])
        plaintext = xor_repeating(bytes.fromhex(tok["ciphertext"]), key)
        if CRC16(plaintext) != int(tok["crc16"]):
            print(f"[!] token index {tok.get('token_index')}: CRC-16 mismatch, skipped")
            continue
        fragments[int(tok["token_index"])] = plaintext
    return fragments


def reassemble_key(fragments: dict[int, bytes]) -> bytes:
    missing = [i for i in range(8) if i not in fragments]
    if missing:
        raise SystemExit(f"[!] missing fragment indices: {missing}")
    return b"".join(fragments[i] for i in range(8))


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__)
        return 1
    with open(sys.argv[1]) as fh:
        trail = json.load(fh)
    with open(sys.argv[2]) as fh:
        tokens = json.load(fh)

    events = trail.get("Records", trail) if isinstance(trail, dict) else trail
    flagged = find_layer_deployment(events)
    print(f"[*] auth-utils deployment/alias events in trail: {len(flagged)}")
    for ev in flagged:
        print(f"    {ev.get('eventTime', '?')} {ev.get('eventName', '?')} "
              f"req={ev.get('requestID', '?')}")

    fragments = recover_fragments(tokens)
    print(f"[*] verified beacon fragments: {sorted(fragments)}")
    key_hex = reassemble_key(fragments).hex()
    print(f"[*] reassembled order-HMAC key (hex): {key_hex}")
    print("[*] feed the reassembled value to whatever validation step the "
          "challenge requires; do not commit it to source control")
    return 0


if __name__ == "__main__":
    sys.exit(main())
