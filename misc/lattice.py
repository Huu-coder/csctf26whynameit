#!/usr/bin/env python3
"""Lattice - custom 64-bit block cipher, offline inverse proof of concept.

Summary: the attachment's cipher is a toy construction (fixed public S-box
and round keys, 16 rounds, rotations, ECB); invert every transformation to
recover the passphrase offline and validate PKCS#7 padding.

Usage: lattice.py CIPHERTEXT_FILE

CIPHERTEXT_FILE holds the encrypted passphrase, either raw bytes or hex
(whitespace tolerated). The CTF instance is retired; this PoC documents
the exploit path.
"""

import sys

MASK64 = (1 << 64) - 1


def lcg(state):
    while True:
        state = (state * 0x19660D + 0x3C6EF35F) & 0xFFFFFFFF
        yield state


def build_sbox():
    g = lcg(0x1A2B3C4D)
    box = list(range(256))
    for i in range(255, 0, -1):
        j = next(g) % (i + 1)
        box[i], box[j] = box[j], box[i]
    return box


def build_keys():
    g = lcg(0xCAFEB0BA)
    return [[next(g) & 0xFF for _ in range(8)] for _ in range(16)]


SBOX = build_sbox()
INV_SBOX = [0] * 256
for i, value in enumerate(SBOX):
    INV_SBOX[value] = i
RKEYS = build_keys()


def rotl64(value, amount):
    amount &= 63
    return ((value << amount) | (value >> (64 - amount))) & MASK64


def rotr64(value, amount):
    amount &= 63
    return ((value >> amount) | (value << (64 - amount))) & MASK64


def rot_amount(round_number):
    return (7 * round_number + 11) % 63 + 1


def encrypt_block(block):
    state = list(block)
    for round_number, key in enumerate(RKEYS):
        if round_number % 2 == 0:
            state = [(state[i] + key[i]) & 0xFF for i in range(8)]
        else:
            state = [state[i] ^ key[i] for i in range(8)]
        state = [SBOX[value] for value in state]
        value = int.from_bytes(bytes(state), "big")
        state = list(rotl64(value, rot_amount(round_number)).to_bytes(8, "big"))
    return bytes(state)


def decrypt_block(block):
    state = list(block)
    for round_number in range(15, -1, -1):
        value = int.from_bytes(bytes(state), "big")
        state = list(rotr64(value, rot_amount(round_number)).to_bytes(8, "big"))
        state = [INV_SBOX[value] for value in state]
        key = RKEYS[round_number]
        if round_number % 2 == 0:
            state = [(state[i] - key[i]) & 0xFF for i in range(8)]
        else:
            state = [state[i] ^ key[i] for i in range(8)]
    return bytes(state)


def decrypt(data):
    if not data or len(data) % 8:
        raise ValueError("ciphertext must contain complete 8-byte blocks")
    padded = b"".join(decrypt_block(data[i:i + 8]) for i in range(0, len(data), 8))
    pad = padded[-1]
    if not 1 <= pad <= 8 or padded[-pad:] != bytes([pad]) * pad:
        raise ValueError(f"invalid PKCS#7 padding: {padded!r}")
    return padded[:-pad]


def encrypt(data):
    pad = 8 - (len(data) % 8)
    padded = data + bytes([pad]) * pad
    return b"".join(encrypt_block(padded[i:i + 8]) for i in range(0, len(padded), 8))


def load_ciphertext(path):
    raw = open(path, "rb").read()
    try:
        text = raw.decode("ascii")
        compact = "".join(text.split())
        if compact and all(c in "0123456789abcdefABCDEF" for c in compact) and len(compact) % 2 == 0:
            return bytes.fromhex(compact)
    except UnicodeDecodeError:
        pass
    return raw


def main():
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} CIPHERTEXT_FILE", file=sys.stderr)
        raise SystemExit(2)
    ciphertext = load_ciphertext(sys.argv[1])
    secret = decrypt(ciphertext)
    if encrypt(secret) != ciphertext:  # inverse validation against forward construction
        raise SystemExit("inverse validation failed")
    print(secret.decode("utf-8", errors="replace"))


if __name__ == "__main__":
    main()
