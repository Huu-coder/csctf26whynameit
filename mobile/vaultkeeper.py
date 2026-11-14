#!/usr/bin/env python3
"""
VaultKeeper (CSCTF 2026, Mobile - Easy)

Reconstructs the AES-256-GCM key for the note stashed in the APK's string
resources: parses the APK Signature Scheme v2 block (no META-INF/CERT.RSA
exists) for the signing certificate, derives the recovery token, resolves the
archive digits from the embedded lookup table (or brute-forces 0000-9999
against an expected archive key), then decrypts the GCM blob.

Usage: python3 vaultkeeper.py <release.apk> <flag_ciphertext.b64> <master_passcode> [expected_archive_key]
The ciphertext resource is one base64 string; dump it with apktool/aapt first.

The CTF instance is retired; this PoC documents the exploit path.
"""
import base64
import hashlib
import hmac
import struct
import sys

ARCHIVE_SESSION = "VK-7F42"
# Values from the APK's string resources (archive_index_table + legend).
ARCHIVE_TABLE = {
    "VK-1A37": "△ ○ □ ◇",
    "VK-9F42": "○ ◇ □ △",
    "VK-7F24": "□ △ ◇ ○",
    "VK-7F42": "◇ □ △ ○",
    "VK-4F71": "◇ ○ △ □",
}
ARCHIVE_LEGEND = {"△": "7", "○": "2", "□": "9", "◇": "4"}
APK_SIG_V2_BLOCK_ID = 0x7109871A
APK_SIG_BLOCK_MAGIC = b"APK Sig Block 42"
EOCD_MAGIC = b"PK\x05\x06"


# ---------- APK v2 signing block ----------

def find_eocd(data: bytes) -> int:
    window = data[-65557:]
    idx = window.rfind(EOCD_MAGIC)
    if idx < 0:
        raise ValueError("EOCD not found (zip64 not supported here)")
    return len(data) - len(window) + idx


def first_cert_der(data: bytes) -> bytes:
    eocd = find_eocd(data)
    cd_offset = struct.unpack_from("<I", data, eocd + 16)[0]
    if data[cd_offset - 16:cd_offset] != APK_SIG_BLOCK_MAGIC:
        raise ValueError("APK Sig Block 42 magic not found before central directory")
    block_size = struct.unpack_from("<Q", data, cd_offset - 24)[0]
    block_start = cd_offset - block_size
    pos, end = block_start + 8, cd_offset - 24
    while pos + 12 <= end:
        pair_len, block_id = struct.unpack_from("<QI", data, pos)
        value_start = pos + 12
        if block_id == APK_SIG_V2_BLOCK_ID:
            return parse_v2_signers(data[value_start:value_start + pair_len - 4])
        pos = value_start + (pair_len - 4)
    raise ValueError("no v2 signature block found")


class Cursor:
    def __init__(self, buf: bytes):
        self.buf, self.pos = buf, 0

    def u64(self) -> int:
        v = struct.unpack_from("<Q", self.buf, self.pos)[0]
        self.pos += 8
        return v

    def take(self, n: int) -> bytes:
        v = self.buf[self.pos:self.pos + n]
        self.pos += n
        return v


def parse_v2_signers(value: bytes) -> bytes:
    c = Cursor(value)
    seq_end = c.pos + c.u64()                     # length-prefixed signers sequence
    while c.pos < seq_end:
        signer_len = c.u64()
        signer_end = c.pos + signer_len
        sd_len = c.u64()                          # signed data
        sd = Cursor(c.take(sd_len))
        # signed data: digests sequence, then certificates sequence, then attrs
        digests_len = sd.u64()
        sd.pos += digests_len
        certs_len = sd.u64()
        certs_end = sd.pos + certs_len
        while sd.pos < certs_end:
            return sd.take(sd.u64())              # first DER certificate
        c.pos = signer_end
    raise ValueError("no certificates in v2 block")


def recovery_token(apk_path: str) -> tuple[str, str]:
    der = first_cert_der(open(apk_path, "rb").read())
    sha = hashlib.sha256(der).hexdigest()
    token = "KJSC-" + sha[:8].upper() + "-RECOVERY"
    return token, sha


# ---------- archive digits ----------

def archive_digits(session: str) -> str:
    symbols = ARCHIVE_TABLE[session].split()
    return "".join(ARCHIVE_LEGEND[s] for s in symbols)


def archive_key(session: str, digits: str) -> str:
    digest = hmac.new(session.encode(), digits.encode(), hashlib.sha256).hexdigest()
    return digest[:8].upper()


def brute_force_archive_key(session: str, target_key: str) -> str | None:
    for code in range(0x10000):
        digits = f"{code:04d}"
        if archive_key(session, digits) == target_key.upper():
            return digits
    return None


# ---------- pure-Python AES-256-GCM ----------

def gf_mul(a: int, b: int) -> int:
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return p


def gf_pow(a: int, e: int) -> int:
    result = 1
    while e:
        if e & 1:
            result = gf_mul(result, a)
        a = gf_mul(a, a)
        e >>= 1
    return result


def _rotl8(v: int, n: int) -> int:
    return ((v << n) | (v >> (8 - n))) & 0xFF


def _build_sbox():
    sbox = []
    for i in range(256):
        inv = gf_pow(i, 254) if i else 0
        sbox.append(inv ^ _rotl8(inv, 1) ^ _rotl8(inv, 2) ^ _rotl8(inv, 3) ^ _rotl8(inv, 4) ^ 0x63)
    return sbox


SBOX = _build_sbox()
RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


def aes_key_expansion(key: bytes):
    assert len(key) == 32
    w = [list(key[i:i + 4]) for i in range(0, 32, 4)]
    i = 8
    while len(w) < 60:                              # Nr = 14 -> 60 words
        temp = list(w[-1])
        if i % 8 == 0:
            temp = temp[1:] + temp[:1]              # RotWord
            temp = [SBOX[b] for b in temp]          # SubWord
            temp[0] ^= RCON[i // 8 - 1]
        elif i % 8 == 4:
            temp = [SBOX[b] for b in temp]
        w.append([a ^ b for a, b in zip(w[-8], temp)])
        i += 1
    return w


def aes_encrypt_block(block: bytes, w) -> bytes:
    s = list(block)

    def add_round_key(rnd):
        for c in range(4):
            for r in range(4):
                s[r + 4 * c] ^= w[rnd * 4 + c][r]

    add_round_key(0)
    for rnd in range(1, 15):
        s[:] = [SBOX[b] for b in s]                 # SubBytes
        for r in range(1, 4):                       # ShiftRows
            row = [s[r + 4 * c] for c in range(4)]
            for c in range(4):
                s[r + 4 * c] = row[(c + r) % 4]
        if rnd != 14:                               # MixColumns
            for c in range(4):
                col = [s[r + 4 * c] for r in range(4)]
                s[0 + 4 * c] = gf_mul(col[0], 2) ^ gf_mul(col[1], 3) ^ col[2] ^ col[3]
                s[1 + 4 * c] = col[0] ^ gf_mul(col[1], 2) ^ gf_mul(col[2], 3) ^ col[3]
                s[2 + 4 * c] = col[0] ^ col[1] ^ gf_mul(col[2], 2) ^ gf_mul(col[3], 3)
                s[3 + 4 * c] = gf_mul(col[0], 3) ^ col[1] ^ col[2] ^ gf_mul(col[3], 2)
        add_round_key(rnd)
    return bytes(s)


def ghash_mul(x: int, y: int) -> int:
    z, v = 0, y
    R = 0xE1000000000000000000000000000000
    for i in range(128):
        if (x >> (127 - i)) & 1:
            z ^= v
        v = (v >> 1) ^ (R if v & 1 else 0)
    return z


def ghash(h: int, data: bytes) -> int:
    x = 0
    for off in range(0, len(data), 16):
        block = int.from_bytes(data[off:off + 16].ljust(16, b"\x00"), "big")
        x = ghash_mul(x ^ block, h)
    return x


def aes_gcm_decrypt(key: bytes, iv: bytes, ct: bytes, tag: bytes, aad: bytes = b"") -> bytes:
    assert len(iv) == 12
    w = aes_key_expansion(key)
    h = int.from_bytes(aes_encrypt_block(b"\x00" * 16, w), "big")
    j0 = int.from_bytes(iv + b"\x00\x00\x00\x01", "big")

    def inc32(counter: int) -> int:
        return ((counter >> 32) << 32) | (((counter & 0xFFFFFFFF) + 1) & 0xFFFFFFFF)

    plain, counter = bytearray(), j0
    for off in range(0, len(ct), 16):
        counter = inc32(counter)
        stream = aes_encrypt_block(counter.to_bytes(16, "big"), w)
        block = ct[off:off + 16]
        plain += bytes(a ^ b for a, b in zip(block, stream))

    def pad16(d: bytes) -> bytes:
        return d + b"\x00" * ((-len(d)) % 16)

    lengths = struct.pack(">QQ", len(aad) * 8, len(ct) * 8)
    s_tag = ghash(h, pad16(aad) + pad16(ct) + lengths)
    expected_tag = (s_tag ^ int.from_bytes(aes_encrypt_block(j0.to_bytes(16, "big"), w), "big")).to_bytes(16, "big")
    if not hmac.compare_digest(expected_tag, tag):
        raise ValueError("GCM tag mismatch (wrong token/digits/passcode)")
    return bytes(plain)


# ---------- driver ----------

def main() -> None:
    if len(sys.argv) < 4:
        raise SystemExit(__doc__)
    apk_path, ct_path, passcode = sys.argv[1], sys.argv[2], sys.argv[3]

    token, cert_sha = recovery_token(apk_path)
    print(f"[*] signing-cert sha256: {cert_sha}")
    print(f"[*] recovery token:      {token}")

    digits = archive_digits(ARCHIVE_SESSION)
    akey = archive_key(ARCHIVE_SESSION, digits)
    print(f"[*] archive digits:      {digits}   (from {ARCHIVE_SESSION} via legend)")
    print(f"[*] archive key:         {akey}")

    if len(sys.argv) >= 5:                          # cross-check via brute force
        brute = brute_force_archive_key(ARCHIVE_SESSION, sys.argv[4])
        print(f"[*] brute force 0000-9999 -> {brute}")

    key = hashlib.sha256((token + digits + passcode).encode()).digest()
    raw = base64.b64decode(open(ct_path).read())
    iv, ct, tag = raw[:12], raw[12:-16], raw[-16:]
    note = aes_gcm_decrypt(key, iv, ct, tag)
    print(f"[*] note: {note.decode('utf-8', 'replace')}")


if __name__ == "__main__":
    main()
