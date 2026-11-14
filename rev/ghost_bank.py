#!/usr/bin/env python3
"""Ghost Bank - CSCTF 2026 reverse engineering (hard).

Reimplements the sealed relay-bench controller's activation protocol: the
64-bit challenge mixer (keyfun) recovered from the flat AArch64 firmware, a
ChaCha20 decryption of the staged tasking with the firmware's exact
parameters, and the GDB Remote Serial Protocol (RSP) exchange used against
the live bench. NOTE: the CTF instance is retired; this PoC documents the
exploit path and runs offline against the handout artifacts.
Usage: ghost_bank.py [--verify firmware.bin] [--capture capture.ndjson]
       [--decrypt BANK_KEY_FILE [PAGE3_BIN]] [--live HOST PORT]
       (BANK_KEY_FILE: raw 32-byte unsealed key read from PAGE 7 during the
       unseal window; it is redacted here, supply your own.)
"""

import hashlib
import json
import socket
import struct
import sys

LO, HI = 0x40000020, 0x40000024
CONTROL, PAGE, OFFSET = 0x40000000, 0x40000008, 0x40000010
DATA, CIPHER_LEN, KEY, STATUS = 0x40000018, 0x4000001C, 0x40000028, 0x40000030
FIRMWARE_SHA256 = "f0b30ccf52d984559b144ca812ef77eedebfe36fdbd8092343ff11b66f1cdf47"
NONCE = b"SEAL-V01\x00\x00\x00\x01"

# True 131-byte PAGE 3 ciphertext (first 8 bytes repaired by re-reading the
# leading offsets in reverse order; see writeup).
PAGE3_CIPHERTEXT = bytes.fromhex(
    "542c88474c43a40d7782ccda43d6a141109d7595df242a58b1c6c2731b8162bf"
    "b6cb5e57e2cd40a8f908f86f4cb10f23b170f230d1f0b21a94876c587aab6d0"
    "7cccb47bff3bd3e64ce9ff2f5e78d40313219b26a8271fac8eaa375323d3c451"
    "86ec5cdc56718b81e553107a45d29690c72260c9544f6172d6bd84cb36e6ad5"
    "42c2c610")


def ror64(x, n):
    return ((x >> n) | (x << (64 - n))) & 0xFFFFFFFFFFFFFFFF


def keyfun(c):
    """64-bit challenge mixer, exactly as disassembled at 0x400120."""
    x = c ^ 0xA3B195354A39B70D
    x = ((x >> 16) & 0x7FFFFFFF) ^ ror64(x, 47)
    x = (x * 0x64170D358AA115A1) & 0xFFFFFFFFFFFFFFFF
    x ^= x >> 29
    x = ror64(x, 13)
    x = (x * 0x65931D9DFC2010DB) & 0xFFFFFFFFFFFFFFFF
    x ^= x >> 31
    return x


# ---- ChaCha20 (20 rounds, sigma "expand 32-byte k", block counter from 1) ----

def rotl32(v, n):
    return ((v << n) | (v >> (32 - n))) & 0xFFFFFFFF


def chacha20_block(key, counter, nonce):
    constants = struct.unpack("<4I", b"expand 32-byte k")
    state = list(constants) + list(struct.unpack("<8I", key)) + [counter] + \
        list(struct.unpack("<3I", nonce))
    working = state[:]
    for _ in range(10):  # 20 rounds = 10 double rounds
        for a, b, c, d in ((0, 4, 8, 12), (1, 5, 9, 13), (2, 6, 10, 14),
                           (3, 7, 11, 15), (0, 5, 10, 15), (1, 6, 11, 12),
                           (2, 7, 8, 13), (3, 4, 9, 14)):
            working[a] = (working[a] + working[b]) & 0xFFFFFFFF
            working[d] = rotl32(working[d] ^ working[a], 16)
            working[c] = (working[c] + working[d]) & 0xFFFFFFFF
            working[b] = rotl32(working[b] ^ working[c], 12)
            working[a] = (working[a] + working[b]) & 0xFFFFFFFF
            working[d] = rotl32(working[d] ^ working[a], 8)
            working[c] = (working[c] + working[d]) & 0xFFFFFFFF
            working[b] = rotl32(working[b] ^ working[c], 7)
    return struct.pack("<16I", *[(w + s) & 0xFFFFFFFF for w, s in zip(working, state)])


def chacha20_xor(key, data, nonce=NONCE, counter=1):
    out = bytearray()
    for off in range(0, len(data), 64):
        block = chacha20_block(key, counter, nonce)
        counter = (counter + 1) & 0xFFFFFFFF
        chunk = data[off:off + 64]
        out += bytes(c ^ k for c, k in zip(chunk, block))
    return bytes(out)


# ---- Minimal RSP client (no-ack mode, chunked pipelining) ----

def rsp_packet(payload):
    return b"$" + payload + b"#" + f"{sum(payload) % 256:02x}".encode()


class RspClient:
    def __init__(self, host, port, timeout=5.0):
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.sock.sendall(rsp_packet(b"qSupported"))
        self._recv_reply()
        self.sock.sendall(rsp_packet(b"QStartNoAckMode"))
        self._recv_reply()

    def _recv_reply(self):
        buf = b""
        while True:
            start = buf.find(b"$")
            if start != -1:
                end = buf.find(b"#", start)
                if end != -1 and len(buf) >= end + 3:
                    return buf[start:end + 3]
            chunk = self.sock.recv(4096)
            if not chunk:
                raise ConnectionError("stub closed connection")
            buf += chunk

    def _payload(self, reply):
        return reply[reply.find(b"$") + 1:reply.find(b"#")]

    def write_reg(self, addr, value):
        data = struct.pack("<I", value).hex().encode()
        self.sock.sendall(rsp_packet(f"M{addr:x},4:{data.decode()}".encode()))
        return self._recv_reply()

    def read_reg(self, addr):
        self.sock.sendall(rsp_packet(f"m{addr:x},4".encode()))
        return struct.unpack("<I", bytes.fromhex(self._payload(self._recv_reply()).decode()))[0]

    def read_byte(self, offset):
        self.write_reg(OFFSET, offset)
        self.sock.sendall(rsp_packet(f"m{DATA:x},1".encode()))
        return bytes.fromhex(self._payload(self._recv_reply()).decode())[0]

    def dump_page(self, length, chunk=7):
        """Pipelined OFFSET/DATA pairs; the leading bytes are re-read in
        reverse order because the stub returns them stale (see writeup)."""
        data = bytearray()
        for base in range(0, length, chunk):
            idxs = list(range(base, min(base + chunk, length)))
            for i in idxs:
                self.write_reg(OFFSET, i)
                self.sock.sendall(rsp_packet(f"m{DATA:x},1".encode()))
            for _ in idxs:
                data.append(bytes.fromhex(self._payload(self._recv_reply()).decode())[0])
        head = min(8, length)
        fixed = [self.read_byte(i) for i in range(head - 1, -1, -1)][::-1]
        data[:head] = bytes(fixed)
        return bytes(data)

    def close(self):
        self.sock.close()


def challenge_from_capture(path):
    """Parse the recorded session; demonstrates why replay fails on a live
    bench (fresh per-connection challenge)."""
    lo = hi = None
    with open(path) as fh:
        for line in fh:
            rec = json.loads(line)
            if rec.get("packet") == "m" and rec.get("addr") == "40000020":
                lo = int(rec["data_le"], 16)
            elif rec.get("packet") == "m" and rec.get("addr") == "40000024":
                hi = int(rec["data_le"], 16)
    if lo is None or hi is None:
        raise ValueError("capture does not contain a challenge")
    challenge = lo | (hi << 32)
    return challenge, keyfun(challenge)


def activate_and_dump(host, port):
    rsp = RspClient(host, port)
    try:
        rsp.write_reg(CONTROL, 0x41)          # start maintenance handshake
        challenge = rsp.read_reg(LO) | (rsp.read_reg(HI) << 32)
        key = keyfun(challenge)
        rsp.write_reg(PAGE, 7)
        rsp.write_reg(KEY, key & 0xFFFFFFFF)  # low word first
        rsp.write_reg(KEY, key >> 32)
        rsp.write_reg(CONTROL, 0x93)          # expect STATUS -> 3
        while rsp.read_reg(STATUS) != 3:
            pass
        rsp.write_reg(CONTROL, 0x9C)          # unseal; CONTROL reads 4 after
        bank_key = rsp.dump_page(64)[:32]     # page 7, read it first (~20 s window)
        rsp.write_reg(PAGE, 3)
        length = rsp.read_reg(CIPHER_LEN)
        page3 = rsp.dump_page(length)
        return bank_key, page3
    finally:
        rsp.close()


def main(argv):
    if len(argv) >= 2 and argv[1] == "--verify":
        digest = hashlib.sha256(open(argv[2], "rb").read()).hexdigest()
        print("firmware sha256:", digest)
        print("match:", digest == FIRMWARE_SHA256)
        return 0
    if len(argv) >= 2 and argv[1] == "--capture":
        challenge, key = challenge_from_capture(argv[2])
        print(f"captured challenge: 0x{challenge:016x}")
        print(f"keyfun(challenge):  0x{key:016x}  (useless on a live bench)")
        return 0
    if len(argv) >= 2 and argv[1] == "--decrypt":
        bank_key = open(argv[2], "rb").read()
        if len(bank_key) != 32:
            raise SystemExit("bank key file must hold exactly 32 raw bytes")
        page3 = open(argv[3], "rb").read() if len(argv) > 3 else PAGE3_CIPHERTEXT
        sys.stdout.buffer.write(chacha20_xor(bank_key, page3) + b"\n")
        return 0
    if len(argv) >= 3 and argv[1] == "--live":
        # TODO: supply host/port of the (retired) bench; never hardcode them.
        bank_key, page3 = activate_and_dump(argv[2], int(argv[3]))
        print("page 3 decrypted:")
        sys.stdout.buffer.write(chacha20_xor(bank_key, page3) + b"\n")
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
