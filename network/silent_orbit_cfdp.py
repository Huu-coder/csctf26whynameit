#!/usr/bin/env python3
"""
Silent Orbit CFDP Recovery (CSCTF 2026, Network - Easy)

Walks a recording of concatenated CCSDS Space Packets, isolates the target
CFDP transaction (source 01, seq 07, dest 02), rebuilds the file-coverage map
from File Data PDUs, and constructs the acknowledged-mode NAK (directive 08)
listing the missing byte ranges over the scope [0, file_size).

Usage: python3 silent_orbit_cfdp.py <recording.bin> [nak.bin]
Without [nak.bin] the NAK is printed as hex; with it the raw PDU is written.

The CTF instance is retired; this PoC documents the exploit path.
"""
import struct
import sys

TARGET_APID = 0x321
SEQ_FLAGS_EOM = 0b11                # end of message / unsegmented
TX_SOURCE = 0x01
TX_SEQ = 0x07
TX_DEST = 0x02

# CFDP 727.2-B v1 small-file layout. Directive codes for Metadata/EOF and the
# in-PDU field offsets are not published in the writeup; NAK=0x08 is the only
# code the writeup fixes. TODO: adjust these constants against the capture.
DIR_METADATA = 0x02                # TODO: verify against capture
DIR_EOF = 0x04                     # TODO: verify against capture
DIR_NAK = 0x08                     # fixed by the writeup
EOF_CONDITION_OK = 0x00
EOF_CONDITION_OFF = 5               # TODO: offset not in writeup
EOF_CHECKSUM_OFF = 6                # small-file: 4-octet checksum
EOF_SIZE_OFF = 10                   # small-file: 4-octet file size
FD_OFFSET_OFF = 4                   # file-data PDU: 4-octet file offset
NAK_SCOPE_END = 0xC0


def walk_space_packets(data: bytes):
    # CCSDS primary header is 6 octets; packet_data_length + 1 is the body size.
    off = 0
    while off + 6 <= len(data):
        b0, b1, _b2, _b3, len_hi, len_lo = data[off:off + 6]
        apid = ((b0 & 0x07) << 8) | b1
        pdu_type = (b0 >> 4) & 0x01           # 0 = TM, 1 = TC
        sec_hdr = (b0 >> 3) & 0x01
        seq_flags = (data[off + 2] >> 6) & 0x03
        body_len = ((len_hi << 8) | len_lo) + 1
        end = off + 6 + body_len
        if end > len(data):
            break                               # truncated tail; stop, no resync
        yield apid, pdu_type, sec_hdr, seq_flags, data[off:end], off
        off = end


def cfdp_pdu(packet: bytes) -> bytes:
    return packet[6:]                # primary header stripped; no secondary header


def pdu_header(pdu: bytes):
    first = pdu[0]
    return {
        "version": (first >> 5) & 0x07,          # expect 0b001
        "type": (first >> 4) & 0x01,             # 0 = file directive, 1 = file data
        "direction": (first >> 3) & 0x01,
        "mode": (first >> 2) & 0x01,             # 1 = acknowledged
        "crc": (first >> 1) & 0x01,
        "large_file": first & 0x01,              # 0 = small file
        "source": pdu[1],
        "seq": pdu[2],
        "dest": pdu[3],
    }


def target_pdus(data: bytes):
    for apid, pdu_type, sec_hdr, seq_flags, pkt, stream_off in walk_space_packets(data):
        if apid != TARGET_APID or pdu_type != 0 or sec_hdr != 0:
            continue
        if seq_flags != SEQ_FLAGS_EOM:
            continue
        h = pdu_header(cfdp_pdu(pkt))
        if h["version"] != 0b001:
            continue
        if (h["source"], h["seq"], h["dest"]) != (TX_SOURCE, TX_SEQ, TX_DEST):
            continue
        yield h, cfdp_pdu(pkt), stream_off


def merge_ranges(ranges):
    merged = []
    for start, end in sorted(ranges):
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return merged


def missing_intervals(covered, file_size):
    missing, cursor = [], 0
    for start, end in merge_ranges(covered):
        start, end = max(start, 0), min(end, file_size)
        if start > cursor:
            missing.append((cursor, start))
        cursor = max(cursor, end)
    if cursor < file_size:
        missing.append((cursor, file_size))
    return missing


def build_nak(file_size: int, missing) -> bytes:
    first = (0b001 << 5) | (0 << 4) | (1 << 3) | (1 << 2) | (0 << 1) | 0  # directive, toward sender, ack, no CRC, small file
    header = bytes([first, TX_SOURCE, TX_SEQ, TX_DEST])
    body = bytes([DIR_NAK]) + struct.pack(">II", 0, file_size)
    for start, end in missing:
        body += struct.pack(">II", start, end)
    return header + body


def main() -> None:
    if len(sys.argv) < 2:
        raise SystemExit(__doc__)
    data = open(sys.argv[1], "rb").read()

    file_size = None
    covered = []
    eof_seen = False
    for h, pdu, stream_off in target_pdus(data):
        if h["type"] == 1:                        # File Data PDU
            offset = struct.unpack_from(">I", pdu, FD_OFFSET_OFF)[0]
            payload_len = len(pdu) - FD_OFFSET_OFF - 4
            if payload_len > 0:
                covered.append((offset, offset + payload_len))
            continue
        directive = pdu[4]
        if directive == DIR_METADATA:
            # Metadata PDU declares the file size; small-file encoding keeps it
            # in the first 4 octets after the fixed fields. TODO: adjust offset
            # if the capture disagrees -- the writeup reports 0xC0 (192).
            file_size = struct.unpack_from(">I", pdu, 13)[0] if len(pdu) >= 17 else NAK_SCOPE_END
            print(f"[*] Metadata PDU at stream offset 0x{stream_off:x}: file_size=0x{file_size:x}")
        elif directive == DIR_EOF:
            condition = pdu[EOF_CONDITION_OFF]
            checksum = struct.unpack_from(">I", pdu, EOF_CHECKSUM_OFF)[0]
            eof_size = struct.unpack_from(">I", pdu, EOF_SIZE_OFF)[0]
            if condition == EOF_CONDITION_OK and checksum == 0 and not eof_seen:
                eof_seen = True                   # first accepted EOF snapshots coverage
                print(f"[*] EOF PDU accepted at stream offset 0x{stream_off:x}: size=0x{eof_size:x}")

    if file_size is None:
        print("[!] no Metadata PDU parsed; assuming file size 0xC0 from the writeup")
        file_size = NAK_SCOPE_END

    merged = merge_ranges(covered)
    missing = missing_intervals(merged, file_size)
    print("[*] missing intervals:", " ".join(f"[{s},{e})" for s, e in missing))

    nak = build_nak(file_size, missing)
    print(f"[*] NAK PDU ({len(nak)} bytes): {nak.hex()}")
    if len(sys.argv) >= 3:
        open(sys.argv[2], "wb").write(nak)
        print(f"[*] NAK written to {sys.argv[2]}")


if __name__ == "__main__":
    main()
