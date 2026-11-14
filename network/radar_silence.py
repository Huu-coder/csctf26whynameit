#!/usr/bin/env python3
"""
Radar Silence (CSCTF 2026, Network - Easy)

Replays a PCAP/PCAPNG, pulls DNS queries from the suspect radar host,
reassembles the four exfiltrated chunks from the anomalous
'*.update.svc-telemetry.example' namespace, and base32-decodes the
bearer token.

Usage: python3 radar_silence.py <capture.pcapng>

The CTF instance is retired; this PoC documents the exploit path.
"""
import base64
import socket
import struct
import sys

SUSPECT_HOST = "192.0.2.37"           # RDR37, the station under suspicion
EXFIL_SUFFIX = ".update.svc-telemetry.example"
DNS_PORT = 53


def iter_pcap(data: bytes):
    magic = data[:4]
    if magic == b"\xa1\xb2\xc3\xd4" or magic == b"\xd4\xc3\xb2\xa1" \
            or magic == b"\xa1\xb2\x3c\x4d" or magic == b"\x4d\x3c\xb2\xa1":
        fmt = ">" if magic[:4] in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d") else "<"
    else:
        raise ValueError("not a classic pcap file")
    off = 24
    while off + 16 <= len(data):
        _ts, _tus, incl_len, _orig_len = struct.unpack_from(fmt + "IIII", data, off)
        off += 16
        yield data[off:off + incl_len]
        off += incl_len


def iter_pcapng(data: bytes):
    off = 0
    endian = "<"
    linktypes = []
    while off + 12 <= len(data):
        raw_type = struct.unpack_from("<I", data, off)[0]
        if raw_type == 0x0A0D0D0A:                 # Section Header Block: fix endianness
            endian = "<" if data[off + 8:off + 12] == b"\x4d\x3c\x2b\x1a" else ">"
        btype, blen = struct.unpack_from(endian + "II", data, off)
        body = data[off + 8:off + blen - 4]
        if btype == 0x00000001:                    # Interface Description Block
            linktypes.append(struct.unpack_from(endian + "H", body, 0)[0])
        elif btype == 0x00000006:                  # Enhanced Packet Block
            if_id, _ts_hi, _ts_lo, cap_len, _orig = struct.unpack_from(endian + "IIIII", body, 0)
            link = linktypes[if_id] if if_id < len(linktypes) else 1
            pkt = body[20:20 + cap_len]
            if link == 1:
                yield pkt
        elif btype == 0x00000003:                  # Simple Packet Block
            (orig_len,) = struct.unpack_from(endian + "I", body, 0)
            yield body[4:4 + min(orig_len, blen - 16)]
        off += blen


def parse_dns_qname(payload: bytes, offset: int):
    labels, pos = [], offset
    while pos < len(payload):
        ln = payload[pos]
        if ln == 0:
            return ".".join(labels), pos + 1
        if ln & 0xC0:                              # compression pointer: not valid in a question
            return None, None
        labels.append(payload[pos + 1:pos + 1 + ln].decode("ascii", "replace"))
        pos += 1 + ln
    return None, None


def iter_udp_dns(packet: bytes):
    # Ethernet -> IPv4 -> UDP -> DNS question.
    if len(packet) < 14 or packet[12:14] != b"\x08\x00":
        return
    ip_off = 14
    ihl = (packet[ip_off] & 0x0F) * 4
    total_len = struct.unpack_from(">H", packet, ip_off + 2)[0]
    proto = packet[ip_off + 9]
    frag = struct.unpack_from(">H", packet, ip_off + 6)[0] & 0x3FFF
    src = socket.inet_ntoa(packet[ip_off + 12:ip_off + 16])
    if proto != 17 or frag != 0:
        return
    udp_off = ip_off + ihl
    udp_end = min(ip_off + total_len, len(packet))
    src_port, dst_port, udp_len = struct.unpack_from(">HHH", packet, udp_off)
    if DNS_PORT not in (src_port, dst_port):
        return
    dns = packet[udp_off + 8:min(udp_off + udp_len, udp_end)]
    if len(dns) < 12:
        return
    qdcount = struct.unpack_from(">H", dns, 4)[0]
    pos = 12
    for _ in range(qdcount):
        qname, pos = parse_dns_qname(dns, pos)
        if qname is None:
            return
        yield src, src_port, dst_port, qname.lower()
        pos += 4                                 # QTYPE + QCLASS


def exfil_chunks(path: str) -> str:
    with open(path, "rb") as fh:
        data = fh.read()
    packets = iter_pcapng(data) if data[:4] == b"\x0a\x0d\x0d\x0a" else iter_pcap(data)
    chunks = {}
    for pkt in packets:
        for src, _sport, _dport, qname in iter_udp_dns(pkt):
            if src != SUSPECT_HOST or not qname.endswith(EXFIL_SUFFIX):
                continue
            labels = qname.split(".")
            # Pattern: <chunk>.<seq>.update.svc-telemetry.example
            if len(labels) < 5 or not labels[1].isdigit():
                continue
            chunks[int(labels[1])] = labels[0]
    if not chunks:
        raise SystemExit("no exfil queries found from " + SUSPECT_HOST)
    return "".join(chunks[k] for k in sorted(chunks))


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit(__doc__)
    blob = exfil_chunks(sys.argv[1])
    print(f"[*] reassembled {len(blob)} base32 chars from {(len(blob) + 7) // 8} padding slots")
    padded = blob.upper() + "=" * ((8 - len(blob) % 8) % 8)
    decoded = base64.b32decode(padded)
    print(f"[*] decoded bearer token ({len(decoded)} bytes): {decoded.decode('ascii')}")


if __name__ == "__main__":
    main()
