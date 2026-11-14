#!/usr/bin/env python3
"""
Onion Deanon - Certificate Serial (CSCTF 2026, OSINT - Easy)

Extracts the serial number from a DER-captured TLS certificate presented by
the retired onion service (openssl x509 -serial equivalent), in pure Python.

Usage: python3 onion_deanon_cert_serial.py <cert.der>

The CTF instance is retired; this PoC documents the exploit path.
"""
import sys


def read_tlv(buf: bytes, off: int):
    """Parse one ASN.1 TLV; return (tag, value_start, value_end, next_off)."""
    tag = buf[off]
    pos = off + 1
    first_len = buf[pos]
    pos += 1
    if first_len & 0x80:
        n = first_len & 0x7F
        length = int.from_bytes(buf[pos:pos + n], "big")
        pos += n
    else:
        length = first_len
    return tag, pos, pos + length, pos + length


def children(buf: bytes, start: int, end: int):
    off = start
    while off < end:
        tag, vs, ve, nxt = read_tlv(buf, off)
        yield tag, vs, ve
        off = nxt


def cert_serial(der: bytes) -> int:
    # Certificate ::= SEQUENCE { tbsCertificate SEQUENCE { ... } }
    _, cert_vs, cert_ve, _ = read_tlv(der, 0)
    tbs_tag, tbs_vs, tbs_ve, _ = read_tlv(der, cert_vs)
    assert tbs_tag == 0x30, "expected tbsCertificate SEQUENCE"
    for tag, vs, ve in children(der, tbs_vs, tbs_ve):
        if tag == 0x02:                          # serialNumber INTEGER (version is [0], 0xA0)
            return int.from_bytes(der[vs:ve], "big")
    raise ValueError("serialNumber INTEGER not found")


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit(__doc__)
    der = open(sys.argv[1], "rb").read()
    serial = cert_serial(der)
    hex_serial = format(serial, "x")
    if len(hex_serial) % 2:
        hex_serial = "0" + hex_serial
    print(f"serial={hex_serial.upper()}")


if __name__ == "__main__":
    main()
