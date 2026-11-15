#!/usr/bin/env python3
"""Recover the radio token without executing the firmware."""
from pathlib import Path
import re
import struct
import sys
import zlib


def solve(path):
    image = Path(path).read_bytes()
    magic, version, count = struct.unpack_from('<4sHH', image)
    assert (magic, version, count) == (b'DWFW', 1, 4), 'Unexpected firmware header'
    sections = {}
    for i in range(count):
        name, offset, size, crc = struct.unpack_from('<8sIII', image, 8 + 20 * i)
        data = image[offset:offset + size]
        assert len(data) == size and zlib.crc32(data) == crc, 'Section checksum mismatch'
        sections[name.rstrip(b'\0')] = data

    dictionary = sections[b'msgcat']
    compressed = sections[b'rootfs']
    assert zlib.adler32(dictionary) == int.from_bytes(compressed[2:6], 'big')
    decoder = zlib.decompressobj(zdict=dictionary)
    archive = decoder.decompress(compressed) + decoder.flush()
    assert decoder.eof, 'Truncated root filesystem'

    files = {}
    pos = 0
    while True:
        assert archive[pos:pos + 6] == b'070701', 'Expected newc CPIO header'
        header = [int(archive[pos + 6 + i * 8:pos + 14 + i * 8], 16) for i in range(13)]
        size, name_size = header[6], header[11]
        name = archive[pos + 110:pos + 110 + name_size - 1].decode()
        pos = (pos + 110 + name_size + 3) & ~3
        assert pos + size <= len(archive), 'Truncated CPIO entry'
        if name == 'TRAILER!!!':
            break
        files[name] = archive[pos:pos + size]
        pos = (pos + size + 3) & ~3

    token = bytes.fromhex(re.search(rb'^admin_token=([0-9a-f]+)$',
                                   files['etc/config/radio'], re.M)[1].decode())
    environment = sections[b'ubootenv']
    assert len(environment) == 0x4000
    flags = []
    for offset in (0, 0x2000):
        copy = environment[offset:offset + 0x2000]
        if zlib.crc32(copy[5:]) != int.from_bytes(copy[:4], 'little'):
            continue
        values = dict(item.split(b'=', 1) for item in copy[5:].split(b'\0') if b'=' in item)
        mac = bytes.fromhex(values[b'ethaddr'].decode().replace(':', ''))
        assert len(mac) == 6
        flag = bytes(byte ^ mac[i % 6] for i, byte in enumerate(token))
        if re.fullmatch(rb'CSCTF\{[ -~]+\}', flag):
            flags.append(flag.decode())
    assert len(flags) == 1, 'Expected exactly one valid flag across environment copies'
    return flags[0]


if __name__ == '__main__':
    print(solve(sys.argv[1] if len(sys.argv) > 1 else Path(__file__).with_name('firmware.bin')))
