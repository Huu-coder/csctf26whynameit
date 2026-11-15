# Third-party solver from the CSCTF 2026 archive (authorship unknown); flags redacted here if present.
#!/usr/bin/env python3
"""Recover the flag's linked list from relay.core; no dependencies."""
import struct
import sys
from pathlib import Path


def solve(data):
    assert data[:6] == b'\x7fELF\x02\x01', 'Expected little-endian ELF64'
    assert struct.unpack_from('<H', data, 16)[0] == 4, 'Expected a core dump'
    phoff = struct.unpack_from('<Q', data, 32)[0]
    phsize, phnum = struct.unpack_from('<HH', data, 54)
    segments = []
    for i in range(phnum):
        kind, _, offset, address, _, size, _, _ = struct.unpack_from(
            '<IIQQQQQQ', data, phoff + i * phsize)
        if kind == 1:
            assert offset + size <= len(data), 'Truncated segment'
            segments.append((address, offset, size))

    def file_offset(address, size):
        for base, offset, length in segments:
            if base <= address and address + size <= base + length:
                return offset + address - base
        raise ValueError(f'Unmapped address: {address:#x}')

    # The fragment follows a next pointer (8 bytes) and length (4 bytes).
    heads = []
    for base, offset, size in segments:
        start = offset
        while (hit := data.find(b'CSCTF', start, offset + size)) != -1:
            if hit >= offset + 12 and struct.unpack_from('<I', data, hit - 4)[0] == 5:
                heads.append(base + hit - offset - 12)
            start = hit + 1
    assert len(heads) == 1, f'Expected one flag head, found {len(heads)}'

    address = heads[0]
    seen = set()
    fragments = []
    while address:
        assert address not in seen, 'Cycle in flag chain'
        seen.add(address)
        offset = file_offset(address, 12)
        following, length = struct.unpack_from('<QI', data, offset)
        offset = file_offset(address + 12, length)
        fragments.append(data[offset:offset + length])
        address = following
    flag = b''.join(fragments).decode('ascii')
    assert flag.startswith('CSCTF{REDACTED}'), 'Incomplete flag'
    return flag


if __name__ == '__main__':
    print(solve(Path(sys.argv[1] if len(sys.argv) > 1 else 'relay.core').read_bytes()))
