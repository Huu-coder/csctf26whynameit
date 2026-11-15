# Third-party solver from the CSCTF 2026 archive (authorship unknown); flags redacted here if present.
from pathlib import Path
import struct

binary = Path(__file__).with_name("fcunlock").read_bytes()
a, b, shift, count, *targets = struct.unpack_from("<7Q", binary, 0x79020)
assert shift == 33 and count == len(targets) == 3
mask = (1 << 64) - 1
code = bytearray()
for target in targets:
    value = target ^ (target >> shift)
    value = value * pow(b, -1, 1 << 64) & mask
    value ^= value >> shift
    value = value * pow(a, -1, 1 << 64) & mask
    value ^= value >> shift

    check = value ^ (value >> shift)
    check = check * a & mask
    check ^= check >> shift
    check = check * b & mask
    check ^= check >> shift
    assert check == target
    code.extend(value.to_bytes(8, "little"))

print("CSCTF{REDACTED}")
