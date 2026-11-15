# Operation DAWN — Radio Recovery

**Category:** Reverse engineering  
**File:** `firmware.bin` (1 MiB)  
**Flag:** `CSCTF{REDACTED}`

## Overview

Recover the radio's admin key from a firmware dump. The solution is entirely static: parse the container, decompress the filesystem using its embedded dictionary, and reproduce the startup script's XOR operation.

This writeup follows the overview/resources/walkthrough style of the [CSCTF 2025 challenge compendium](https://github.com/ChronosPK/CSCTF-2025-challenges). The findings below were derived from the local firmware, rather than a matching solution in that repository.

## Resources

- `firmware.bin`: original challenge artifact.
- `solve.py`: Python standard-library solver, with checksum and format assertions.

## Solution walkthrough

### 1. Parse the firmware container

`file firmware.bin` identifies generic data. The first eight bytes contain `DWFW`, followed by little-endian 16-bit version `1` and section count `4`. Each 20-byte table entry is `<8sIII`: name, offset, size, CRC32.

| Section | Offset | Size | CRC32 |
| --- | --- | --- | --- |
| loader | `0x0200` | `0x006f` | `e08559b1` |
| ubootenv | `0x0270` | `0x4000` | `0e0748da` |
| msgcat | `0x4270` | `0x0102` | `5a21c5b2` |
| rootfs | `0x4380` | `0x0279` | `65047329` |

All four CRC32 values match their section contents.

### 2. Supply the missing zlib dictionary

The rootfs begins with `78 f9`: a zlib stream with the preset-dictionary flag set. Ordinary `zlib.decompress()` fails with error 2 because it needs that dictionary.

The following four bytes specify dictionary Adler32 `55d45a6c`. This exactly matches the complete `msgcat` section, including its final newline. Decompress with:

```python
decoder = zlib.decompressobj(zdict=sections[b'msgcat'])
rootfs = decoder.decompress(sections[b'rootfs']) + decoder.flush()
```

The result is a 2,560-byte `newc` CPIO archive, identified by `070701` headers.

### 3. Reverse the admin-key initialization

`etc/config/radio` contains:

```text
admin_token=<redacted>
```

`etc/init.d/S40admin` reads `ethaddr` with `fw_printenv`, removes the colons, and XORs each token byte with the corresponding MAC byte, repeating every six bytes. It writes the decoded result to `/var/run/admin.key`.

The `ubootenv` section contains two 8,192-byte copies. Each has a four-byte little-endian CRC32, a one-byte marker, and NUL-separated environment variables. Both CRCs validate over the bytes after the five-byte header.

| Absolute offset | Marker | ethaddr | recovery |
| --- | --- | --- | --- |
| `0x0270` | `6` | `00:11:22:33:44:55` | `legacy` |
| `0x2270` | `7` | `3c:22:fb:4a:1d:90` | `ready` |

The second copy is consistent with the intended recovery configuration. Trying both valid copies confirms it: the first yields nonprintable garbage; the second yields the flag. The solver tests both rather than assuming a universal U-Boot marker-selection rule.

```python
mac = bytes.fromhex('3c22fb4a1d90')
flag = bytes(byte ^ mac[i % 6] for i, byte in enumerate(token))
```

### 4. Reproduce

```console
$ python3 solve.py
CSCTF{REDACTED}
```

The solver validates the section checksums, dictionary ID, decompression completion, archive structure, and environment CRCs, and requires exactly one flag-shaped result. No firmware execution or external packages are needed. The flag has not been submitted to a live scoreboard.
