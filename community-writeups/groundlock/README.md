# 🚩 REV 🚩

## <span style="color:#1E88E5">&#9679;</span> Groundlock

> Points: **Unknown** · Solves: **Unknown**

> **Flag:** `CSCTF{REDACTED}`<br>
> **Deployment:** Not provided<br>
> **Scoring:** Not provided

---

### Overview

#### Challenge Brief

The original challenge description was not supplied. From the provided binary, the objective is to recover a 24-byte service code that releases the GRIFFON-FC ground-maintenance interlock and prints a maintenance token.

**Flag format:** `CSCTF{message}`

---

### Resources

#### Files

- [fcunlock](fcunlock) — stripped, statically linked x86-64 Linux ELF executable.
- [solve.py](solve.py) — Python solver created during analysis; requires Python 3.8 or newer and no third-party packages.

#### Hints

No hints were supplied with the binary.

---

### Solution Walkthrough

1. Locate the service-code validation routine.
2. Extract the mixing function and its expected outputs.
3. Reverse the mixing operations to recover the service code.
4. Run the binary with the recovered code and read the flag.

#### 1. Locate the validation routine

Inspect the executable and its relevant strings:

```bash
file fcunlock
strings -t x fcunlock | rg 'usage:|ACCESS DENIED|GRIFFON|Maintenance token'
```

The strings reveal the interface and success output:

```text
usage: %s <service-code>
ACCESS DENIED
GRIFFON-FC ground-maintenance interlock released.
Maintenance token: CSCTF{%.*s}
```

The ELF entry point at `0x401530` passes `0x4016da` as the main function to the C runtime. Disassemble the main function and the helper immediately before it:

```bash
objdump -d -M intel --start-address=0x401655 --stop-address=0x401869 fcunlock
```

Main requires exactly one argument with a length of `3 * 8 = 24` bytes. It splits that argument into three little-endian 64-bit integers, calls the helper at `0x401655` on each, and compares the results with three stored constants. All three comparisons must succeed.

<br>

#### 2. Extract the mixing function and expected outputs

The helper performs the following operations, with multiplication wrapping modulo `2^64`:

```python
def mix(x):
    mask = (1 << 64) - 1
    x ^= x >> 33
    x = x * 0xff51afd7ed558ccd & mask
    x ^= x >> 33
    x = x * 0xc4ceb9fe1a85ec53 & mask
    x ^= x >> 33
    return x
```

Inspect the data used by the checker:

```bash
readelf -SW fcunlock | rg '\.rodata'
xxd -s 0x79020 -l 56 fcunlock
```

The `.rodata` section starts at virtual address `0x479000` and file offset `0x79000`. The seven little-endian 64-bit values beginning at file offset `0x79020` are:

| File offset | Value | Meaning |
| --- | --- | --- |
| `0x79020` | `0xff51afd7ed558ccd` | First multiplier |
| `0x79028` | `0xc4ceb9fe1a85ec53` | Second multiplier |
| `0x79030` | `33` | Right-shift count |
| `0x79038` | `3` | Number of blocks |
| `0x79040` | `0x8bfd351846ffb86b` | Expected result for block 0 |
| `0x79048` | `0x3ff3fd892aa7e3b2` | Expected result for block 1 |
| `0x79050` | `0xf61e79e7e639e0d2` | Expected result for block 2 |

<br>

#### 3. Reverse the mixing operations

Every operation is reversible. Both multipliers are odd, so each has a multiplicative inverse modulo `2^64`, computed with `pow(multiplier, -1, 1 << 64)`.

The XOR-shift also undoes itself. If `y = x ^ (x >> 33)`, then:

```text
y ^ (y >> 33) = x ^ (x >> 66) = x
```

The final term is zero because `x` is only 64 bits wide. Reverse the five operations in order: XOR-shift, inverse second multiplier, XOR-shift, inverse first multiplier, XOR-shift.

Save the following as `solve.py` beside `fcunlock`:

```python
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
```

The assertion runs each recovered block through the original mixing function to verify it matches its target. Converting the recovered integers back to little-endian bytes gives:

| Block | Recovered bytes |
| --- | --- |
| 0 | `HALCYON_` |
| 1 | `1B5FC6D7` |
| 2 | `2036689A` |

Run:

```bash
python3 solve.py
```

Output:

```text
CSCTF{REDACTED}
```

<br>

#### 4. Verify with the binary

Run a copy of the executable with the recovered service code, without the flag wrapper:

```bash
cp fcunlock /tmp/groundlock-fcunlock
chmod u+x /tmp/groundlock-fcunlock
/tmp/groundlock-fcunlock HALCYON_1B5FC6D72036689A
```

Verified output:

```text
GRIFFON-FC ground-maintenance interlock released.
Maintenance token: CSCTF{REDACTED}
```

The executable accepts the recovered code without any patches. Verification was local; no challenge-server submission was checked.

<br>
<br>

Format adapted from the [CSCTF 2025 Challenge Compendium](https://github.com/ChronosPK/CSCTF-2025-challenges/blob/main/README.md).
