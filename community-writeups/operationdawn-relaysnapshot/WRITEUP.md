# Operation Dawn — Relay Snapshot

**Category:** Reverse engineering / Misc

**Flag:** `CSCTF{REDACTED}`

## Overview

The supplied file, `relay.core`, is an x86-64 Linux ELF core dump. The flag is stored as fragments in a linked list on the heap, mixed with unrelated message fragments.

This writeup follows the overview/resources/walkthrough structure of the [CSCTF 2025 challenge compendium](https://github.com/ChronosPK/CSCTF-2025-challenges/blob/main/README.md). That repository does not contain this challenge; the findings below come from the supplied core dump.

## Resources

- `relay.core`: supplied memory snapshot.
- `solve.py`: dependency-free Python solver.

## Solution walkthrough

### 1. Inspect the snapshot

```sh
file relay.core
strings -a -t x relay.core | head -40
readelf -l relay.core
```

Strings include `CSCTF`, `{20_`, `_mov`, and `59c}`, alongside messages such as `burn_it` and `fall_back`. File order does not give the flag order.

The relevant `PT_LOAD` segment maps file offset `0x33f8` to virtual address `0x55a7aff17000`, with size `0x21000`. Convert a pointer in this segment to a file offset with:

```text
offset = 0x33f8 + (pointer - 0x55a7aff17000)
```

### 2. Recover the node layout

```sh
xxd -s 0x3690 -l 1104 relay.core
```

The fragments are in allocations spaced `0x30` bytes apart. Each node starts with an eight-byte little-endian pointer, followed by a four-byte length and the fragment bytes:

```c
struct node {
    struct node *next;  // +0x00
    uint32_t length;    // +0x08
    char fragment[];   // +0x0c
};
```

For example, `CSCTF` occurs at file offset `0x37c4`. Its node starts at `0x37b8`, corresponding to virtual address `0x55a7aff173c0`. The next pointer is `0x55a7aff17450`, which maps to `0x3848`: the node containing `{20_`.

### 3. Follow the pointers

Starting at the `CSCTF` node yields:

| Node address | Fragment |
|---|---|
| `0x55a7aff173c0` | `CSCTF` |
| `0x55a7aff17450` | `{20_` |
| `0x55a7aff17570` | `dock` |
| `0x55a7aff174e0` | `_mov` |
| `0x55a7aff17330` | `e_orc` |
| `0x55a7aff17300` | `hard_` |
| `0x55a7aff175d0` | `elm_` |
| `0x55a7aff17630` | `grove` |
| `0x55a7aff17390` | `_dus` |
| `0x55a7aff172d0` | `k_866` |
| `0x55a7aff17690` | `59c}` |

The final node has a null next pointer. Concatenate the length-delimited fragments without adding separators.

```sh
python3 solve.py relay.core
# CSCTF{REDACTED}
```

The solver reads the ELF load mappings, locates the length-prefixed `CSCTF` fragment, and follows its chain. Assertions check mapping bounds, head uniqueness, cycles, and flag delimiters. The result was also checked against a separate traversal using the heap mapping above. No live challenge submission was performed.
