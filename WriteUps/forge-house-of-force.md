### forge

> Pwn · Medium · Iulian Schifirnet
> Points at solve: [fill in]

**Tools used**

python3 (`/home/kali/csctf2026/forge_scripts/exploit.py`; `python3 exploit.py <host> <port>`, add `local` to run against the provided loader/libc). Attachments: `forge`, `forge.c`, `libc.so.6` (Ubuntu GLIBC 2.27-3ubuntu1.6), `ld-linux-x86-64.so.2`.

**Approach**

Target: glibc 2.27 pwn challenge. Protections: PIE, full RELRO, NX, canary. No seccomp.

Program: a tiny heap menu over 16 `struct note { char *data; size_t size; }` slots — `forge` (malloc of any size + read content), `temper` (append), `inspect` (`puts`), `melt` (`free`).

The bug is in `temper()`:

```c
read_until_nl(p + strlen(p), notes[i].size);   // should be size - strlen(p)
```

`read_until_nl` reads up to `size` bytes starting *after* the string terminator, so a fully filled chunk (no NUL inside) allows a linear heap overflow of up to `size` bytes past the chunk. `read_until_nl` stops at `\n` but stores NULs, so binary payloads are fine (addresses containing `0x0a` are the only caveat).

Because `strlen` walks into the *next* chunk's size field, the overflow starts at `next_chunk.size + 1` (the low byte of a size field is nonzero, the second byte is 0). Payload offsets are shifted by one byte accordingly.

libc offsets: `main_arena = 0x3ebc40`, unsorted `fd = main_arena+0x60 = 0x3ebca0`, `__free_hook = 0x3ed8e8`, `system = 0x4f420`.

1. **Libc leak.** Allocate `A' = 0x18`, `C = 0x500`, guard `D = 0x18` (so `C` doesn't merge into top when freed). Free `C` → unsorted bin, `C.fd = main_arena+0x60`. `puts(A')` over-reads into `C`'s header, but the size field `0x511` has a NUL byte that stops it early. Fix it with the overflow: after `free(C)`, `strlen(A') = 0x18 + 2` (`11 05` then NUL), so `temper(A')` writes 6 bytes at `C.size+2`, turning the size into `0xffffffffffff0511`. Now `puts` runs into `C.fd`, printing 6 bytes of the pointer. `libc = leak - 0x3ebca0`.
   *All later mallocs must be served by tcache* — any malloc that falls through to the corrupted unsorted chunk aborts, so all chunks are allocated up front.
2. **Tcache poison.** Allocate `E`, `F`, `G` (`0x28` → `0x30` chunks) contiguously, `E` immediately before `F`. Free `G` then `F` (`count = 2`, head `F`). `strlen(E) = 0x28 + 1` (next chunk's size `0x31` is nonzero, next byte NUL), so `temper(E)` starts at `F.size+1`: 7 padding bytes preserve the size and the next 8 bytes overwrite `F.fd = __free_hook`.
3. **Hook overwrite.** `forge(0x28)` pops `F`; the bin head becomes `__free_hook`. `forge(0x28)` returns the fake chunk at `__free_hook` — write `system` there. (glibc 2.27 `tcache_get` has no alignment/size checks.)
4. **Trigger.** A guard note `D` was forged with content `"/bin/sh\0"`. `melt(D)` → `free("/bin/sh")` → `__free_hook` → `system("/bin/sh")` → shell, `cat /flag*` → flag.

Note: the 250 ms-constant FIN on the initially advertised port was a dead relay backend; the alternate port served the binary.

**Why it works**

Root cause: `temper()` passes `notes[i].size` instead of `size - strlen(p)` as the read length, giving a linear heap overflow of up to `size` bytes past a fully filled chunk. Because `strlen(p)` bleeds one byte into the next chunk's size field, the overflow write lands at `next_chunk.size + 1`, letting it preserve the nonzero size byte while overwriting adjacent data. The leaked libc base comes from the unsorted-bin `fd` pointer (`main_arena+0x60`) — normally hidden behind the NUL in the `0x511` size field, until the `temper()` overflow rewrites that field to drop the NUL barrier. On glibc 2.27, `tcache_get` has no alignment/size checks, so poisoning a tcache `fd` to `__free_hook` yields an arbitrary allocation at the hook; overwriting `__free_hook` with `system` turns the next `free()` of a chunk containing `/bin/sh` into `system("/bin/sh")`.

**Validation**

`melt(D)` triggered `__free_hook` → `system("/bin/sh")`, and `cat /flag*` printed `CSCTF{REDACTED}`.
