### Relic

> Pwn · Medium · Iulian Schifirnet
> Points at solve: [fill in]

**Tools used**

Not specified. (The solve used a ROP exploit script, `/tmp/relic_solve.py`, with offsets from the bundled libc.)

**Approach**

The program reads `0x120` bytes into a `0x40`-byte stack buffer, allowing a 72-byte offset to saved RIP. The deposit is one-shot, so the exploit uses a first-stage ROP chain to read a second stage into `.bss`, pivots the stack there, leaks libc's `read` address with `write`, then computes libc base and calls `system()` with a command string.

Binary protections: no PIE, no stack canary, NX enabled, full RELRO. The included `__libc_csu_init` provides ret2csu gadgets. The exploit uses `read@GOT` (`0x403fe8`) and `write@GOT` (`0x403fd8`), and a writable `.bss` address at `0x404800`.

1. Overflow the saved return pointer after 72 bytes.
2. ret2csu-call `read(0, .bss, 0x200)`, then pivot via `leave; ret`.
3. Use ret2csu to call `write(1, read@GOT, 8)` and leak libc. Compute `libc_base = leak - 0x10e1e0` and `system = libc_base + 0x52290` using the bundled libc offsets.
4. Read another ROP stage, then call `system()` on a command to print the flag.

The exploit script used during the solve is `/tmp/relic_solve.py`.

**Why it works**

The missing stack canary and PIE make the overflow deterministic, and NX prevents shellcode injection, so the solve rides existing code: `__libc_csu_init`'s ret2csu gadgets give controlled `rdi`/`rsi`/`rdx` and a `call` primitive without libc knowledge up front. The one-shot constraint is worked around by staging the real chain into `.bss` with a first-stage `read` and pivoting the stack onto it with `leave; ret`, after which a GOT leak yields libc base and a clean `system()` call.

Remediation: bound input to the actual buffer size (or use a larger buffer), enable stack protection, and consider PIE. The one-shot requirement is challenge logic rather than a defense against the stack overflow.

**Validation**

The exploit chain completed and printed the flag via `system()`; the flag is redacted here (`CSCTF{REDACTED}`).
