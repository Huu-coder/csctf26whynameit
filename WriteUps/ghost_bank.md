### Ghost Bank

> Reverse engineering · Hard · Chronos Security
> Points at solve: [fill in]

**Tools used**

capstone (disassembly), custom RSP client (`rspc.py`), Python ChaCha20.

**Approach**

Bench: <instance> (raw TCP GDB Remote Serial Protocol)

Handout:

- `firmware.bin` — 956-byte flat AArch64 image, loaded at `0x00400000` (sha256 `f0b30ccf52d984559b144ca812ef77eedebfe36fdbd8092343ff11b66f1cdf47`)
- `firmware-load.txt` — load metadata, MMIO map, RSP stub behaviour
- `capture.ndjson` — 8-packet historical maintenance session

MMIO map (from `firmware-load.txt`):

| Register | Address | Access |
|---|---|---|
| CONTROL | `0x40000000` | r/w |
| PAGE | `0x40000008` | w |
| OFFSET | `0x40000010` | w |
| DATA | `0x40000018` | r (1 byte) |
| CIPHER_LEN | `0x4000001c` | r |
| CHALLENGE_LO | `0x40000020` | r |
| CHALLENGE_HI | `0x40000024` | r |
| KEY | `0x40000028` | w |
| STATUS | `0x40000030` | r |

All 4-byte accesses aligned LE32; any other width/address replies `E01`.

Firmware. `capstone` disassembly of the image shows three routines.

**Main loop (`0x400000`)** — the controller's activation protocol:

```
wait  [CONTROL] == 0x41                  ; 'A' = start maintenance handshake
w1 = [CHALLENGE_HI]; w0 = [CHALLENGE_LO]
[PAGE] = 7
challenge = w0 | (w1 << 32)              ; 64-bit challenge
key = keyfun(challenge)                  ; bl 0x400120
[KEY] = key & 0xffffffff                 ; low word
[KEY] = key >> 32                        ; high word
[CONTROL] = 0x93
poll [STATUS] until == 3                 ; key accepted
[CONTROL] = 0x9c                         ; unseal diagnostic bank
```

**`keyfun` (`0x400120`)** — 64-bit mixer, exactly:

```python
def keyfun(c):
    x = c ^ 0xA3B195354A39B70D
    x = ((x >> 16) & 0x7fffffff) ^ ror64(x, 47)
    x = (x * 0x64170D358AA115A1) & (2**64-1)
    x ^= x >> 29
    x = ror64(x, 13)
    x = (x * 0x65931D9DFC2010DB) & (2**64-1)
    x ^= x >> 31
    return x
```

**ChaCha20 (`0x400174` block, `0x4002e0` stream XOR)** — standard 20-round ChaCha with sigma `"expand 32-byte k"` (at `0x4003a0`), nonce `"SEAL-V01\x00\x00\x00\x01"` (at `0x4003b0`), key pointer passed in `x0`, and the block counter **starting at 1** (`w13 = 1` before the first block call).

The capture is a decoy for replay. `capture.ndjson` records an old maintenance session:

```
M 40000000 = 41          ; CONTROL = 'A'
m 40000020 = efcdab89    ; CHALLENGE_LO
m 40000024 = 67452301    ; CHALLENGE_HI  (challenge 0x0123456789abcdef)
M 40000008 = 07          ; PAGE = 7
M 40000028 = <redacted>  ; KEY low
M 40000028 = <redacted>  ; KEY high
M 40000000 = 93          ; CONTROL = 0x93
m 40000030 = 03          ; STATUS = 3
```

The challenge `0x0123456789abcdef` is synthetic and the derived key is useless on a live bench: every connection issues a fresh 64-bit challenge. The point is to reimplement `keyfun` from the firmware and run the handshake against the live challenge read from `0x40000020`/`0x40000024`.

Live activation. After writing `CONTROL = 0x41` the live bench exposes a random challenge, e.g.:

```
challenge = 0xfd6717f2d4894c7b
key       = keyfun(challenge) = 0x7bd8d039cf6dbebf
```

Then, replicating the firmware exactly:

```
PAGE     = 7
KEY      = key & 0xffffffff
KEY      = key >> 32
CONTROL  = 0x93      -> STATUS becomes 3 (accepted)
CONTROL  = 0x9c      -> bank unsealed, CONTROL reads 4
```

Replaying the captured key instead leaves `STATUS = 3` unreachable — the "recorded value is still valid" trap.

Reading the sealed bank. `CIPHER_LEN` reports the per-page payload length. After unsealing:

- **PAGE 3, len 131** — the ChaCha20-sealed staged tasking.
- **PAGE 7, len 0** — the 32-byte bank key, followed by 32 zero bytes.

Page 7 is only readable during the short unseal window right after `CONTROL = 0x9c`; within ~20 s it reverts to the sealed fixed blob `e655d996d1fdf37e48e3a2904014664da8395e7805a06973059c99cb5869428c...` so read it first. The unsealed key is constant across benches:

```
<redacted>
```

Page 3 is read byte-by-byte: write `OFFSET = n`, read one byte from `DATA`.

RSP performance/quirks:

- The link is ~250 ms RTT; pipelining `M OFFSET` / `m DATA` pairs in small chunks (6–8 offsets, drain replies between chunks) is ~20× faster than synchronous packets. Sending hundreds of packets at once makes the stub close the connection.
- **First bytes of a pipelined page 3 dump can be stale.** With chunked forward reads the first ~7 ciphertext bytes came back wrong (`b8 68 d6 f1 d1 4b a4 0d`) while bytes 8+ were correct. Re-reading the first offsets in **reverse order** yielded the true bytes `54 2c 88 47 4c 43 a4 0d`. Substituting those recovered the full plaintext.

True 131-byte page-3 ciphertext (first 8 bytes repaired):

```
542c88474c43a40d7782ccda43d6a141109d7595df242a58b1c6c2731b8162bf
b6cb5e57e2cd40a8f908f86f4cb10f23b170f230d1f0b21a94876c587aab6d0
7cccb47bff3bd3e64ce9ff2f5e78d40313219b26a8271fac8eaa375323d3c451
86ec5cdc56718b81e553107a45d29690c72260c9544f6172d6bd84cb36e6ad5
42c2c610
```

Decryption. Exactly the firmware's ChaCha20 parameters:

```
key     = <redacted>
nonce   = 53 45 41 4c 2d 56 30 31 00 00 00 01   ("SEAL-V01\0\0\0\1")
counter = 1
```

Plaintext:

```
TASKING//STAGED-EW//RELAY-BENCH//AUTHKEY CSCTF{REDACTED}//JAM PROFILE: 435.125MHz; TRIGGER: PRIMARY-LINK LOSS//END
```

Working artefacts: `../ghost_bank_solve/rspc.py` — minimal RSP client (no-ack mode, batching); `../ghost_bank_solve/step6.py` — activation + page 7 / page 3 dump; `../ghost_bank_solve/verify.py`, `slowread.py` — first-bytes recovery study; `../ghost_bank_solve/final_decrypt.py` — ChaCha20 bank decryption.

**Why it works**

The firmware is a software activation protocol that authenticates the operator via a fresh per-connection 64-bit challenge: the challenge is mixed by `keyfun`, and the resulting key must be written (low word, then high word) to `KEY` before `CONTROL = 0x93` will flip `STATUS` to 3 and allow the `0x9c` unseal. The provided capture is a synthetic decoy — replaying its fixed key cannot satisfy a live bench because `CHALLENGE_LO`/`CHALLENGE_HI` are regenerated per connection; reimplementing `keyfun` from the disassembly and deriving the key from the live challenge satisfies the check. The unsealed bank holds the stage-2 ciphertext (page 3) and the stage-2 decryption key (page 7); ChaCha20 with the exact firmware parameters (sigma, nonce, block counter starting at 1) recovers the staged tasking text. The stale leading bytes are a stub pipelining artifact, worked around by re-reading the first offsets in reverse order.

**Validation**

After `CONTROL = 0x93`, `STATUS` reached 3 (key accepted); after `CONTROL = 0x9c`, `CONTROL` read 4 (bank unsealed). Page 7 returned the 32-byte bank key during the short unseal window; page 3 (131 bytes) decrypted with the firmware's exact ChaCha20 parameters to a coherent `TASKING//STAGED-EW//...` message ending in `//END`, containing the flag (`CSCTF{REDACTED}`). The firmware image sha256 (`f0b30ccf52d984559b144ca812ef77eedebfe36fdbd8092343ff11b66f1cdf47`) matched the handout.
