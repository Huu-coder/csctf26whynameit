# 🚩 REV 🚩

## <span style="color:#1E88E5">&#9679;</span> HELIOS GRID RTU

> Points: **500** · Solves: **—**

> **Flag:** `CSCTF{REDACTED}`<br>
> **Deployment:** `dynamic`<br>
> **Scoring:** max 500, decay 50, min 100


---

### Overview

#### Challenge Brief
A HELIOS GRID remote terminal unit (RTU) exposes a single web service console. Behind it is a real emulated ATmega328P running signed control firmware. The unit issues a service token only for a correctly authenticated control directive — and the authentication key is physically unreadable from outside.

Identify the silicon, bring up the one interface on the bench that still answers, recover the application firmware, and produce a valid authentication tag over a control directive carrying the live nonce. Interact only with your assigned instance.

The entry point is a browser console (`http://HOST:PORT`) that is a *dumb terminal*: it ships every typed line verbatim over one WebSocket (`/ws`) and prints whatever the server returns. A "bench" view lets you pick a hardware adapter (AVR ISP, USB serial cable, JTAG probe, debugWIRE probe) and wire its leads onto target pins; the wiring is sent as a `wire ...` line. The server runs `avrdude` and an `svc` service client against the emulated MCU, using whichever transport you physically wired.

**Flag format:** **`CSCTF{...}`**

---

### Resources

#### Files
- No downloadable files. Everything is recovered live from the assigned instance over the WebSocket console.

#### Hints
- No hints provided. (The challenge text itself is the roadmap: *identify → bring up the one interface → recover firmware → forge a tag over the live nonce*.)


---

### Solution Walkthrough

1. Identify the silicon
2. Bring up the one interface that answers
3. Recover the application firmware
4. Reverse the service protocol and the MAC
5. Forge the CBC-MAC and issue the token

<br>

#### 1. Identify the silicon

The console speaks a small command set (`help`, `avrdude`, `apt`, `bench`, `wire`). The bench offers four adapters. The ATmega328P has **no JTAG scan-chain**, so that probe is a decoy. Wire a real **AVR ISP** to the ICSP header and read the signature:

```bash
# commands typed into the web console (shipped over /ws):
wire avrisp MISO:ICSP_MISO MOSI:ICSP_MOSI SCK:ICSP_SCK RESET:ICSP_RESET VCC:ICSP_VCC GND:ICSP_GND
avrdude -c avrisp -p m328p -U signature:r:-:h
```

```
avrdude: Device signature = 0x1e950f (probably m328p)
```

`0x1e950f` → **ATmega328P**.

<br>

#### 2. Bring up the one interface that answers

Read the fuses and lock bits over ISP:

```bash
avrdude -c avrisp -p m328p -U lfuse:r:-:h -U hfuse:r:-:h -U efuse:r:-:h -U lock:r:-:h
```

```
lfuse = 0xff
hfuse = 0xd8     ; DWEN=1 -> debugWIRE disabled, SPIEN enabled, BOOTRST=0, BOOTSZ=00
efuse = 0xfd
lock  = 0xfc     ; LB1=LB2=0  -> LOCK MODE 3 (programming + VERIFICATION disabled)
```

So three of the four adapters are dead ends:
- **JTAG** — absent on this MCU.
- **debugWIRE** — fused off (`DWEN=1`).
- **AVR ISP** — answers, *but* lock mode 3 disables flash/EEPROM **readback**. Dumping flash or EEPROM over ISP returns all `0xFF`:

```bash
avrdude -c avrisp -p m328p -U flash:r:-:i
# -> :20000000FFFFFFFF...FF   (every byte FF — readback blocked by lock bits)
```

That is the "authentication key is physically unreadable from outside": the external programmer cannot read the chip.

The one thing left: `hfuse` has `BOOTRST=0` (boot into the bootloader) and the boot-lock bits (`BLB`) are **unprogrammed**. Lock mode 3 only blocks *external* programmer reads — code running *inside* the chip (the serial bootloader) can still `LPM` the application flash and stream it out. Wire the **USB serial cable** and talk STK500/`arduino` to the bootloader:

```bash
wire usbserial USB:USB
avrdude -c arduino -p m328p -P /dev/ttyUSB0 -U signature:r:-:h   # bootloader answers
```

<br>

#### 3. Recover the application firmware

Dump flash (and EEPROM) through the bootloader:

```bash
avrdude -c arduino -p m328p -P /dev/ttyUSB0 -U flash:r:-:i      # real bytes this time
avrdude -c arduino -p m328p -P /dev/ttyUSB0 -U eeprom:r:-:h
```

Flash now contains real code; the EEPROM is an operator note that spells out the intended path verbatim:

```
scan/debug: JTAG scan-chain is ABSENT on this MCU, and
debugWIRE is fused OFF (hfuse DWEN=1). to read the unit use
ISP for signature/fuses, and the serial bootloader for
flash/eeprom. the application flash is yours; the boot
section is masked.
...
speak to it with the `svc` client (not loaded by default):
    apt install svc
```

Only the **application** section comes back; the **boot section is masked** (the bootloader refuses to dump its own region). Reassemble and convert the Intel-HEX to a binary:

```bash
# extract the :NN... records from the console output, then:
objcopy -I ihex flash.hex -O binary flash.bin   # 32 KiB, ~2 KB non-FF
```

A quick look shows the AES forward S-box (`63 7c 77 7b f2 6b 6f c5 ...`) and the Rcon table (`01 02 04 08 10 20 40 80 1b 36`) — so the firmware does **AES-128 encryption** (no inverse S-box → encrypt-only, i.e. a MAC).

<br>

#### 4. Reverse the service protocol and the MAC

Install and probe the service client:

```bash
apt install svc
svc            # subcommands: nonce | telemetry | sign <rec> | exec <frame> <tag>
svc nonce      # service: nonce = 7eeb03f54886e185        (8 bytes)
svc telemetry  # service: telemetry = 54017eeb5c4733103c4e374b555a3d2e
svc sign 00000000000000000000000000000000   # tag = 2545be16b0fcadff5d49df085d700e9e
svc exec                                     # frame must be 32 bytes (64 hex digits)
```

Disassembling `flash.bin` as AVR (radare2 `-a avr`) recovers the service state machine. The MCU speaks a framed serial protocol `[0xAA][opcode][len][payload]` with a `[0x55][status][len][data]` reply. Key routines:

- `0x1b8` — **xorshift32** PRNG (shift 13 ⊕ , 17 ⊕, 5), seeded `0xe98edaca` at boot. State at RAM `0x1b8`.
- `0x238` — nonce generator: two PRNG words → **8-byte nonce at RAM `0x1b0`**.
- `0x2b6` — `KeyExpansion(key)` → 176-byte round keys at RAM `0x100`.
- `0x39a` — `AES128_encrypt(dst, plaintext, roundkeys@0x100)`.
- `0x536` — `main`: init USART, **copy the 16-byte AES key from flash `0x7f00`** (inside the masked boot section!) → expand → generate nonce → dispatch loop.

Opcode handlers:

| opcode | name | behaviour |
|---|---|---|
| `0x01` | **sign** | `len==16`; reject if `rec[0]==0xCC`; reply `AES_K(rec)` |
| `0x02` | **exec** | `len==48` = `B0‖B1‖tag` (see below) |
| `0x03` | nonce | reply 8 bytes at `0x1b0` |
| `0x04` | telemetry | reply 16-byte status block |
| `0x05` | reseed | reseed PRNG from payload (or `0xdeadbeef`) + regen nonce |

So `svc sign` is a **single-block AES oracle**: `sign(x) = AES_K(x)` (as long as `x[0] != 0xCC`).

`svc exec` (handler `0x71c`) over the 48-byte payload does, in order:

```
t0  = AES_K(B0)                 ; 0x39a on first block
X   = t0 XOR B1                 ; XOR second block in
tag'= AES_K(X)                  ; 0x39a again
if tag' != provided_tag:  error 0x11      ; <-- this is CBC-MAC(IV=0) over B0‖B1
if B1[0]  != 0xCC:        error 0x14      ; directive magic
if B1[1]  != 0x0A:        error 0x15      ; directive version
if B1[2..9] != nonce@0x1b0: error 0x13    ; must carry the LIVE nonce
-> ISSUE_TOKEN                            ; success
```

Two crucial facts:
- The authentication is `tag == AES_K(AES_K(B0) ⊕ B1)` — **textbook 2-block CBC-MAC with IV=0**.
- **`B0` is never content-checked** — only the MAC, `B1`'s `CC 0A` prefix, and the nonce in `B1[2..9]` matter.
- The AES **key lives at flash `0x7f00`, in the masked boot section** → genuinely unrecoverable. We must forge *without* the key.

The only guard against forgery is that `sign` refuses records beginning with `0xCC` (the control-block magic) — but that is trivially sidestepped, because we never feed the control block to the oracle; we feed `X = AES_K(B0) ⊕ B1`.

<br>

#### 5. Forge the CBC-MAC and issue the token

A single-block AES oracle plus a CBC-MAC verifier is a classic existential forgery. For a chosen `B0` and the required `B1`:

```
t0  = sign(B0)              # = AES_K(B0)
X   = t0 XOR B1
tag = sign(X)               # = AES_K(AES_K(B0) XOR B1) == CBC-MAC(B0, B1)
```

Build `B1 = CC 0A ‖ <live nonce (8)> ‖ 00*6` and any `B0` (we use zeros). The only constraint is that `X[0] != 0xCC` so the oracle accepts it — since `B1[0]=0xCC`, that means `t0[0] != 0`; if it is zero, pick another `B0`. All of it runs in **one** WebSocket session so the nonce stays live (`nonce`/`sign` do not rotate it; `exec` only rotates it *after* the check).

```python
import json, time, websocket
URL = "ws://<instance>/ws"
ws = websocket.create_connection(URL, timeout=20)

def drain(t=1.2):
    ws.settimeout(t); out = []
    try:
        while True: out.append(ws.recv())
    except Exception: pass
    return out

def cmd(line, t=2.0):
    ws.send(line); time.sleep(0.15)
    return "\n".join(json.loads(m).get("data", "") for m in drain(t))

def val(resp):            # 'service: nonce = ....' -> hex bytes
    return bytes.fromhex(resp.split("=")[-1].strip())

drain(2.0)                         # banner
cmd("apt install svc")
N  = val(cmd("svc nonce"))         # live 8-byte nonce
B1 = bytes([0xCC, 0x0A]) + N + bytes(6)
B0 = bytes(16)                     # B0[0] != 0xCC
t0 = val(cmd("svc sign " + B0.hex()))          # AES_K(B0)
X  = bytes(a ^ b for a, b in zip(t0, B1))
assert X[0] != 0xCC                            # oracle rejects 0xCC-prefixed input
tag   = val(cmd("svc sign " + X.hex()))        # AES_K(t0 ^ B1)  == CBC-MAC(B0,B1)
frame = B0 + B1
print(cmd("svc exec " + frame.hex() + " " + tag.hex(), 3.0))
ws.close()
```

Running it:

```
[nonce] 7f2f49a7ac4b77d6
[t0=AES(B0)] 2545be16b0fcadff5d49df085d700e9e
[tag=AES(t0^B1)] da2fe927a6c10da079c52886716d0167
[frame] 00000000000000000000000000000000cc0a7f2f49a7ac4b77d6000000000000

service: directive authenticated
service: control action ISSUE_TOKEN accepted
service: SERVICE TOKEN = CSCTF{REDACTED}
```

Flag: `CSCTF{REDACTED}`

> **Takeaways**
> - AVR lock bits (mode 3) only block *external* programmer reads. If `BOOTRST` points at a bootloader and the boot-lock bits are open, the chip will happily dump its own application flash over serial — the "unreadable" flash is one adapter swap away.
> - Hiding the AES key in the masked boot section makes it truly unrecoverable, which is the point: the intended solve is an **oracle-based CBC-MAC forgery**, not key extraction.
> - Refusing to `sign` blocks that start with the `0xCC` magic looks like a forgery defence but isn't — CBC-MAC forgery feeds `AES_K(B0) ⊕ B1` to the oracle, never the control block itself.



<br>
<br>
