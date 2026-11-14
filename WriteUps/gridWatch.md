### GridWatch

> Network · Hard · Marius Merai
> Points at solve: [fill in]

**Tools used**

Custom Python tooling — `gwscripts/mavlib.py` (MAVLink 2 pack/parse, X.25 CRC, signing, HKDF-SHA256), `gwscripts/fit.py` (RTC linear fit from the tlog), `gwscripts/reposition.py` (final exploit).

**Approach**

The drone signs everything with a per-airframe session key that is never carried on the link, but it supports field re-provisioning via `SETUP_SIGNING`, authenticated with a provisioning key derived from the airframe serial, its commissioning epoch and the per-connection nonce. The commissioning epoch had to be recovered by calibrating the drone RTC (offset + ppm drift) against the packet capture. Once the provision key was derived, `SETUP_SIGNING` installed our own signing key and the normal ArduPilot-style flight sequence (`DO_SET_MODE` GUIDED → ARM → `DO_REPOSITION`) was accepted.

Target: `<instance>` (raw MAVLink 2 over TCP).

Artifacts:

- `gridWatch/capture.tlog` — 25 signed MAVLink 2 frames (8-byte big-endian UNIX-µs per-packet header, then a raw MAVLink 2 frame), same airframe `CX-FALCON-9951`, patrol corridor `LEA-220-VEST`.
- `gridWatch/provisioning_note.md` — the HKDF recipe for the provisioning key and the flight-control order.

Two non-obvious details cost most of the time:

1. The RTC is in 10 µs ticks since a **custom commissioning epoch** (2024-12-12 00:58:43 UTC, UNIX `1733965123`), not the MAVLink 2015 epoch, and it runs **+17.0 ppm** fast.
2. The `SETUP_SIGNING` wire order is `initial_timestamp, target_system, target_component, secret_key` (i.e. the 32-byte key sits at payload offset 10), not the order it is often assumed/written in. Sending the key at offset 8 ("happy path" wire order with `secret_key` before the target fields) is accepted by the provisioning check but installs a garbage key, so every subsequent command fails with `REJECT: bad signature`.

Recon:

1. The tlog parses cleanly as MAVLink 2 once the 8-byte BE timestamp prefix is skipped. All frames are signed (`incompat=0x01`), link id `249`, sysid/compid `1/1` for the drone and `255/190` for the GCS. Observed message ids: `HEARTBEAT(0)`, `SYS_STATUS(1)`, `GLOBAL_POSITION_INT(33)`, `COMMAND_LONG(76)`, `COMMAND_ACK(77)`, `STATUSTEXT(253)`. At connect the live drone emits a heartbeat, a status line and `PROV NONCE <16 hex>`, then stays silent.
2. CRC extras were brute-forced from the capture (one byte each) and matched stock `common.xml` values (`HEARTBEAT=50`, `COMMAND_LONG=152`, `COMMAND_ACK=143`, `STATUSTEXT=83`, `GLOBAL_POSITION_INT=104`, `SETUP_SIGNING=71`), confirming the dialect.

RTC calibration (commissioning epoch):

3. Each signed frame carries a 48-bit little-endian timestamp. Pairing it with the tlog's big-endian UNIX-µs prefix and doing a least-squares fit `t_unix = a + b·ticks` over the 713 s capture gives:

```
b = 9.999830012707 µs/tick   →  100001.7 ticks/s  →  +17.0 ppm
```

The exact relation is `ticks = round((t_unix − E) · 100001.7)`, with the zero crossing

```
E = 1 733 965 123 s  (2024-12-12 00:58:43 UTC)
```

Cross-check from the live link: greeting tick `6004578915160` at local `2026-11-07 00:0x` maps back to the same epoch within ~0.15 s. Re-deriving the provisioning key with this epoch and the raw 8-byte nonce as HKDF salt worked on the first try:

```
prov_key = HKDF-SHA256(ikm = b"CX-FALCON-9951" || epoch_le64,
                       salt = bytes.fromhex(nonce),
                       info = b"CX-PROV/v1", L = 32)
```

Note the salt is the **decoded 8 bytes**, not the 16-char hex string.

Signing details learned by probing:

4. The drone replies to every message with a `STATUSTEXT`, which gives a clear oracle: `REJECT: unsigned message`, `REJECT: bad signature`, `REJECT: provisioning authentication failed`, `REJECT: replayed/old timestamp`, `REJECT: unexpected command N`, state errors, and `lockout: too many rejects, closing` after ~10 rejects per connection.
5. Signature = `SHA256(key32 || frame_without_sig || link_id || ts6)[:6]`, standard MAVLink 2. The drone's own replies use the same construction. The provisioning check ignores the signature timestamp entirely; the normal path enforces `ts > initial_timestamp` (and freshness), so live-RTC-derived ticks must be used. The drone's outgoing timestamps advance by 1 tick per message — a session counter, not wall time — but inbound commands must be stamped with the real RTC formula.
6. Payload that makes the install work (42 bytes):

```
struct.pack('<Q', ts) + b'\x01\x01' + key32
        initial_ts      tgt sys/comp    secret_key   ← key at offset 10
```

Exploit flow (all on one TCP connection — the nonce, and therefore the prov key, is per-connection):

1. Read greeting → `PROV NONCE`.
2. Compute `prov_key`; send `SETUP_SIGNING` in the layout above, signed with `prov_key`, `link_id=249`, `ts=now_rtc`. Reply: `signing re-provisioned: new key active`.
3. `COMMAND_LONG(176)` `MAV_CMD_DO_SET_MODE`, `param1=1` (CUSTOM_MODE_ENABLED), `param2=4` (GUIDED) → `mode GUIDED`, heartbeat `custom_mode=4`. (SET_MODE msgid 11 and `MAV_CMD_SET_MESSAGE_INTERVAL(511)` are rejected by the sim — mode changes must go through command 176.)
4. `COMMAND_LONG(400)` `MAV_CMD_COMPONENT_ARM_DISARM`, `param1=1` → `ACK`, `ARMED`, heartbeat `base_mode=129`.
5. `COMMAND_LONG(192)` `MAV_CMD_DO_REPOSITION` with `param5=45.65, param6=24.15, param7=100` (well outside the captured patrol around 45.5120/24.0130) → `COMMAND_ACK(192, ACCEPTED)` and `STATUSTEXT: CSCTF{REDACTED}`.

**Why it works**

The drone re-provisions its per-airframe signing key over the same channel that relies on that key for authentication, protected only by a provisioning key derivable from non-secret airframe data (serial number and commissioning epoch) plus a per-connection nonce. The commissioning epoch was recoverable by fitting the RTC (offset and +17.0 ppm drift) against the capture, so the provisioning key could be derived offline and `SETUP_SIGNING` could legitimately install an attacker-chosen session key. From there, the normal authorized flight sequence is accepted, and `DO_REPOSITION` retasks the drone outside its patrol corridor.

Remediation:

- Derive session material server-side only; never accept a peer-supplied signing key on the same channel that relies on that key for authentication.
- Bind re-provisioning to the existing key (or a challenge-response over the nonce) and to the exact peer identity, and validate the new key's provenance.
- Keep the key field position/format unambiguous in the protocol spec; silent acceptance of a misplaced key field creates a state where the drone believes signing is active while rejecting every real command.

**Validation**

The drone returned `COMMAND_ACK(192, ACCEPTED)` for `MAV_CMD_DO_REPOSITION` and echoed the flag in a `STATUSTEXT` message; the flag was accepted as the solution.
