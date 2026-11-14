### Split Horizon

> Reverse engineering · Medium · Dan-Andrei Grigorescu
> Points at solve: [fill in]

**Tools used**

Not specified.

**Approach**

1. Retrieved the case files from `GET /files/`. `manifest.json` listed the approved waypoint as `45.9714, 23.5778` with a `0.001` degree server tolerance. The signed audit trail was hash-chain intact and nominal, but did not include raw coordinates.
2. `vireo-ctl.dll` showed the client handshake and stream protocol. The session key is the first 16 bytes of HMAC-SHA256 over `clientNonce || serverNonce`, keyed by the XOR of embedded `MaskA` and `MaskB`. Command payloads are XORed with the repeating session key. Reassembling TCP stream 1 and decrypting the frames exposed sequence 5:

```json
{"mission_id":"AV-C66D4E","seq":5,"params":{"altitude":4500,"speed":200,"waypoint_lat":45.9702,"waypoint_lon":23.5830,"payload_weight":2.5,"wind_compensation":0.0,"WAYPOINT_LAT":45.9720,"WAYPOINT_LON":23.5783}}
```

3. The drone client uses `[JsonPropertyName("waypoint_lat")]` and `[JsonPropertyName("waypoint_lon")]`; its default case-sensitive `System.Text.Json` handling therefore flew the lowercase values: **45.9702, 23.5830**. These values differ from the approved waypoint by roughly 380 m.
4. The Go server uses `encoding/json`, which matches struct field names case-insensitively. For duplicate matching keys, the later uppercase values won, so the server recorded **45.9720, 23.5783**. Those values are close enough to the approved point to pass the server's tolerance check. The hash chain and signature certify the server's conclusion, not the actual drone-side parse result.
5. The report was accepted by `POST /submit` with:

- Executed waypoint: `45.9702, 23.5830`
- Logged waypoint: `45.9720, 23.5783`
- Exploited fields: `waypoint_lat+waypoint_lon`
- Malicious sequence: `5`
- Mechanism: `case_insensitive_last_wins_vs_case_sensitive_exact`

**Why it works**

The bug is a JSON key-matching differential between the Vireo drone client and the Go command server. The drone's .NET `System.Text.Json` parser honors the exact lowercase waypoint keys and ignores the uppercase duplicates (case-sensitive); the Go `encoding/json` server matches keys case-insensitively and, for duplicates, takes the later uppercase values (last-wins). This lets the signed server audit record different coordinates from the coordinates flown by the drone — and the hash chain/signature cannot detect the discrepancy because they certify the server-side parse, not the drone-side one.

Remediation: reject duplicate JSON keys before parsing, require canonical field names and casing, and validate the exact byte-level command representation that the aircraft consumes. Bind audit records to the client-parsed command or include a device-authenticated acknowledgment of the executed coordinates, rather than treating server-side validation as proof of aircraft behavior.

**Validation**

The report was accepted by `POST /submit`; the flag `CSCTF{REDACTED}` was returned (flag redacted).
