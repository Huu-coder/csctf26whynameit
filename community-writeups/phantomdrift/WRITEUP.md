# 🚩 FORENSICS 🚩

## <span style="color:#1E88E5">&#9679;</span> Phantom Drift

> Points: **?** · Solves: **?**

> **Flag:** `CSCTF{REDACTED}`<br>

---

### Overview

#### Challenge Brief
Reconnaissance drone Valkyrie-9 drifted off its approved waypoint while the command server recorded the mission as nominal. Reconcile the recovered client and backend logic with the flight record, telemetry, and radio intercept to show how the diversion avoided the alarm.

This is a constructed offline forensic case.

**Flag format:** **`CSCTF{REDACTED}`**

`sha256(f"{approved_lat:.4f}{approved_lon:.4f}{delta_lat:.6f}{delta_lon:.6f}{displacement_m:.1f}")[:16]`. The `TAG:` in `flight_log.bin` is the last 8 hex characters of the same digest.

---

### Resources

#### Files
- `files/drone_control.decompiled`
- `files/command_backend.decompiled`
- `files/flight_log.bin`
- `files/mission_manifest.json`
- `files/radio_intercept.log`
- `files/telemetry_logs.json`

#### Hints
No hints provided.

---

### Solution Walkthrough

1. Decode the decompiled sources
2. Find the duplicate-key telemetry record
3. Get the approved and diverted coordinates
4. Compute the distance and recover the tag
5. Build the flag

<br>

### 1. Decode the decompiled sources

Both `.decompiled` files contain a single base64 string named `DECODED_CONTENT`:

```bash
grep -oP 'DECODED_CONTENT = "\K[^"]+' drone_control.decompiled   | base64 -d > drone_control.cs
grep -oP 'DECODED_CONTENT = "\K[^"]+' command_backend.decompiled | base64 -d > command_backend.go
```

- `drone_control.cs`: a Unity/C# client that uses Newtonsoft.Json. `FlightParams` binds the snake_case keys `waypoint_lat` / `waypoint_lon`. Unknown properties are logged and then marked `Handled = true`, so they are dropped silently.
- `command_backend.go`: a Go backend whose `FlightParams` struct has the same `json:"waypoint_lat"` tags. The source comment says outright: *"this is where the parser differential manifests"*.

Both sides check the waypoint the same way: `|delta| < 0.001` on each axis (about 111 m).

<br>

### 2. Find the duplicate-key telemetry record

Every reading in `telemetry_logs.json` has the same 7 keys except two:

```json
{"phase": "waypoint_update", "timestamp": 1723741800,
 "waypoint_lat": 47.2591, "waypoint_lon": 19.0402, ...,
 "WaypointLat": 47.26,    "WaypointLon": 19.045,  ...}

{"phase": "server_validation", "validation_result": "PASS",
 "note": "Server-side validation passed — Go parsed WaypointLat=47.2600 ...",
 "discrepancy_detected": false}
```

The command record holds each field twice. The snake_case copy contains the **approved** waypoint. The PascalCase copy contains the **diverted** one. The two parsers read different copies of the same message: one sees the approved point, the other sees the diverted point. As a result the drone flew to the diverted coordinates, while the server logged `PASS` and `MISSION_SUCCESS`.

> Note: the challenge's story does not match real library behaviour. Go's `encoding/json` matches key names case-insensitively, but it does not ignore underscores, so `WaypointLat` would not bind to the tag `waypoint_lat`. Also, `PropertyNameCaseInsensitive` is a System.Text.Json setting, not a Newtonsoft one. Treat the differential as the intended mechanism; the numbers below do not depend on it.

<br>

### 3. Get the approved and diverted coordinates

| | Lat | Lon | Source |
|---|---|---|---|
| Approved | `47.2591` | `19.0402` | `mission_manifest.json`, hardcoded in both sources |
| Diverted | `47.2600` | `19.0450` | PascalCase keys, and the radio intercept at 12:31:15–12:31:30 |
| Delta | `0.000900` | `0.004800` | diverted − approved |

The 0.0048° longitude delta is almost 5× the 0.001 tolerance, and it points **east**. This matches GROUND_STATION_3's report of *"380m EAST of planned waypoint"*.

<br>

### 4. Compute the distance and recover the tag

`flight_log.bin` is 36 bytes. It starts with a `FLGT` header, and the last 12 bytes (from offset `0x18`) are XOR-ed with the mission ID `Valkyrie-9`:

```
02 20 2b 51 1d 11 5f 5d 1e 0f 37 53  ^ "Valkyrie-9"  ->  TAG:dc6836a2
```

The tag shows which Earth radius was used for the haversine distance:

| Radius | Distance | Last 8 hex | Match |
|---|---|---|---|
| 6371000 m (mean) | 375.8 | `2126c52e` | ❌ |
| 6378137 m (WGS-84 equatorial) | 376.2 | `dc6836a2` | ✅ |

<br>

### 5. Build the flag

```python
import hashlib, json, math

m = json.load(open("mission_manifest.json"))
lat0, lon0 = m["approved_waypoint_lat"], m["approved_waypoint_lon"]

rec = next(r for r in json.load(open("telemetry_logs.json"))["readings"]
           if r["phase"] == "waypoint_update")
lat1, lon1 = rec["WaypointLat"], rec["WaypointLon"]

R = 6378137.0
p0, p1 = math.radians(lat0), math.radians(lat1)
a = math.sin((p1 - p0) / 2) ** 2 + math.cos(p0) * math.cos(p1) * math.sin(math.radians(lon1 - lon0) / 2) ** 2
dist = 2 * R * math.asin(math.sqrt(a))

s = f"{lat0:.4f}{lon0:.4f}{lat1 - lat0:.6f}{lon1 - lon0:.6f}{dist:.1f}"
h = hashlib.sha256(s.encode()).hexdigest()

blob = open("flight_log.bin", "rb").read()[0x18:]
tag = bytes(c ^ b"Valkyrie-9"[i % 10] for i, c in enumerate(blob)).decode()
assert tag == f"TAG:{h[-8:]}"

print(f"CSCTF{{{h[:16]}}}")
```

```unknown
47.259119.04020.0009000.004800376.2
TAG:dc6836a2
CSCTF{REDACTED}
```

Flag: `CSCTF{REDACTED}`

<br>
<br>
