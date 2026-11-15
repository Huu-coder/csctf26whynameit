import hashlib, json, math, re

# 1. Approved waypoint from the manifest
m = json.load(open("mission_manifest.json"))
lat0, lon0 = m["approved_waypoint_lat"], m["approved_waypoint_lon"]

# 2. Diverted waypoint = PascalCase duplicate keys in the waypoint_update record
rec = next(r for r in json.load(open("telemetry_logs.json"))["readings"]
           if r["phase"] == "waypoint_update")
lat1, lon1 = rec["WaypointLat"], rec["WaypointLon"]

# 3. Great-circle distance (haversine, WGS-84 equatorial radius)
R = 6378137.0
p0, p1 = math.radians(lat0), math.radians(lat1)
a = math.sin((p1 - p0) / 2) ** 2 + math.cos(p0) * math.cos(p1) * math.sin(math.radians(lon1 - lon0) / 2) ** 2
dist = 2 * R * math.asin(math.sqrt(a))

s = f"{lat0:.4f}{lon0:.4f}{lat1 - lat0:.6f}{lon1 - lon0:.6f}{dist:.1f}"
h = hashlib.sha256(s.encode()).hexdigest()

# 4. Verify against the XOR-ed tag in flight_log.bin
blob = open("flight_log.bin", "rb").read()[0x18:]
key = b"Valkyrie-9"
tag = bytes(c ^ key[i % len(key)] for i, c in enumerate(blob)).decode()
assert tag == f"TAG:{h[-8:]}", (tag, h)

print(s)
print(tag)
print(f"CSCTF{{{h[:16]}}}")
