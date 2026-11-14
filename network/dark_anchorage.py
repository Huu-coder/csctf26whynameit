#!/usr/bin/env python3
"""Dark Anchorage (KALNET-1) — AIS/radar reconciliation and report submission PoC.

Computes the radar<->AIS bijection, the false AIS broadcast displacement and
run, and the real vessel's closest approach to the cable-fault point in a
local tangent plane, then submits the KALNET-RECON-1 report.

Usage: python3 dark_anchorage.py [base_url] <ais.ndjson> <radar.csv> [submit_path]

Note: the CTF instance is retired; this PoC documents the exploit path.
"""
import csv
import json
import math
import sys
from datetime import datetime, timedelta

import requests
from scipy.optimize import linear_sum_assignment

R = 6378137
LAT0, LON0 = 50.05140349, 19.84867233      # cable-fault point
RADAR_OFFSET_MIN = 60                     # radar local_time = UTC + 60 min
TS_FMT = "%Y-%m-%dT%H:%MZ"


def to_local(lat, lon):
    east = R * math.cos(math.radians(LAT0)) * math.radians(lon - LON0)
    north = R * math.radians(lat - LAT0)
    return east, north


def parse_ts(s):
    return datetime.strptime(s.strip(), TS_FMT)


def load_ais(path):
    # Expected NDJSON fields: mmsi, time, lat, lon (TODO: adjust to artifact schema if different).
    vessels = {}
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            mmsi = str(rec.get("mmsi") or rec.get("MMSI"))
            ts = parse_ts(rec.get("time") or rec.get("timestamp") or rec.get("ts"))
            vessels.setdefault(mmsi, {})[ts] = to_local(float(rec["lat"]), float(rec["lon"]))
    return vessels


def load_radar(path):
    # Expected CSV columns: track, time, lat, lon (TODO: adjust to artifact schema if different).
    tracks = {}
    with open(path, newline="") as fh:
        for row in csv.DictReader(fh):
            track = row.get("track") or row.get("track_id") or row.get("id")
            ts = parse_ts(row.get("time") or row.get("timestamp") or row.get("ts")) - timedelta(minutes=RADAR_OFFSET_MIN)
            tracks.setdefault(track, {})[ts] = to_local(float(row["lat"]), float(row["lon"]))
    return tracks


def median(values):
    s = sorted(values)
    n = len(s)
    mid = n // 2
    return s[mid] if n % 2 else (s[mid - 1] + s[mid]) / 2


def associate(ais, radar):
    mmsis, track_ids = sorted(ais), sorted(radar)
    cost = []
    for track in track_ids:
        row = []
        for mmsi in mmsis:
            common = sorted(set(ais[mmsi]) & set(radar[track]))
            residuals = [math.dist(ais[mmsi][t], radar[track][t]) for t in common]  # euclidean, 2D
            row.append(median(residuals) if residuals else 1e12)
        cost.append(row)
    ri, ci = linear_sum_assignment(cost)
    return {track_ids[i]: mmsis[j] for i, j in zip(ri, ci)}


def find_false_broadcast(ais, radar, pairs):
    for track, mmsi in sorted(pairs.items()):
        common = sorted(set(ais[mmsi]) & set(radar[track]))
        res = [(t, ais[mmsi][t][0] - radar[track][t][0], ais[mmsi][t][1] - radar[track][t][1])
               for t in common]
        run, best = [], []
        for t, de, dn in res:
            if math.hypot(de, dn) >= 250.0:
                run.append((t, de, dn))
            else:
                if len(run) > len(best):
                    best = run
                run = []
        if len(run) > len(best):
            best = run
        if best:
            east = sum(r[1] for r in best) / len(best)
            north = sum(r[2] for r in best) / len(best)
            # Round half away from zero, as the report validator expects.
            east = int(math.copysign(math.floor(abs(east) + 0.5), east))
            north = int(math.copysign(math.floor(abs(north) + 0.5), north))
            return {
                "mmsi": mmsi,
                "ais_minus_radar_east_m": east,
                "ais_minus_radar_north_m": north,
                "start_utc": best[0][0].strftime("%Y-%m-%dT%H:%M:%SZ"),
                "end_utc": best[-1][0].strftime("%Y-%m-%dT%H:%M:%SZ"),
            }, track
    return None, None


def closest_approach(radar, track, mmsi):
    pts = sorted(radar[track].items())
    best = (float("inf"), None)
    for (t0, p), (t1, q) in zip(pts, pts[1:]):
        dx, dy = q[0] - p[0], q[1] - p[1]
        denom = dx * dx + dy * dy
        u = max(0.0, min(1.0, -(p[0] * dx + p[1] * dy) / denom)) if denom else 0.0
        cx, cy = p[0] + u * dx, p[1] + u * dy
        dist = math.hypot(cx, cy)
        if dist < best[0]:
            utc = t0 + (t1 - t0) * u
            best = (dist, utc)
    dist, utc = best
    return {"mmsi": mmsi,
            "utc": utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "distance_m": round(dist, 1)}


def main():
    base = sys.argv[1] if len(sys.argv) > 1 else "http://<instance>"
    if len(sys.argv) < 4:
        sys.exit("Usage: python3 dark_anchorage.py [base_url] <ais.ndjson> <radar.csv> [submit_path]")
    submit_path = sys.argv[4] if len(sys.argv) > 4 else "/submit"  # TODO: writeup does not record the exact submission endpoint

    ais, radar = load_ais(sys.argv[2]), load_radar(sys.argv[3])
    pairs = associate(ais, radar)
    divergence, flagged_track = find_false_broadcast(ais, radar, pairs)
    if divergence is None:
        sys.exit("No false broadcast run (>=250 m residual) found.")
    report = {
        "associations": [{"radar_track": t, "mmsi": pairs[t]} for t in sorted(pairs)],
        "divergence": divergence,
        "closest_approach": closest_approach(radar, flagged_track, pairs[flagged_track]),
        "offset": RADAR_OFFSET_MIN,
    }
    print(json.dumps(report, indent=2))

    requests.get(base + "/schema", timeout=15)  # recon: documents the report contract
    resp = requests.post(base + submit_path, json=report, timeout=15)
    print(resp.status_code, resp.text)  # 400 invalid report / 422 report not accepted on failure


if __name__ == "__main__":
    main()
