#!/usr/bin/env python3
"""
Silent Breaker — forensics.

A compromised OT-VPN session (stolen employee credentials) issued a single
IEC-60870-5-104 C_SC_NA_1 ON command to the breaker IOA while the historian
displayed a frozen, forged current value marked QUALITY=SUSPECT.

Usage:
    python3 silent_breaker.py [base_url] [submit_path]

    base_url     default: http://<instance>
    submit_path  submission endpoint for the final report. The writeup does
                 not record it; supply via argv[2] or SUBMIT_PATH env var.

The CTF instance is retired; this PoC documents the exploit path. Values such
as IOA, command time and the frozen telemetry figure are the documented
findings from the analysis, reproduced here as constants — the live fetch
steps (events, roster, VPN window) are re-derived against the target.
"""

import json
import os
import sys

import requests

BASE_URL = sys.argv[1] if len(sys.argv) > 1 else "http://<instance>"
SUBMIT_PATH = (
    sys.argv[2] if len(sys.argv) > 2 else os.environ.get("SUBMIT_PATH", "/submit")
    # TODO: supply <submission endpoint> — the writeup shows the report body
    # but not the path that accepts it.
)

PEER = "GT-3908-Z83"           # unrecognized signaling peer from the feed
NORMAL_IOA = 8918              # RTU common address / IOA the capture decodes
SUSPECT_IOA_HEX = "0x22d6"     # breaker-current IOA per the historian log
FROZEN_TELEMETRY = "441.0"     # repeated QUALITY=SUSPECT value (A)
COMMAND_TIME_UTC = "20:50"     # C_SC_NA_1 Act, qualifier ON, per the capture

session = requests.Session()
session.headers["User-Agent"] = "silent-breaker-poc/1.0"


def get_files() -> list:
    r = session.get(f"{BASE_URL}/files/", timeout=15)
    r.raise_for_status()
    return r.json()


def get_events() -> list:
    r = session.get(f"{BASE_URL}/events", timeout=15)
    r.raise_for_status()
    body = r.json()
    return body if isinstance(body, list) else body.get("events", [])


def confirm_target(employee_id: str) -> dict:
    r = session.post(
        f"{BASE_URL}/confirm-target",
        json={"employee_id": employee_id},
        headers={"Content-Type": "application/json"},
        timeout=15,
    )
    r.raise_for_status()
    return r.json()


def get_vpn_window() -> dict:
    r = session.get(f"{BASE_URL}/query/vpn-window", timeout=15)
    r.raise_for_status()
    return r.json()


def correlate_roster(events: list, roster: list) -> dict | None:
    peer_msisdns = {
        e.get("msisdn") or e.get("from") or e.get("sender")
        for e in events if PEER in json.dumps(e)
    } - {None}
    for entry in roster:
        ot_role = "OT" in str(entry.get("role", ""))
        if ot_role and (entry.get("msisdn") in peer_msisdns):
            return entry
    return None


def main() -> int:
    print(f"[*] target: {BASE_URL}")

    print("[*] fetching case index /files/ ...")
    files = get_files()
    print(f"    artifacts: {files}")
    # TODO: download the listed artifacts (roster.json, IEC-104 capture,
    # HMI historian log) and parse them locally for the C_SC_NA_1 frame,
    # Act->ActCon handshake and the QUALITY=SUSPECT run. The writeup's
    # documented findings are used below as constants.

    print("[*] fetching free event feed /events ...")
    events = get_events()
    peer_events = [e for e in events if PEER in json.dumps(e)]
    print(f"    events from {PEER}: {len(peer_events)}")

    roster_path = os.environ.get("ROSTER_JSON")
    if roster_path:
        with open(roster_path) as fh:
            roster = json.load(fh)
        roster = roster if isinstance(roster, list) else roster.get("roster", [])
        match = correlate_roster(peer_events, roster)
        target = match or {}
        employee_id = target.get("employee_id", "<unknown>")
        print(f"[*] OT-enabled roster match: {json.dumps(target)}")
    else:
        # Roster artifact not supplied locally; correlation documented in the
        # writeup identified the OT Field Engineering match.
        print("[*] ROSTER_JSON not set; skipping live roster correlation "
              "(supply the roster artifact from /files/ to enable it)")
        employee_id = os.environ.get("EMPLOYEE_ID", "<employee_id>")

    if employee_id.startswith("<"):
        print("[!] no employee_id available; set ROSTER_JSON or EMPLOYEE_ID")
        return 1

    print(f"[*] confirming target {employee_id} ...")
    print(f"    confirm-target -> {confirm_target(employee_id)}")

    print("[*] fetching OT-VPN window ...")
    window = get_vpn_window()
    print(f"    {window}")
    vpn_session_id = window.get("session_id") or window.get("SessionID") \
        or next(iter(window.values()), "<unknown>")

    report = {
        "ioa_address": SUSPECT_IOA_HEX,
        "command_qualifier": "ON",
        "command_time_utc": COMMAND_TIME_UTC,
        "telemetry_status": FROZEN_TELEMETRY,
        "vpn_session_id": vpn_session_id,
    }
    print(f"[*] report: {json.dumps(report)}")

    if "<" in str(vpn_session_id):
        print("[!] could not determine vpn_session_id; not submitting")
        return 1
    r = session.post(f"{BASE_URL}{SUBMIT_PATH}", json=report, timeout=15)
    print(f"[*] submission -> HTTP {r.status_code}: {r.text}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
