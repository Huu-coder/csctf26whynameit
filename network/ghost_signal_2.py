#!/usr/bin/env python3
"""Ghost Signal (alternate derivation) — flag from IMSI + Diameter Session-Id + timestamp.

Serializes the correlated identity as `<IMSI>:<Session-Id>:<initial-timestamp>`,
hashes it with SHA-256, and takes the first 8 lowercase hex characters.

Usage: python3 ghost_signal_2.py <billing_events.json> [ss7.pcap] [diameter.pcap]

Note: the CTF instance is retired; this PoC documents the exploit path.
Optional pcap arguments are used only to cross-check the IMSI via tshark.
"""
import hashlib
import json
import re
import subprocess
import sys

IMSI_RE = re.compile(r"IMSI: (\d+)")


def attack_events(events):
    picked = []
    for e in events:
        eid = str(e.get("id", ""))
        flags = {k for k, v in e.items() if v is True}
        if eid.startswith(("atk_", "pivot_")) or flags & {"zero_charge_on_roaming", "unusual_routing_path"}:
            picked.append(e)
    return picked


def billing_facts(path):
    with open(path) as fh:
        events = json.load(fh)
    if isinstance(events, dict):
        events = events.get("events") or events.get("billing_events") or list(events.values())
    atk = attack_events(events)
    if not atk:
        sys.exit("No attack billing events (atk_* / pivot_*) found.")
    imsis = {str(e.get("imsi", "")) for e in atk}
    sessions = {str(e.get("session") or e.get("session_id") or e.get("Session-Id") or "") for e in atk}
    sessions.discard("")
    if len(imsis) != 1 or len(sessions) != 1:
        sys.exit(f"Ambiguous billing correlation: imsis={imsis} sessions={sessions}")
    ts_values = []
    for e in atk:
        for key in ("timestamp", "time", "unix"):
            if e.get(key) is not None:
                ts_values.append(int(e[key]))
                break
    return imsis.pop(), sessions.pop(), (min(ts_values) if ts_values else None)


def imsi_from_pcap(pcap, args):
    out = subprocess.check_output(["tshark", "-r", pcap] + args, text=True, errors="replace")
    return sorted(set(re.findall(r"\d{14,16}", out)))


def main():
    if len(sys.argv) < 2:
        sys.exit("Usage: python3 ghost_signal_2.py <billing_events.json> [ss7.pcap] [diameter.pcap]")
    imsi, session, ts = billing_facts(sys.argv[1])
    print("billing IMSI:   ", imsi)
    print("billing session:", session)
    print("initial ts:     ", ts)

    for pcap, args in ((sys.argv[2] if len(sys.argv) > 2 else None, ["-V"]),
                       (sys.argv[3] if len(sys.argv) > 3 else None,
                        ["-T", "fields", "-e", "diameter.Subscription-Id-Data"])):
        if pcap:
            found = imsi_from_pcap(pcap, args)
            print(f"cross-check {pcap}:", found, "OK" if imsi in found else "MISMATCH")

    # The session id itself embeds the initial timestamp; prefer it when present.
    parts = session.split(";")
    if len(parts) >= 3 and parts[1].isdigit():
        ts = int(parts[1])
    if ts is None:
        sys.exit("Could not determine the initial timestamp from billing events or the session id.")

    serialized = f"{imsi}:{session}:{ts}"
    digest = hashlib.sha256(serialized.encode()).hexdigest()
    print("serialized:", serialized)
    print("sha256:", digest)
    print("flag body (first 8 lowercase hex):", digest[:8])


if __name__ == "__main__":
    main()
