#!/usr/bin/env python3
"""Ghost Signal — cross-plane IMSI correlation PoC (SS7 + Diameter + billing).

Extracts the hidden subscriber IMSI from each of the three record sources,
confirms they agree, and derives the flag material as the first 8 lowercase
hex characters of SHA-256 over the three identical identities joined by ':'.

Usage: python3 ghost_signal.py <ss7.pcap> <diameter.pcap> <billing_events.json>

Note: the CTF instance is retired; this PoC documents the exploit path.
Requires tshark on PATH for the pcap decodes.
"""
import hashlib
import json
import re
import subprocess
import sys

IMSI_RE = re.compile(r"IMSI: (\d+)")


def imsi_from_ss7(pcap):
    # The IMSI is not exposed via -e gsm_map.imsi in this build; read it from the verbose decode.
    out = subprocess.check_output(["tshark", "-r", pcap, "-V"], text=True, errors="replace")
    return sorted(set(IMSI_RE.findall(out)))


def imsi_from_diameter(pcap):
    out = subprocess.check_output(
        ["tshark", "-r", pcap, "-T", "fields",
         "-e", "diameter.Session-Id", "-e", "diameter.Subscription-Id-Data"],
        text=True, errors="replace")
    return sorted({tok for tok in re.findall(r"\d{14,16}", out)})


def attack_events(events):
    # Malicious records: atk_* / pivot_* ids, or the documented abuse flags.
    picked = []
    for e in events:
        eid = str(e.get("id", ""))
        flags = {k for k, v in e.items() if v is True}
        if eid.startswith(("atk_", "pivot_")) or flags & {"zero_charge_on_roaming", "unusual_routing_path"}:
            picked.append(e)
    return picked


def imsi_from_billing(path):
    with open(path) as fh:
        events = json.load(fh)
    if isinstance(events, dict):
        events = events.get("events") or events.get("billing_events") or list(events.values())
    imsis = {str(e.get("imsi") or e.get("IMSI") or e.get("subscription_id", ""))
             for e in attack_events(events)}
    imsis.discard("")
    return sorted(imsis)


def main():
    if len(sys.argv) != 4:
        sys.exit("Usage: python3 ghost_signal.py <ss7.pcap> <diameter.pcap> <billing_events.json>")
    ss7_imsis = imsi_from_ss7(sys.argv[1])
    diam_imsis = imsi_from_diameter(sys.argv[2])
    bill_imsis = imsi_from_billing(sys.argv[3])
    print("ss7:     ", ss7_imsis)
    print("diameter:", diam_imsis)
    print("billing: ", bill_imsis)

    common = set(ss7_imsis) & set(diam_imsis) & set(bill_imsis)
    if len(common) != 1:
        sys.exit(f"No unique common IMSI across the three sources: {common or 'none'}")
    imsi = common.pop()
    print("common IMSI:", imsi)

    digest = hashlib.sha256(f"{imsi}:{imsi}:{imsi}".encode()).hexdigest()
    print("sha256:", digest)
    print("flag body (first 8 lowercase hex):", digest[:8])


if __name__ == "__main__":
    main()
