#!/usr/bin/env python3
"""
BlackOut (CSCTF 2026, ICS - Hard)

Rebuilds the canonical flag serialization for the malicious Modbus FC16 write
against substation 0x4A2E and hashes it as specified: firmware header, station
id, exact event-log timestamp (NOT the pcap clock, which runs ten minutes
ahead), register start and calibration seed; flag = first 8 lowercase hex of
SHA-256.

Usage: python3 blackout.py [header station timestamp register_start seed]
All fields default to the values documented in the evidence handout.

The CTF instance is retired; this PoC documents the exploit path.
"""
import hashlib
import sys

# Values corroborated across the HMI config, scada_network.pcap (packet 31),
# scada_event.log, alarm_override.dat and the first four bytes of plc_firmware.bin.
FIRMWARE_HEADER = "0x504C4331"        # 'PLC1' big-endian, from plc_firmware.bin
STATION_ID = "0x4A2E"                 # substation, alarm_override.dat + event log
TIMESTAMP = "2025-11-15T06:15:03Z"    # event-log time; capture clock conflicts by 10 minutes
REGISTER_START = "40001"              # FC16 start register, 64 registers, 0x55FA payload
CALIBRATION_SEED = "137"              # HMI config and startup log


def build_serialization(header, station, timestamp, register, seed) -> str:
    # Exact serialization required by the flag specification.
    return f"{header}:{station}:{timestamp}:{register}:{seed}"


def main() -> None:
    fields = sys.argv[1:] or [FIRMWARE_HEADER, STATION_ID, TIMESTAMP, REGISTER_START, CALIBRATION_SEED]
    if len(fields) != 5:
        raise SystemExit(__doc__)
    serialization = build_serialization(*fields)
    digest = hashlib.sha256(serialization.encode("ascii")).hexdigest()
    print(f"[*] serialization: {serialization}")
    print(f"[*] sha256:        {digest}")
    print(f"[*] first 8 hex:   {digest[:8]}")


if __name__ == "__main__":
    main()
