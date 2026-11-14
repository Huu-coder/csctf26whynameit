#!/usr/bin/env python3
"""Vardanne Civil Continuity Service - proof of concept.

Summary: attestation membership is pinned to the ACTUAL DTSTART of the
effective occurrence (RECURRENCE-ID VEVENTs supersede nominal RRULE
occurrences; EXDATE deletes a nominal identity outright), within a fixed
window, 24 records, strictly ascending, strict JSON.

Usage: vardanne.py [BASE_URL] [CASE_ICS] [--print]

CASE_ICS defaults to ./case.ics. --print emits the attestation JSON to
stdout instead of POSTing it to BASE_URL/attest. The CTF instance is
retired; this PoC documents the exploit path.
"""

import json
import re
import sys
from datetime import datetime, timedelta, timezone

import requests

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://<instance>"
ICS_PATH = sys.argv[2] if len(sys.argv) > 2 else "case.ics"
PRINT_ONLY = "--print" in sys.argv

WINDOW_START = datetime(2026, 6, 29, tzinfo=timezone.utc)
WINDOW_END = datetime(2026, 7, 14, tzinfo=timezone.utc)
REQUIRED_COUNT = 24
DEFAULT_DURATION = timedelta(hours=1)  # one-hour masters

WEEKDAYS = {"MO": 0, "TU": 1, "WE": 2, "TH": 3, "FR": 4, "SA": 5, "SU": 6}


def parse_ics(path):
    text = open(path, encoding="utf-8-sig").read()
    # Unfold continuation lines (start with a space or tab).
    text = re.sub(r"\r?\n[ \t]", "", text)
    events, cur = [], None
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        if line == "BEGIN:VEVENT":
            cur = {}
            continue
        if line == "END:VEVENT":
            events.append(cur)
            cur = None
            continue
        if cur is None or ":" not in line:
            continue
        content, value = line.split(":", 1)
        name, _, params = content.partition(";")
        cur.setdefault(name.upper(), []).append((params.upper(), value.strip()))
    return events


def prop(event, name):
    values = event.get(name.upper(), [])
    return values[0][1] if values else None


def prop_all(event, name):
    return [v for _, v in event.get(name.upper(), [])]


def parse_dt(value):
    value = value.strip()
    if value.endswith("Z"):
        value = value[:-1]
    # Floating times are treated as UTC; the brief forbids implicit timezones.
    return datetime.strptime(value, "%Y%m%dT%H%M%S").replace(tzinfo=timezone.utc)


def parse_rrule(value):
    rule = {}
    for part in value.split(";"):
        key, _, val = part.partition("=")
        rule[key.upper()] = val.upper()
    return rule


def fmt_z(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def expand_rrule(dtstart, rule):
    freq = rule.get("FREQ")
    interval = int(rule.get("INTERVAL", "1"))
    count = int(rule["COUNT"]) if "COUNT" in rule else None
    until = parse_dt(rule["UNTIL"]) if "UNTIL" in rule else None
    out = []

    def keep(moment):
        if count is not None and len(out) >= count:
            return False
        if until is not None and moment > until:
            return False
        return True

    if freq == "DAILY":
        day = 0
        while True:
            moment = dtstart + timedelta(days=day)
            day += 1
            if moment < dtstart:
                continue
            if until is not None and moment > until:
                break
            if (moment - dtstart).days % interval == 0:
                if not keep(moment):
                    break
                out.append(moment)
                if count is not None and len(out) >= count:
                    break
    elif freq == "WEEKLY":
        byday = [WEEKDAYS[d] for d in rule.get("BYDAY", "").split(",") if d]
        week_zero = dtstart.date() - timedelta(days=dtstart.weekday())  # Monday-start week
        day = 0
        while True:
            date = dtstart.date() + timedelta(days=day)
            day += 1
            week_index = (date - week_zero).days // 7
            if week_index % interval != 0 or date.weekday() not in byday:
                if count is None and until is not None and \
                        datetime(date.year, date.month, date.day, tzinfo=timezone.utc) > until:
                    break
                continue
            moment = datetime(date.year, date.month, date.day,
                              dtstart.hour, dtstart.minute, dtstart.second,
                              tzinfo=timezone.utc)
            if moment < dtstart:
                continue
            if not keep(moment):
                break
            out.append(moment)
            if count is None and until is not None and moment >= until:
                break
            if count is not None and len(out) >= count:
                break
    else:
        raise ValueError(f"unsupported FREQ: {freq}")
    return out


def build_activations(events):
    # Nominal identities per master event, keyed by (uid, start).
    nominals = {}
    detached = []
    for ev in events:
        uid = prop(ev, "UID")
        dtstart = parse_dt(prop(ev, "DTSTART"))
        dtend_raw = prop(ev, "DTEND")
        dtend = parse_dt(dtend_raw) if dtend_raw else dtstart + DEFAULT_DURATION
        category = (prop(ev, "CATEGORIES") or "EMERGENCY-RELAY").split(",")[0].strip()
        base = {"uid": uid, "start": dtstart, "end": dtend,
                "recurrence_id": dtstart, "category": category}

        rec_id = prop(ev, "RECURRENCE-ID")
        if rec_id:  # detached instance: supersedes the nominal occurrence
            base["recurrence_id"] = parse_dt(rec_id)
            detached.append(base)
            continue

        rrule = prop(ev, "RRULE")
        if rrule:
            for moment in expand_rrule(dtstart, parse_rrule(rrule)):
                duration = dtend - dtstart
                nominals[(uid, moment)] = {**base, "start": moment,
                                           "end": moment + duration,
                                           "recurrence_id": moment}
        else:
            nominals[(uid, dtstart)] = base
        for extra in prop_all(ev, "RDATE"):          # standalone nominal identities
            for value in extra.split(","):
                moment = parse_dt(value)
                duration = dtend - dtstart
                nominals[(uid, moment)] = {**base, "start": moment,
                                           "end": moment + duration,
                                           "recurrence_id": moment}

    # EXDATE removes a nominal identity outright, before detached replacement.
    for ev in events:
        uid = prop(ev, "UID")
        for raw in prop_all(ev, "EXDATE"):
            for value in raw.split(","):
                nominals.pop((uid, parse_dt(value)), None)

    # Detached replacement: drop the nominal, keep the detached one.
    for det in detached:
        nominals.pop((det["uid"], det["recurrence_id"]), None)
        nominals[(det["uid"], det["start"])] = det

    # Membership is on the ACTUAL start only; ordering strictly ascending.
    windowed = [r for r in nominals.values()
                if WINDOW_START <= r["start"] < WINDOW_END]
    windowed.sort(key=lambda r: r["start"])
    for prev, cur in zip(windowed, windowed[1:]):
        if cur["start"] <= prev["start"]:
            raise ValueError("starts are not strictly ascending")

    return [{"uid": r["uid"],
             "recurrence_id_utc": fmt_z(r["recurrence_id"]),
             "start_utc": fmt_z(r["start"]),
             "end_utc": fmt_z(r["end"]),
             "category": r["category"]}
            for r in windowed]


def main():
    events = parse_ics(ICS_PATH)
    activations = build_activations(events)
    print(f"[+] {len(activations)} activation(s) in window", file=sys.stderr)
    if len(activations) != REQUIRED_COUNT:
        print(f"[!] expected {REQUIRED_COUNT} records; refusing to attest", file=sys.stderr)
        raise SystemExit(1)

    # Strict JSON: compact separators, UTF-8 without BOM, no duplicates.
    payload = json.dumps({"activations": activations},
                         separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    if PRINT_ONLY:
        sys.stdout.buffer.write(payload + b"\n")
        return

    resp = requests.post(f"{BASE}/attest", data=payload,
                         headers={"Content-Type": "application/json"}, timeout=10)
    resp.raise_for_status()
    print(resp.text)


if __name__ == "__main__":
    main()
