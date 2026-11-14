### Vardanne Civil Continuity Service

> [fill in] · [fill in] · [fill in]
> Points at solve: [fill in]

**Tools used**

python (mini RFC 5545 expander and attestation builder, `work/solve.py`; input `dl/case.ics`, payload `work/attest.json`)

**Approach**

Target: `http://<instance>/`

1. **Brief (`GET /brief`)** — Response window: `2026-06-29T00:00:00Z` <= actual `DTSTART` < `2026-07-14T00:00:00Z`. Membership is on the **actual start only** — no interval-overlap inclusion, no clipping of start/end. Ordering: strictly ascending `start_utc`. Calendar semantics: `DTSTART`, `RRULE`, `RDATE`, `EXDATE` create **nominal identities**; `EXDATE` removes an identity **before** detached replacement; a `RECURRENCE-ID` VEVENT replaces the nominal occurrence and its own `DTSTART` is the **actual** start. Attestation: one JSON object, one `activations` array of exactly **24** records, each with exactly `uid`, `recurrence_id_utc`, `start_utc`, `end_utc`, `category` (`EMERGENCY-RELAY`). Strict JSON: no BOM, no duplicate member names at any depth, no unknown/missing members, no implicit timezones.
2. **Calendar (`GET /case.ics`)** — Three UIDs, all one-hour masters except the detached instances:

| UID | Rule | Notes |
|---|---|---|
| relay-1 | `FREQ=DAILY;COUNT=12;INTERVAL=2` from 06-25 08:00Z, `RDATE 06-30T08:00Z`, `EXDATE 07-05T08:00Z` | detached: `RECURRENCE-ID 06-29T08:00` -> `DTSTART 06-28T07:00` (1.5 h); detached: `RECURRENCE-ID 07-15T08:00` -> `DTSTART 07-13T07:00` (1.5 h) |
| relay-2 | `DTSTART 06-29T10:00Z`, `FREQ=WEEKLY;COUNT=12;BYDAY=MO,WE,FR`, `RDATE 07-04T10:00Z` | 06-29 is a Monday; RDATE 07-04 is a Saturday |
| relay-3 | `DTSTART 06-26T13:00Z`, `FREQ=DAILY;UNTIL=07-14T13:00Z;INTERVAL=2`, `RDATE 06-29T13:00Z` | RDATE 06-29 is off the even-day RRULE; 07-14T13:00 is past the window end |

3. **Traps and resolution**:

   1. **Detached 06-29 -> 06-28T07:00**: the nominal 06-29 identity is replaced, and the *actual* start is before the horizon start, so it is **excluded** despite the nominal occurring inside the window.
   2. **Detached 07-15 -> 07-13T07:00**: the nominal is after the horizon, but the actual start is inside, so it is **included**; `recurrence_id_utc` stays `2026-07-15T08:00:00Z` while `start_utc` is `2026-07-13T07:00:00Z` (and its own `DTEND 08:30` is used, not the master's 1 h duration).
   3. **EXDATE 07-05** removes that identity outright (no detached replacement exists for it).
   4. **RDATEs** are separate nominal identities (06-30 relay-1, 07-04 relay-2, 06-29 relay-3) with `recurrence_id_utc == start_utc`.
   5. **Boundary cases**: occurrences are included by start, not overlap; `07-14T13:00Z` (relay-3) and `07-15T08:00Z` (relay-1 master rule) fall outside; `07-13` occurrences are in.
   6. Strict JSON: serialized compactly, UTF-8 without BOM, and validated with `object_pairs_hook` to reject duplicate member names.

4. Per-UID in-window counts: relay-1 = 8, relay-2 = 8, relay-3 = 8 -> **24** (matching the schema's required count). Sorted strictly ascending by `start_utc`, `POST /attest` with `Content-Type: application/json` returned:

```json
{"routing_authorization":"CSCTF{REDACTED}"}
```

**Why it works**

The challenge pins window membership to the **actual** `DTSTART` of the effective occurrence, not to the nominal series occurrence: `EXDATE` deletes a nominal identity before detached replacement is applied, and a `RECURRENCE-ID` VEVENT supersedes the nominal occurrence with its own `DTSTART`/`DTEND`. So the 06-29 nominal is excluded (its replacement starts 06-28, before the horizon), the 07-15 nominal is included (its replacement starts 07-13), and the 07-05 identity is gone entirely. Combined with start-of-membership (not overlap), the 07-14/07-15 boundary exclusions, the off-RRULE RDATEs as standalone identities, and the strict-JSON/24-record schema, only one attestation validates.

**Validation**

`POST /attest` returned the `routing_authorization` value `CSCTF{REDACTED}` (flag redacted).
