### DarkAnchorageReconciliation — KALNET-1

> Network · Medium · Chronos Security
> Points at solve: [fill in]

**Tools used**

Python, scipy (`scipy.optimize.linear_sum_assignment`).

**Approach**

Target: http://<instance>/

Task: given AIS-like NDJSON (16 vessels, 91 samples each), coastal radar CSV (16 anonymous tracks, 91 samples each), a cable-fault point, and a method note, produce the KALNET-RECON-1 report: the full radar↔AIS bijection, the false AIS broadcast's displacement vector and run, and the actual closest approach of the real vessel to the cable, computed in a local tangent plane.

1. **Local plane** (schema): origin = cable-fault point `(lat0=50.05140349, lon0=19.84867233)`, `R=6378137`:

```
east  = R*cos(radians(lat0))*(radians(lon)-radians(lon0))
north = R*(radians(lat)-radians(lat0))
```

2. **Clock normalization.** The radar header says `radar_utc_offset_minutes=60` and the method note says local_time = UTC + offset, so subtract 60 min. After that both feeds cover `2026-11-06T11:00Z .. 14:00Z` on the same 120 s cadence, and all 91 sample stamps pair exactly.

3. **Association.** For every radar track × MMSI, score = median Euclidean residual over the 91 paired samples; solve the assignment with Hungarian (`scipy.optimize.linear_sum_assignment`). Result: every true pair has median residual **0.000 m**, while each row's second-best candidate is ~269–310 m — exactly the note's "accepted bijection ≤35 m, wrong pairs ≥180 m". The 16 pairs are listed in `accepted_report.json`.

4. **False broadcast.** Only `R-02 ↔ MMSI 970971662` has samples ≥250 m apart. The residual `AIS − radar` is constant **+390 m east / +330 m north** (|r| ≈ 510.9 m) for a contiguous 5-sample run, with component step changes well under 15 m:

```
12:26:00Z  +390.0004 / +330.0000
12:28:00Z  +390.0000 / +330.0000
12:30:00Z  +390.0004 / +330.0000
12:32:00Z  +389.9997 / +330.0000
12:34:00Z  +390.0000 / +330.0000
```

Mean components round (half away from zero) to `east=390`, `north=330`; run spans `12:26:00Z .. 12:34:00Z`. So AIS (KAL-TRANSIT-662) was displaced ~511 m NE of radar truth exactly across the cable-fault window — the false broadcast that made AIS look clear of the corridor.

5. **Actual closest approach (radar only).** Consecutive radar fixes of R-02, segment CPA to local origin with `u=clamp(-dot(p,q-p)/dot(q-p,q-p),0,1)`. The track runs east along the cable latitude and crosses the origin between the `12:30:00Z` and `12:32:00Z` fixes at `u≈0.8182`:

- UTC: `2026-11-06T12:31:38Z`
- distance: **0.0 m** (rounded to 0.1 m) — the real contact passed directly over the KALNET-1 fault point.

Report format gotcha: `/schema` documents divergence keys as a compressed phrase (`ais_minus_radar_east_m_north_m`, `start_utc_end_utc`). The validator actually wants them **split**:

```json
"divergence": {
  "mmsi": "970971662",
  "ais_minus_radar_east_m": 390,
  "ais_minus_radar_north_m": 330,
  "start_utc": "2026-11-06T12:26:00Z",
  "end_utc": "2026-11-06T12:34:00Z"
}
```

Associations are `[{"radar_track":"R-01","mmsi":"..."}]` in ascending track order; closest_approach is `{mmsi, utc, distance_m}`; offset is `60`. Structural failures return `400 invalid report`; semantic failures return `422 report not accepted`.

**Why it works**

Once the radar's +60 minute local offset is removed, both feeds describe the same physical contacts on the same 120 s cadence, so paired samples coincide in time. Median-residual scoring is robust against the single 5-sample corrupted run (only `R-02 ↔ 970971662` exceeds 250 m), which lets the Hungarian assignment recover the true bijection cleanly — every true pair at 0.000 m with second-best candidates ≥269 m away. The constant `+390/+330` residual over a contiguous 5-sample window, with component step changes under 15 m, is the signature of a synthetic offset injected into the AIS feed: it displaced KAL-TRANSIT-662 about 511 m NE of its true position precisely during the cable-fault window, making AIS appear to miss the corridor. Segment CPA computed on the radar track — which the spoof cannot touch — shows the real contact crossed the fault point itself (distance 0.0 m).

**Validation**

The bijection is self-validating: all 16 true pairs score 0.000 m median residual against a 269–310 m runner-up margin, comfortably inside the note's acceptance bounds. The report was submitted in the split-divergence-key format (after discovering the schema/validator mismatch); structural failures return `400 invalid report` and semantic failures `422 report not accepted`. The 16 accepted pairs are recorded in `accepted_report.json`.
