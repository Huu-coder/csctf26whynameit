### ANWA National Alert Origination Gateway

> [fill in] · [fill in] · [fill in]
> Points at solve: [fill in]

**Tools used**

sha256-hex tooling for the unlock digest; manual JSON duplicate-member probing of `/api/v1/orders`.

**Approach**

A fabricated CAP **Alert** (`ANWA-CAP-992ed112-ef82`, *"IMMEDIATE EVACUATION - PROCEED INLAND VIA ROUTE N2"*, areas `AS-HAL`, `AS-QUI`, severity Extreme) was on air. We held an `observer` credential (`s.harrow` / passphrase issued on `/`). The broadcast centre honours **cancellations**, but the API only permits `dispatch` (which includes a Cancel message) for the `dispatcher` role, and all dispatcher roles were revoked at 03:11Z.

1. Recon: the console registry (`/reference/authorities`) showed `AS-HAL`/`AS-QUI` belong to authority **NAA-05**, while our credential's authority is **NAA-01** — the grant scope is derived from the credential (`/api/v1/grant` returns an NAA-01, Minor-severity grant), so we cannot mint our own grant for the target areas. The archive (`/feed/cap/archive`) embeds the *dispatch authorization grant* of every past message as an XML comment. The live message `ANWA-CAP-8b676281-ef46` (Cyclone Meren track update 6) carries:

   ```
   jti=G-54c045893c auth=NAA-05 sev_max=Extreme geo=[AS-HAL,AS-QUI,AS-CAP]
   nbf=2026-11-06T23:26:00Z exp=2026-11-07T11:26:00Z
   ```

   which exactly covers our cancellation (authority, severity, area) and is valid against `/reference/clock` (03:26Z). That grant is already consumed — the ledger shows it used at 02:52Z and, crucially, a `verifier_disagreement` entry: *"noncanonical_scalar: scalar S not reduced modulo group order; accepted downstream, rejected by RFC 8032 conformant verifier"*. The broadcast centre therefore verifies Ed25519 **without** the canonical-`S` check, while single-use is keyed on `sha256(sig)` — so the same grant can be re-presented with a second, non-canonical signature encoding of the *same* signature: `S' = S + k·L` (L = group order). That yields a different digest, bypassing the replay check, while still verifying.

2. Parser differential in `/api/v1/orders` (v1 passthrough): the schema says three submission paths exist and *"two of the three were rewritten in the v2 cycle with a validating decoder; one is still the v1 passthrough"*. Probing duplicate JSON members identified the v1 path as **`/api/v1/orders`**: it rejects duplicates only accidentally (first-wins/last-wins mix), while `/batch` and `/staged` return `duplicate_member`.

   The v1 decoder normalises JSON member names (so `"operation"`, `"Operation"`, `"OPERATION"` are the same key; the last occurrence wins) for the *authorisation* check, but the role gate inspects a different, case-sensitive lookup: with body

   ```json
   {"operation":"dispatch","Operation":"preview", ...}
   ```

   the policy check is satisfied with the operation value parsed by the *schema* decoder (`preview`, allowed for observers → `X-Authorized-Operation: preview`), whereas the dispatcher gate reads the case-sensitive `operation` key and the broadcast path then acts on the **dispatch** operation, executing the CAP message. Confirmed empirically:

   * `{"operation":"dispatch","Operation":"preview"}` → **200 BROADCAST**
   * `{"operation":"Operation":"preview","operation":"dispatch"}` → 403 role_required (gate sees preview-then-dispatch under its own parse)
   * `{"operation":"preview","operation":"dispatch"}` → 403 (v2-style last-wins)
   * `{"Operation":"preview","operation":"dispatch"}` → 403

   So the differing key case routes the *policy* check one way and the *execution* another.

3. Unlock digest: `release_unlock = sha256-hex("landfall|<cancelled identifier>|<grant jti>|<area sorted, comma-joined>")`:

   ```
   sha256("landfall|ANWA-CAP-992ed112-ef82|G-54c045893c|AS-HAL,AS-QUI")
   ```

4. Exploit — POST `<instance>/api/v1/orders`:

   ```json
   {
     "operation": "dispatch",
     "Operation": "preview",
     "authorization": {"payload": "<grant payload from ANWA-CAP-8b676281-ef46>",
                       "sig": "<S' = S + 2L, base64url>"},
     "payload": {"msgType":"Cancel",
                 "headline":"CANCEL fabricated evacuation order",
                 "severity":"Extreme",
                 "area":["AS-HAL","AS-QUI"],
                 "references":"alerts@anwa.astrenia.test,ANWA-CAP-992ed112-ef82,2026-11-07T02:53:00+00:00"},
     "unlock": "<digest above>"
   }
   ```

   Response `200 BROADCAST` on `CBS-4370`; the cancellation of `ANWA-CAP-992ed112-ef82` went on air, and the response carried a `release_digest` equal to the flag.

**Why it works**

1. Grant replay protection is keyed on `sha256(sig)` instead of `jti` (the jti is right there in the payload) — any signature encoding variant mints "new" single-use tokens.
2. Ed25519 verification lacks the strict `S < L` / canonical-encoding check (explicitly disclosed in the ledger), so `S' = S + k·L` verifies as the same signature while hashing differently.
3. The legacy v1 orders path uses case-insensitive/normalising JSON parsing for policy decisions while the dispatcher role gate uses a case-sensitive lookup, so policy and execution read different `operation` values — an observer can execute a dispatcher-only action.

**Validation**

The broadcast endpoint returned `200 BROADCAST` on `CBS-4370` and the cancellation of `ANWA-CAP-992ed112-ef82` was confirmed on air; the response `release_digest` was returned and matched the flag, `CSCTF{REDACTED}`.
