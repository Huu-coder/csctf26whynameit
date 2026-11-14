### Kessara Fire-Authorization Console

> [fill in] · [fill in] · [fill in]
> Points at solve: [fill in]

**Tools used**

curl; a synchronized burst of concurrent HTTP requests.

**Approach**

A race condition in the approval endpoint allowed one authenticated officer to satisfy a two-person approval threshold by issuing concurrent approval requests. The target order reached `ARMED`, exposing its arming authorization.

1. Recon: `GET /schema` documented the API, identified the authenticated officer as `VEGA-7`, and described a two-person rule (`required_approvals = 2`) with approval idempotence per officer. `GET /orders` showed one `PENDING_AUTH` order: `AO-7D31C9`.

   ```sh
   curl -sS -H 'Authorization: Bearer <operator_key>' http://<instance>/schema
   curl -sS -H 'Authorization: Bearer <operator_key>' http://<instance>/orders
   ```

2. Exploit: sent a synchronized burst of eight concurrent, bodyless `POST /orders/AO-7D31C9/approve` requests with the issued bearer credential. Concurrent processing recorded two approvals for the same officer in the same epoch, despite the distinct-officer requirement. The response showed the order as `ARMED` and returned the authorization.

   ```sh
   # Concurrently POST, with no request body:
   POST /orders/AO-7D31C9/approve
   ```

The successful response included two `VEGA-7` approval records and the authorization (the flag).

**Why it works**

The approval path checked-then-acted non-atomically: concurrent requests from the same officer were each evaluated against the pre-update state, so both were recorded in the same epoch and counted toward the two-person threshold, bypassing the distinct-officer requirement. Idempotence was not enforced at the data layer.

Remediation: enforce the distinct-officer constraint atomically at the data layer, using a uniqueness constraint on `(order_id, approval_epoch, officer)` and a transaction/lock around threshold evaluation and state transition. Concurrent retries by the same officer should remain idempotent.

**Validation**

The concurrent approve burst returned the order as `ARMED` with two `VEGA-7` approval records and the authorization, `CSCTF{REDACTED}`. No further service-side verification is recorded in the source.
