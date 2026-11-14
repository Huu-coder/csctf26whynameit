### Northern Viaduct Emergency Clearance

> Web · Medium · Chronos Security
> Points at solve: [fill in]

**Tools used**

curl.

**Approach**

The public clearance API properly rejects the overweight detained convoy. The docket's supervisor button reveals the internal emergency-dispatch endpoint; the gateway blocks paths beginning `/api/v1/internal/`, but its path-prefix filter disagrees with downstream routing about an encoded dot-dot segment.

1. Recon:

   - `GET /api/v1/consignments/CTLD-FR-8821` confirmed the detention: CP-04 measured 46,200 kg against the 40,000 kg viaduct limit.
   - The docket loads `/static/assets/js/chunks/chunk-dispatch-admin.9c4d.js`. Its supervisor control posts `{consignment_id, reason}` to `/api/v1/internal/dispatch/emergency-clearance`.
   - A direct request to that path receives `GW_ACL_INTERNAL_ROUTE_PROHIBITED` from the edge gateway.

2. Exploitation — send the authorized supervisor action through a path that does not begin with the protected prefix, but normalizes downstream to the internal handler:

   ```sh
   curl --path-as-is -i -X POST \
     'http://<instance>/api/v1/consignments/%2e%2e/internal/dispatch/emergency-clearance' \
     -H 'Content-Type: application/json' \
     --data '{"consignment_id":"CTLD-FR-8821","reason":"Authorized emergency viaduct escort"}'
   ```

   The response confirmed emergency clearance and barrier unlock.

**Why it works**

The edge gateway enforces its ACL on the raw path prefix, so anything not beginning with `/api/v1/internal/` is let through. Downstream routing then decodes `%2e%2e` as `..` and collapses the dot-dot segment, resolving `/api/v1/consignments/%2e%2e/internal/dispatch/emergency-clearance` to `/api/v1/internal/dispatch/emergency-clearance`. Because the proxy and the backend disagree on decoding and dot-segment canonicalization, the request reaches the internal supervisor endpoint without ever matching the blocked prefix at the edge.

Remediation: canonicalize and validate request paths once, before authorization and routing. Apply ACLs to the normalized path and ensure the proxy and backend use identical decoding and dot-segment rules. Prefer explicit route allowlists for internal endpoints.

**Validation**

The response confirmed emergency clearance and barrier unlock; the flag was `CSCTF{REDACTED}`.
