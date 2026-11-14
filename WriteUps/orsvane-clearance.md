### Orsvane Freight Clearance

> [fill in] · [fill in] · [fill in]
> Points at solve: [fill in]

**Tools used**

curl, the API's own `/schema` documentation endpoint.

**Approach**

1. `GET /schema` described the API and the release checks. `GET /consignments` identified the held item as `MFC-VPH7WKB`. Its details showed line item 0 used embargoed code `8543.70`, while the approval record was `APPROVED` and its `current_manifest_hash` matched `manifest_hash`.
2. Amend line item 0 to a recognized, non-embargoed classification already used by the other line item, `8409.99`:

```sh
curl -X PATCH http://<instance>/consignments/MFC-VPH7WKB/lineitems/0 \
  -H 'Content-Type: application/json' \
  --data '{"hs_code":"8409.99","justification":"Corrected tariff classification following customs review."}'
```

The manifest stayed valid because `hs_code` was not covered by the approval hash.
3. Release the consignment:

```sh
curl -X POST http://<instance>/consignments/MFC-VPH7WKB/release
```

The API returned `RELEASED` with the clearance certificate.

**Why it works**

Approval binds a manifest hash over only the listed covered fields, and HS codes are not among them. Release checked both the approval hash and whether any current line item used an embargoed code. Amending `hs_code` therefore leaves the approval hash intact while removing the embargoed-code condition, so the release check passes for a consignment whose classification was changed after approval. The approval effectively attests to data that no longer exists.

Remediation:

- Include tariff classification codes in the approved manifest hash.
- Re-open or revoke approval whenever any security-relevant line-item field is amended.
- Validate release against the exact approved data, not against independently mutable fields.

**Validation**

The release endpoint returned `RELEASED` with the clearance certificate. The flag, `CSCTF{REDACTED}`, is redacted here.
