### Keycustody

> Web · Easy · Chronos Security
> Points at solve: [fill in]

**Tools used**

Not specified.

**Approach**

The source records only a credential artifact, not a solve narrative:

```json
{"sub": "analyst-recon-17", "role": "admin", "token": "<redacted>"}
```

The embedded token is an HS256 JWT (`kid: "session"`). Decoded (read-only), its payload carries `sub: "analyst-recon-17"` and `role: "analyst"` — i.e. the outer object claims `role: "admin"` while the token itself asserts `role: "analyst"`. The challenge title and category indicate a key/token custody-handling flaw, but the source does not document the steps from this artifact to the solution, the instance interaction, or the flag.

**Why it works**

Not recorded in the source. The one mechanism visible in the artifact is the discrepancy between the outer claimed role (`admin`) and the role embedded in the signed token payload (`analyst`) — the token's actual contents, not the surrounding claim, are what a verifier would see. The root cause and exploitation path are not documented.

**Validation**

Not recorded in the source. No flag or service-side acceptance is present; to be filled in.
