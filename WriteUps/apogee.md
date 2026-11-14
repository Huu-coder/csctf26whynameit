### ORRIN-3 / Apogee Delivery Portal

> Web · Hard · Mohamed Amine Mzoughi
> Points at solve: [fill in]

**Tools used**

curl, sha256sum.

**Approach**

The delivery pipeline validates a manifest by looking up archive entries **by file name**, but extracts **every** archive entry in order, honouring Unix symlinks. Because ZIP permits duplicate names, the verifier can hash one entry while the extractor writes another. A vendor package (`PKG-2683`) used this to overwrite the trusted manoeuvre table with a malicious revision through a symlink pointing into the write-protected trusted store. The same technique from the analyst route restored the validated table.

1. Recon — public endpoints (`/api/v1/schema` documents them):

   - `/api/v1/status` — trusted table path `/tmp/apogee/trusted/ops/r3-manoeuvre.ctab`, hash `91e9500f…` (malicious REVISION 54), 895 B
   - `/reference/validated` — validated original REVISION 53, 837 B, `824048d5…a02796`
   - `/deliveries`, `/journal` — delivery history and extraction audit
   - `/api/v1/submissions` — analyst multipart upload (`manifest` + `package`)
   - `/api/v1/pass/receipt` — sealed receipt, unlock digest required

   Schema notes that mattered: `extract-zip 2.0.1`, "symbolic links and unix modes declared in the archive are honoured", trusted store layout `/tmp/apogee/trusted/<layout>/<table>`, staging root `/tmp/apogee/staging/<id>`.

2. Root cause — the incident journal for `PKG-2683` shows 7 archive entries but only 6 validated members, and the table name appears twice:

   ```
   entry_names: [..., "tables/r3-manoeuvre.ctab", "tables/r3-manoeuvre.ctab"]
   links: {"tables/r3-manoeuvre.ctab": {
     "target": "../../../trusted/ops/r3-manoeuvre.ctab",
     "resolved": "/tmp/apogee/trusted/ops/r3-manoeuvre.ctab",
     "sha256": "91e9500f..." }}
   ```

   The verifier builds a name→entry lookup, so the **last** duplicate wins; the extractor iterates all entries. Package layout was:

   1. symlink `tables/r3-manoeuvre.ctab` → `../../../trusted/ops/r3-manoeuvre.ctab`
   2. regular `tables/r3-manoeuvre.ctab` containing the payload

   Extraction creates the symlink, then writing the regular entry through the same path follows the link into the trusted store. The signed manifest declared the regular (last) entry, so validation passed. Directory "write protection" is bypassed because the pipeline process itself follows the link.

3. Exploitation — confirmed the two behaviours with safe in-staging probes:

   - Manifest declaring the **first** duplicate failed with `E_SIZE_MISMATCH: manifest size 4 != archive 12` (verifier read the symlink target string — last entry wins).
   - Symlink-first + payload-last passed and wrote the payload through the link.

   Restore package `PKG-RESTORE-R53`:

   | Order | Entry | Content |
   |---|---|---|
   | 1 | `tables/r3-manoeuvre.ctab` (symlink, mode `S_IFLNK\|0777`) | `../../../trusted/ops/r3-manoeuvre.ctab` |
   | 2 | `tables/r3-manoeuvre.ctab` (file) | validated REVISION 53 table (837 B, `824048d5…`) |

   Manifest declares only the last entry:

   ```json
   {
     "package_id": "PKG-RESTORE-R53",
     "spacecraft": "ORRIN-3",
     "table": "r3-manoeuvre.ctab",
     "vendor": "NSOC Analyst Desk",
     "created": "2026-11-06T14:45:00Z",
     "members": [{"path": "tables/r3-manoeuvre.ctab", "size": 837,
                  "sha256": "824048d585827e94b48a46a7fbe66aeae2080671975f5380c29fe80596a02796"}]
   }
   ```

   Submitted as `multipart/form-data` to `POST /api/v1/submissions`. Result: validation passed, extraction status `ok`, and the journal recorded the restoration:

   ```
   link:tables/r3-manoeuvre.ctab -> ../../../trusted/ops/r3-manoeuvre.ctab
   ```

   `/api/v1/status` then reported the trusted table as 837 B with `sha256 = 824048d5…a02796`.

4. Receipt unlock — the sealed receipt disclosed:

   ```json
   "unlock_algorithm": "sha256-hex",
   "unlock_input": "apogee|<spacecraft>|<validated_sha256>|<restore_package_id>",
   "unlock_context": {"spacecraft": "ORRIN-3",
     "validated_sha256": "824048d585827e94b48a46a7fbe66aeae2080671975f5380c29fe80596a02796",
     "restore_package_id": "PKG-RESTORE-R53"}
   ```

   ```bash
   printf 'apogee|ORRIN-3|824048d585827e94b48a46a7fbe66aeae2080671975f5380c29fe80596a02796|PKG-RESTORE-R53' \
     | sha256sum
   # <unlock-digest>

   curl '<instance>/api/v1/pass/receipt?unlock=<unlock-digest>'
   ```

**Why it works**

ZIP duplicate names plus symlink entries let a package pass name-based validation on one entry while the extractor writes a different one through the link. The verifier's name→entry lookup resolves to the last duplicate (the signed, regular entry), while the extractor iterates all entries in order — creating the symlink first and then following it when writing the "same" path. Signature validation therefore vouches for content that never lands in the trusted store; the payload that wins is whatever was written through the link.

Remediation:

- Enforce unique entry names after path canonicalization; reject archives with duplicate names rather than resolving by lookup.
- Validate and hash the exact byte stream that will be extracted, not a name lookup; cross-check entry count between validation and extraction.
- Never honour symlink entries (or `S_IFLNK` external attributes) from untrusted archives; extract into a sandbox that cannot resolve links outside the staging root.
- Reject absolute or traversal-bearing link targets; use `openat`/`O_NOFOLLOW`-style extraction.
- Perform trusted-store writes with a separate privileged step that copies verified content, not via filesystem side effects of extraction.

**Validation**

Validation passed, extraction status `ok`; the journal recorded `link:tables/r3-manoeuvre.ctab -> ../../../trusted/ops/r3-manoeuvre.ctab`; `/api/v1/status` reported the trusted table as 837 B with `sha256 = 824048d5…a02796`; the sealed receipt returned `status: verified` before the 15:04:32Z pass. The flag was `CSCTF{REDACTED}`.
