### VaultKeeper

> Mobile · Easy · Pratik Shetty
> Points at solve: [fill in]

**Tools used**

python solver scripts (`vault_scripts/apk_v2_cert.py` to parse the v2 signing block, `vault_scripts/vault_solve.py` to brute the 4-digit code, test passcode candidates, and decrypt)

**Approach**

Attachment: `vaultkeeper.apk` (2,413,853 B, SHA-256 `79559746ad419b219c88b362ff89b667993bad726e3b7109501b075c007de2ed`).

The note is stored as an AES-GCM blob in a string resource. The key is `SHA-256(recovery_token || archive_digits || master_passcode)`, where each piece is recovered from a different part of the app (signing certificate, resources, and the handover card). Everything is doable offline.

1. **Recovery token (signing cert).** `MainActivity` builds the token from the APK signing certificate:

```java
sha = SHA-256(packageManager.getPackageInfo(pkg, GET_SIGNATURES).signatures[0].toByteArray());
token = "KJSC-" + hex(sha).substring(0, 8).toUpperCase() + "-RECOVERY";
```

The APK is signed with APK Signature Scheme v2 only (no `META-INF/CERT.RSA`), so `keytool` can't read it. Parse the APK Signing Block directly: EOCD → central-directory offset → 16-byte magic `APK Sig Block 42`, then the length-prefixed ID/value pairs. Block `0x7109871a` (v2) → signer → signed data → certificates; the first DER cert is the signing certificate.

```
sha256(cert.der) = 1c28dc7e5ab079ffa0f014a0fefd11c7bf673e5d0d912c4c80ebd210818894d6
token            = <recovery-token>
```

(Decompiler trap: `K0.b.w0` looks like Base64 but is actually per-byte `String.format("%02x")` — the token uses the lowercase hex digest, then uppercases it.)

2. **Archive digits / stage 2 key.** `ArchiveActivity` computes `archive_key = HMAC-SHA256(key=archive_session, msg=4 digits)` → lowercase hex → first 8 chars → uppercase. The resources leak both halves:

```xml
<string name="archive_session">VK-7F42</string>
<string name="archive_index_table">VK-1A37 -> △ ○ □ ◇
VK-9F42 -> ○ ◇ □ △
VK-7F24 -> □ △ ◇ ○
VK-7F42 -> ◇ □ △ ○
VK-4F71 -> ◇ ○ △ □</string>
<string name="archive_legend_internal">△=7,○=2,□=9,◇=4</string>
```

`VK-7F42 → ◇ □ △ ○ → <archive-digits>`, and

```
HMAC-SHA256("VK-7F42", "<archive-digits>").hex()[:8].upper() = <archive-key>
```

which is exactly the hardcoded value `RecoveryStage2Receiver` accepts (`archive_key` extra, after `stage1_complete` is set). A brute force over 0000–9999 finds the same code, so the table is only a shortcut.

The exported components wired to this: `vault://recover?stage=1` with `recovery_token=<recovery-token>` unlocks stage 1 (`RecoveryDiagnosticsActivity` compares against `VaultDiagnosticsProvider`'s `recovery_token`), then the broadcast `com.vaultkeeper.action.RECOVERY_STAGE2` with `archive_key=<archive-key>` sets stage 2. `LegacyRecoveryActivity` is a dead end (decommissioned channel).

3. **Note decryption.**

```java
key = SHA-256(token || archive_digits || passcode);
c  = Cipher.getInstance("AES/GCM/NoPadding");
c.init(DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, iv)); // iv = ct[0:12]
note = c.doFinal(ct[12:]);
```

The ciphertext is `R.string.flag_ciphertext_b64`, and the master passcode is the authorization code from the handover card: `<master-passcode>`.

```
key = SHA-256("<recovery-token>" "<archive-digits>" "<master-passcode>")
pt  = CSCTF{REDACTED}
```

**Why it works**

Three independent recovery paths — the v2 signing block (which survives without any `META-INF/CERT.RSA` because the APK uses APK Signature Scheme v2 only), the resource-resident lookup table plus its legend (or a 0000–9999 brute force as a cross-check), and the handover card's authorization code — converge into a single AES-256-GCM key. GCM's authentication tag only validates with the exact token, digits, and passcode, so the decryption itself proves all three recoveries are correct; a wrong piece fails the tag check rather than returning garbage plaintext.

**Validation**

GCM authentication confirmed the whole chain — the tag validates only with the exact token, digits, and passcode — and decryption yielded the flag `CSCTF{REDACTED}` (flag redacted).
