### Lattice

> Misc · Easy · Iulian Schifirnet
> Points at solve: [fill in]

**Tools used**

Python (offline inverse implementation of the custom block cipher), written from the supplied source.

**Approach**

The attachment provided a Python implementation of a custom 64-bit block cipher and the ciphertext of the secret passphrase.

1. Analysis: the cipher uses a fixed permutation S-box, 16 rounds of bytewise key addition/XOR, S-box substitution, and a 64-bit rotation. Each transformation is invertible.
2. Implementation: undo the rounds in reverse order, rotate right, apply the inverse S-box, then subtract the round key modulo 256 for even rounds or XOR it for odd rounds.
3. Decrypt every 8-byte block, then remove and validate PKCS#7 padding.
4. The recovered passphrase was `<redacted>`.
5. Verified it against the supplied source (`match`) and submitted it to the audit service, which returned the flag.

**Why it works**

The cipher is a toy construction with fixed public keys and an unauthenticated ECB mode, so every step is reversible offline with no oracle access — confidentiality rested entirely on the secret key material, which was public/fixed. Real systems should use a vetted authenticated-encryption scheme with managed secret keys.

**Validation**

The recovered passphrase matched the supplied source check, and submitting it to the audit service returned the flag, `CSCTF{REDACTED}`.
