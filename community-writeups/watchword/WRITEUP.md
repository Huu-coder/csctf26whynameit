## <span style="color:#1E88E5">&#9679;</span> Watchword

> **Category:** Crypto<br>
> **Flag:** `CSCTF{REDACTED}`<br>
> **Deployment:** `static`


---

### Overview

#### Challenge Brief
Intercepted SABRELINK dispatch traffic. Three authenticated dispatches were tagged
under the **same** AES-128-GCM nonce (a firmware fault). The master order is sealed
with AES-128-CTR (IV all-zero) under the link's per-nonce tag mask `E_K(J0)`.
Recover the master order text; the flag is that text.

**Flag format:** **`CSCTF{...}`**

---

### Resources

#### Files
- `watchword.zip`
  - `watchword/README.txt`
  - `watchword/intercepts.json`: nonce, 3 × (plaintext, ciphertext, tag), sealed master order

#### Hints
No hints provided.

---

### Solution Walkthrough

1. Write each GCM tag as a polynomial in the GHASH key `H`
2. Remove the unknown mask `E_K(J0)` and solve for `H`
3. Recover `E_K(J0)` and use it as the AES-CTR key for the master order

#### Why this works (brief)
GCM's tag is `T = GHASH_H(A, C) ⊕ E_K(J0)`, and `J0` depends only on the nonce.
With empty AAD and a ciphertext of one block (after padding), GHASH is:

`T = C·H² ⊕ L·H ⊕ E_K(J0)`  (in GF(2¹²⁸), `L = 0⁶⁴ ‖ bitlen(C)`)

Reusing a nonce means every tag shares the same `H` **and** the same mask `E_K(J0)`.
XORing two tags cancels the mask and leaves a quadratic in `H`. That's the
"forbidden attack" (Joux). Here `E_K(J0)`, the "watchword", is used directly as the
key, so recovering it is enough. We never need the GCM key `K`.
<br>

#### 1. Model the tags
All three ciphertexts are ≤ 16 bytes (16, 15, 13), so each is one zero-padded block
`Cᵢ` with its own length block `Lᵢ`:
```
Tᵢ = Cᵢ·H² ⊕ Lᵢ·H ⊕ M        (M = E_K(J0))
```
The lengths differ, so the `Lᵢ·H` terms don't cancel, and that's fine.
<br>

#### 2. Cancel `M` and solve for `H`
Pairwise differences against dispatch 1 give two quadratics:
```
aⱼ·H² ⊕ bⱼ·H ⊕ cⱼ = 0     with aⱼ = C₁⊕Cⱼ, bⱼ = L₁⊕Lⱼ, cⱼ = T₁⊕Tⱼ
```
Combining `a₁·Q₂ ⊕ a₂·Q₁` removes `H²` and leaves a **linear** equation, so no
root finding is needed:
```
H = (a₁c₂ ⊕ a₂c₁) / (a₁b₂ ⊕ a₂b₁)
```
Check `H` against both quadratics, then get `M = T₁ ⊕ C₁H² ⊕ L₁H` and confirm it
reproduces all three tags.
<br>

#### 3. Decrypt the master order
```python
# solve.py: GCM nonce-reuse → recover H and E_K(J0) → AES-CTR decrypt
import json, sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

d = json.load(open(sys.argv[1]))
R = 0xE1 << 120
def gmul(x, y):  # GCM bit-reflected GF(2^128) multiply
    z = 0
    for i in range(127, -1, -1):
        if (y >> i) & 1: z ^= x
        x = (x >> 1) ^ R if x & 1 else x >> 1
    return z
def gpow(x, e):
    r = 1 << 127
    while e:
        if e & 1: r = gmul(r, x)
        x = gmul(x, x); e >>= 1
    return r
ginv = lambda x: gpow(x, (1 << 128) - 2)
b2i = lambda b: int.from_bytes(b, 'big')

eqs = []
for it in d['intercepts']:
    c = bytes.fromhex(it['ciphertext_hex'])
    eqs.append((b2i(c.ljust(16, b'\0')), len(c) * 8, b2i(bytes.fromhex(it['tag_hex']))))

C1, L1, T1 = eqs[0]
(a1, b1, c1), (a2, b2, c2) = [(C1 ^ C, L1 ^ L, T1 ^ T) for C, L, T in eqs[1:]]
H = gmul(gmul(a1, c2) ^ gmul(a2, c1), ginv(gmul(a1, b2) ^ gmul(a2, b1)))
M = T1 ^ gmul(C1, gmul(H, H)) ^ gmul(L1, H)
assert all(gmul(C, gmul(H, H)) ^ gmul(L, H) ^ M == T for C, L, T in eqs)

ct = bytes.fromhex(d['sealed_master_order_ctr_hex'])
key = M.to_bytes(16, 'big')
print(Cipher(algorithms.AES(key), modes.CTR(bytes(16))).decryptor().update(ct).decode())
```
Run:
```bash
python3 solve.py watchword/intercepts.json
```
Intermediate values:
```txt
H       = 730426f0d054fc7539d26145168be28a
E_K(J0) = 66b18782c578d8b27ec249a6298dfeb2
```
<br>

Expected result:
```txt
CSCTF{REDACTED}
```
