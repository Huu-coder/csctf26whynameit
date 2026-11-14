### Torven Ordnance

> Crypto · Easy · Chronos Security
> Points at solve: [fill in]

**Tools used**

Python (`pow(a, -1, n)`), `forge.py`

**Approach**

`GET /schema` is self-describing:

- curve `secp256k1`, SHA-256 big-endian message hash mod `n`
- routes: `/pubkey`, `/receipts`, `POST /authorize`
- alternative hex widths 64, receipts use raw (non-low) `s`, `/authorize` requires low-s
- and, tellingly, `"same_nonce_recovery":"k=(z1-z2)*inv(s1-s2)modn;d=(s1*k-z1)*inv(r)modn"`

`GET /receipts` returns two signed release receipts:

| id | r | s |
|----|----|----|
| ta-9.7.14 | `02631cf5…86569` | `30200cdf…e6705` |
| ta-9.7.15 | `02631cf5…86569` | `9870880c…c160d` |

Both share the same `r`, so both were produced with the **same nonce k** — the classic ECDSA nonce-reuse failure. The schema even hands over the recovery equations.

Key recovery. With `z_i = int(sha256(message_i)) mod n`:

```
k = (z1 - z2) * inv(s1 - s2) mod n
d = (s1 * k - z1) * inv(r) mod n
```

`forge.py` does this with pure-Python `pow(a, -1, n)` and then checks `d·G` against `GET /pubkey` — it matches:

```
k = <redacted>
d = <redacted>
Q = 04243530a22e…935be039b0   (== published pubkey)
```

Forging the master authorization. The target message is given in the schema (`authorize_message_rule: exact-master-message-hex`):

```
TORVEN-AUTHZ-V1
operation=promote-master-arming
artifact=master-arming-image
```

Reuse the recovered `k` (we already know `r`, no EC math needed):

```
z_m  = sha256(master_message) mod n
s_m  = k^-1 * (z_m + r*d) mod n
if s_m > n//2: s_m = n - s_m      # /authorize requires low-s
```

Then:

```
POST /authorize
Content-Type: application/json
{"message_hex":"544f5256454e2d…6d6167650a","r":"02631cf5…86569","s":"3f27783a…155998c2"}
```

Response:

```json
{"master_authorization":"CSCTF{REDACTED}"}
```

**Why it works**

ECDSA is only as strong as its nonce: with the same `k`, two signatures yield two linear equations in the two unknowns `k` and `d` (the private key), solvable with one modular inverse. Because `r` is identical in both receipts, nonce reuse is detectable from public data alone, and the schema literally publishes the recovery formulas. Once `d` is recovered, arbitrary messages can be signed; the only wrinkle is the low-s requirement on `/authorize`, handled by flipping `s_m` to `n - s_m` when needed.

**Validation**

The derived public key `d·G` matched the published `/pubkey` (`Q = 04243530a22e…935be039b0`), and `POST /authorize` returned a `master_authorization` value (`CSCTF{REDACTED}`).
