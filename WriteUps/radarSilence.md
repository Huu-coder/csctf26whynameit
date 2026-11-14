### Radar Silence

> Network · Easy · Chronos Security
> Points at solve: [fill in]

**Tools used**

Wireshark/tshark-style PCAP analysis, base32 decoding (RFC 4648).

**Approach**

Challenge description: RDR37 (192.0.2.37) carries the air-surveillance radar link of an Operation Dawn ally whose picture feeds the coalition's shared air surveillance; OPS40 (192.0.2.40) logs operations. Before a scheduled cutover, analysts marked RDR37 for a suspected bearer-token leak. This PCAPNG is an isolated-lab replay, not a production capture. Determine whether a bearer token left RDR37 and recover it for reissue. The flag wraps the lower-case station ID and a 32-character lower-case hex token around a `_rotation_` infix.

1. **Recon.** Opening the PCAP with a DNS-focused filter immediately stands out — all traffic is UDP/53. Two hosts are active:

| Host | Role |
|------|------|
| `192.0.2.37` | RDR37 — the radar station under suspicion |
| `192.0.2.40` | OPS40 — operations logger |
| `192.0.2.1`  | DNS resolver |

Parsing every query name from RDR37 reveals two distinct namespaces:

- **`*.airnet.example`** — legitimate-looking infrastructure names (`patch-cache`, `wpad`, `mirror`, `_dmarc.mail`, `rdr37-diag`)
- **`*.update.svc-telemetry.example`** — anomalous, with high-entropy labels as the leftmost subdomain

2. **DNS exfiltration.** Four queries from `192.0.2.37` follow the pattern `<chunk>.<seq>.update.svc-telemetry.example`, where the numeric second label (`00`–`03`) is a sequence number and the first label is a payload chunk:

```
<chunk-0>.00.update.svc-telemetry.example
<chunk-1>.01.update.svc-telemetry.example
<chunk-2>.02.update.svc-telemetry.example
<chunk-3>.03.update.svc-telemetry.example
```

3. **Decoding.**

Step 1 — reassemble the chunks in sequence-number order. The concatenated string is 52 characters long; the alphabet (`a-z`, `2-7`) is RFC 4648 base32 (lowercase variant).

Step 2 — base32 decode:

```python
import base64
data = "<reassembled-52-char-lowercase-base32>"
padded = data.upper() + "=" * ((8 - len(data) % 8) % 8)
decoded = base64.b32decode(padded)
print(decoded)
# b'<32-char lowercase hex bearer token>'
```

The decoded bytes are printable ASCII — the bearer token itself, already expressed as a 32-character lowercase hex string (redacted here).

**Why it works**

DNS exfiltration encodes arbitrary data into subdomain labels, which are case-insensitive and limited to `[a-zA-Z0-9-]`. Base32 is a natural fit: it uses only letters and digits `2-7`, making every label a valid DNS name. The per-query sequence numbers in the second label prevent reassembly errors if packets arrive out of order. The queries blend into background telemetry traffic (`svc-telemetry.example`) and are indistinguishable from legitimate beaconing without inspecting the label entropy — a classic low-and-slow exfil pattern.

**Validation**

The four `*.update.svc-telemetry.example` queries were reassembled, base32-decoded, and the result validated as a printable 32-character lowercase hex token — consistent with the format required for reissue. The recovered token and the flag (`CSCTF{REDACTED}`) are redacted here.
