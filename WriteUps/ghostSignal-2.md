### Ghost Signal

> Network · Hard · CSA Romania
> Points at solve: [fill in]

**Tools used**

Not specified.

**Approach**

1. In `ss7_capture.pcap`, signalling from GT `49211` begins at Unix time `1723740150` with repeated `sendRoutingInfo` requests, followed by `sendRoutingInfoForSM`. A second GT, `49311`, then issues repeated `updateLocation` operations for IMSI `226012014000001`, indicating subscriber-location manipulation after the initial reconnaissance.
2. At the same initial timestamp, `diameter_capture.pcap` records a Server-Assignment request from the rogue host `cscf.rogue.evil-domain.net`. The HSS accepts it with `DIAMETER_SUCCESS`, associates it with `cscf.pivot.eastern-tele.ro`, and uses the full Session-Id:

```text
hss.eastern-tele.ro;1723740150;49211
```

3. The billing export corroborates the activity. Its first anomalous event is `atk_0000` at Unix timestamp `1723740150`, for the same IMSI and Diameter session. It records an accepted, zero-charge roaming event and an attacker-controlled redirect host. Later events continue the zero-charge activity and unusual routing path.
4. Following the required serialization, the flag input is:

```text
226012014000001:hss.eastern-tele.ro;1723740150;49211:1723740150
```

5. Its SHA-256 digest is:

```text
28358943473f95eb307747e985e8e07a933b69f9a9129afea922d0ba912177e0
```

Taking the first eight lowercase hexadecimal characters gives `CSCTF{REDACTED}`.

**Why it works**

Three independent sources anchor the same anomalous activity at the same Unix timestamp: the SS7 capture (reconnaissance via `sendRoutingInfo` followed by location manipulation via `updateLocation`), the Diameter capture (a rogue `S-CSCF/I-CSCF` accepted by the HSS and bound to the target IMSI's session), and the billing export (accepted, zero-charge roaming events on the same IMSI and session). Correlating them pins down the exact serialization the challenge expects — IMSI, full Session-Id, and initial timestamp — and the flag is derived as the first eight lowercase hex characters of the SHA-256 of that string.

**Validation**

The SHA-256 of the serialized input was computed and truncated as specified; the resulting value was accepted as the flag.
