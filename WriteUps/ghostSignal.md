### ghostSignal

> Network · Hard · CSA Romania
> Points at solve: [fill in]

**Tools used**

tshark, Python 3 (`hashlib`).

**Approach**

Category: Network / telecom protocol forensics.

Artifacts: `ss7_capture.pcap`, `diameter_capture.pcap`, `billing_events.json`.

Summary of the finding: a fraudulent roaming operation is visible across three independent record sources. All three artefact types agree on one hidden subscriber identity — the IMSI `226012014000001` (MCC 226 = Romania, MNC 01). Per the challenge rule, the flag is built by taking that identity as it appears in each artefact, joining the three values with `:`, hashing with SHA-256 and keeping the leading 8 lowercase hex digits:

```
sha256("226012014000001:226012014000001:226012014000001")
   = <redacted>
flag: CSCTF{REDACTED}
```

The SCTP verification tags in the captures (`0x4d334155` = "M3AU", `0x0a0b0c0d`) are capture-fixture values, not part of the hash input — they are a consistency check on the same derived hash, not something to concatenate.

Intrusion chain (timeline anchored at `1723740150` (2024-08-15 12:42:30 EDT), the first malicious record):

1. **SS7 first contact (frames 46–55, 12:42:30–12:43:10).** A roaming GT (`49211`) probes the network with `sendRoutingInfo` (op 22) and `sendRoutingInfoForSM` (op 45) for MSISDNs `+40721000101`–`+40721000105`, alternating SRI at :50/:54/:58/:62/:66 and SRI-for-SM at :70/:73/:76/:79/:82. TCAP origin transaction IDs all follow the `4921X102` pattern (e.g. `49210002`, `49210102`, …), one per probe.

2. **Diameter rogue Cx session (frames 25–28, 12:42:30–12:42:31.5).** A Server-Assignment Request (Command Code 301, app 16777216) arrives from `cscf.rogue.evil-domain.net` (10.40.0.99), Origin-Realm `evil-domain.net`, for `Subscription-Id-Data 226012014000001` (Subscription-Id-Type 0 END_USER_E164), `Public-Identity sip:+40721000101@eastern-tele.ro`, session `hss.eastern-tele.ro;1723740150;49211`. The HSS answers and the reply carries `Server-Name sip:cscf.pivot.eastern-tele.ro:5060` plus a hidden AVP-coded URI `diameter://intercept-49211.evil-domain.net` that tshark does not render as a named AVP.

3. **Billing interception (billing_events.json, 12:42:30–12:42:58).**
   - Five `CCR-I` events `atk_0000`–`atk_0004` for IMSI `226012014000001`, targeting `+40721000101`–`+40721000105`, each `charging_amount 0.0` and flagged `zero_charge_on_roaming`, redirected to `intercept-49211.evil-domain.net`.
   - Five `CCA` events `pivot_0000`–`pivot_0004` on the same session, `serving_cscf` `cscf.pivot.eastern-tele.ro`, `redirect_host redirect-49211.evil-domain.net`, flagged `unusual_routing_path`.
   - All ten share the session id `hss.eastern-tele.ro;1723740150;49211`.

4. **SS7 location update / subscription hijack (frames 56–60, 12:43:10–12:43:18).** `updateLocation` (op 2) from calling GT `49311` with `msc-Number 49311` and `vlr-Number 40721009999`; all messages carry IMSI `226012014000001` (TBCD bytes `22 06 21 10 04 00 00 f1`). The attacker has moved the subscriber's location into an attacker-controlled VLR after intercepting the Cx and charging paths.

The same IMSI appears in every malicious record in every artefact: SS7 `updateLocation` ×5, Diameter rogue Cx Subscription-Id-Data, and all ten billing attack events.

Reproduction. The IMSI is not exposed by `tshark -e gsm_map.imsi` in this build; it must be read from the verbose decode:

```bash
tshark -r ss7_capture.pcap -V | grep -oP 'IMSI: \K\d+'          # 226012014000001
tshark -r diameter_capture.pcap -T fields \
  -e diameter.Session-Id -e diameter.Subscription-Id-Data -e diameter.Origin-Host
python3 -I -c "import hashlib;print(hashlib.sha256(b'226012014000001:226012014000001:226012014000001').hexdigest())"
```

`billing_events.json` is filtered by IMSI: every `atk_*`/`pivot_*` event shares `226012014000001` and the session `hss.eastern-tele.ro;1723740150;49211`.

Artefact integrity. Both pcaps validate cleanly: correct IP header checksums and SCTP CRC32c on every frame, consistent per-capture verification tags, no trailing/extra data. The malicious traffic is not a parse artefact — it is a coherent, self-consistent intrusion chain.

**Why it works**

The attacker probed MSISDNs via SS7 `sendRoutingInfo`/`sendRoutingInfoForSM`, registered a rogue CSCF on the Diameter Cx interface with a Server-Assignment-Request to redirect the subscriber's session, mirrored the interception in the billing plane with zero-charge `CCR-I` events and unusual-routing `CCA` events bound to one shared session id, then issued an SS7 `updateLocation` to pull the subscriber into an attacker-controlled VLR. The common thread across all three planes — one IMSI appearing in SS7 `updateLocation`, the Diameter rogue Cx `Subscription-Id-Data`, and every billing attack event — identifies the hidden subscriber; the challenge's flag derivation hashes the joined identity triplet, so the consistency itself is the answer.

**Validation**

All three independent artefacts yield the same IMSI (`226012014000001`): verbose SS7 decode (`updateLocation` messages), Diameter rogue Cx `Subscription-Id-Data`, and every `atk_*`/`pivot_*` billing event. Both pcaps pass checksum and SCTP CRC32c integrity validation, confirming the records are not parse artefacts. The derived SHA-256 matched the challenge's flag rule, yielding `CSCTF{REDACTED}`.
