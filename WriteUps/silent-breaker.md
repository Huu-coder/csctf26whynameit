### Silent Breaker

> Forensics · Medium · Dan-Andrei Grigorescu
> Points at solve: [fill in]

**Tools used**

curl, Wireshark

**Approach**

The substation breaker was operated through the IEC 60870-5-104 control channel after a suspicious mobile-signaling sequence identified the compromised Velkarion Mobile employee. The attacker then used that employee's OT-VPN session to send an ON command while historian data was held at a forged current value.

Target: `<instance>`

The case index at `GET /files/` provided the report contract, roster, IEC-104 capture, and HMI historian log. The free feed at `GET /events` showed seven events from the unrecognized signaling peer `GT-3908-Z83`.

The event MSISDNs were correlated with `roster.json`. The OT-enabled match was:

- Employee: Sanda Stoica
- Employee ID: `VLK-2348-STO`
- Role: OT Field Engineering
- MSISDN: `+882-16-2727477`

The target was confirmed with:

```bash
curl -X POST <instance>/confirm-target \
  -H 'Content-Type: application/json' \
  -d '{"employee_id":"VLK-2348-STO"}'
```

`GET /query/vpn-window` returned the relevant session:

- Session ID: `VPN-552283`
- Source IP: `198.51.100.59`
- Start: `2026-06-15T20:16:36Z`

The packet capture showed the legitimate RTU reporting normally on IOA `8918` until the control action. At `2026-06-15T20:50:43Z`, the client sent an IEC-104 `C_SC_NA_1` single command to IOA `8918`; Wireshark decoded the command as `Act`, and the command qualifier was ON. The server acknowledged it as `ActCon`.

The historian log identifies the breaker-current IOA as `0x22d6`. It reports normal values around `389-392 A`, then stores `441.0 A` repeatedly from `20:49:50Z` through `20:52:40Z`, with the repeated run marked `QUALITY=SUSPECT`. The frozen displayed telemetry value required by the contract is therefore `441.0`.

The wire command time is `20:50` UTC. The VPN session start is not the command time.

Submission:

```json
{
  "ioa_address": "0x22d6",
  "command_qualifier": "ON",
  "command_time_utc": "20:50",
  "telemetry_status": "441.0",
  "vpn_session_id": "VPN-552283"
}
```

**Why it works**

The attacker abused a compromised employee's OT-VPN access to reach the IEC-104 control path and issue a single command (`C_SC_NA_1`, qualifier ON) to the breaker IOA, while the historian — fed/cached values rather than validated live RTU telemetry — displayed a frozen, forged `441.0 A` reading marked `QUALITY=SUSPECT`. Correlating the signaling peer, roster, VPN window, packet capture, and historian anomaly attributes the command to the stolen session rather than to normal operations.

Remediation:
- Block and investigate the unrecognized signaling peer `GT-3908-Z83`.
- Revoke Sanda Stoica's OT-VPN credentials and review the associated source IP `198.51.100.59`.
- Require authenticated IEC-104 command paths with allowlisted peers and command authorization.
- Alert on commands to the breaker IOA and correlate them with VPN identity and source IP.
- Treat repeated historian values as untrusted until validated against live RTU telemetry; preserve raw RTU data separately from historian cache records.

**Validation**

The service accepted the report and returned the flag (`CSCTF{REDACTED}`).
