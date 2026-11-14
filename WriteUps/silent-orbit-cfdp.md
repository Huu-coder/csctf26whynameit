### Silent Orbit CFDP Recovery

> Network · Easy · Cosmin Gorea / HiveHack
> Points at solve: [fill in]

**Tools used**

Not specified.

**Approach**

1. Walked the recording — concatenated CCSDS Space Packets — using the six-byte primary header and packet length (`packet_data_length + 1`), without resynchronizing. Eligible packets use APID `0x321`, telemetry, no secondary header, and sequence flags `11`. The target CFDP transaction is source `01`, sequence `07`, destination `02`, with Version 1, acknowledged mode, no CRC, and small-file encoding.
2. The matching Metadata PDU is at stream offset `0x46`. It declares file size `0xC0` (192 bytes), NULL_CHECKSUM, no closure, and no options, so the relay enters COLLECT. The first accepted EOF at `0xD51` has no error, a zero checksum, no fault-location TLV, and the same file size; it snapshots coverage.
3. File Data PDUs contribute their byte ranges, with duplicate/overlapping ranges merged and ranges extending beyond the file size excluded. The resulting missing intervals are:

```
[5,6) [19,20) [35,36) [51,52) [68,69) [83,84)
[101,102) [119,120) [138,139) [154,155) [171,172) [187,188)
```

4. Constructed the NAK toward the sender: acknowledged, small-file, for transaction `01/07/02`. Its directive is `08`, scope is `[0, 0xC0)`, followed by the ascending missing-range pairs above. The resulting PDU is 112 bytes (4-byte CFDP header, three one-byte IDs, and a 105-byte data field).

**Why it works**

The relay had entered COLLECT waiting for the file's missing byte ranges, and the EOF coverage snapshot showed exactly which intervals never arrived. A CFDP NAK with directive `08` tells the sender precisely which byte ranges to retransmit, completing the file with one targeted retransmission request rather than a full-file resend.

**Validation**

The source reports a recovered flag: `CSCTF{REDACTED}` (flag redacted).
