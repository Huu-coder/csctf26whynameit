### BlackOut

> ICS · Hard · CSA Romania
> Points at solve: [fill in]

**Tools used**

Not specified.

**Approach**

The evidence describes a malicious Modbus write against substation `0x4A2E`.

1. The HMI configuration contains a hidden FC16 (`Write Multiple Registers`) command starting at register `40001`, spanning 64 registers, with a repeating `55 FA` payload. Packet 31 of `scada_network.pcap` confirms the same operation from `192.168.50.5` to the PLC at `192.168.50.10`: function code 16, start register 40001, count 64, and register values `0x55FA`.

2. The event log corroborates the write at the operational layer. At `2025-11-15T06:15:03Z`, it reports an unexpected FC16 write to read-only registers 40001–40064 and a buffer overflow. The packet-capture clock places packet 31 ten minutes earlier, so that conflicting capture time is not substituted for the exact log timestamp required by the flag specification. Subsequent log entries record altered alarm thresholds, a failed firmware-integrity check, and finally a power outage at station `0x4A2E`.

3. `alarm_override.dat` agrees with the station identifier and threshold changes. Its records encode the high-temperature change from 85 to 250, low-pressure change from 200 to 10, and overcurrent change from 500 to 5000. The HMI configuration and startup log both provide the calibration seed `137`.

4. The first four bytes of `plc_firmware.bin` are `50 4C 43 31`, so the required uppercase firmware header is `0x504C4331`. Using only the fields required by the serialization specification gives:

   ```text
   0x504C4331:0x4A2E:2025-11-15T06:15:03Z:40001:137
   ```

   Its SHA-256 digest was computed; taking the first eight lowercase hexadecimal characters of that digest yields the flag.

**Why it works**

The flag specification pins down an exact serialization — firmware header, station identifier, the event-log timestamp, register start, and calibration seed — and binds the flag to the SHA-256 of that canonical string, truncated to eight hex characters. The only non-obvious choice is the timestamp: the pcap clock conflicts with the event log by ten minutes, and the log's exact timestamp (`2025-11-15T06:15:03Z`) is the one the specification requires, so the capture time must not be used. Cross-corroborating the HMI config, the pcap, the event log, and `alarm_override.dat` pins every field of the serialization.

**Validation**

The serialization string was assembled per the spec and hashed; the flag formed from the first eight lowercase hex characters of the digest was `CSCTF{REDACTED}`. (The digest itself is withheld because its leading bytes constitute the flag body.)
