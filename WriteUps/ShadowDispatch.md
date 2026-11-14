### Shadow Dispatch

> Forensics · Hard · Marius Merai
> Points at solve: [fill in]

**Tools used**

Not specified. (CloudTrail logs, static inspection of the bundled bytecode, and CRC-16 token verification were used.)

**Approach**

1. The `prod` alias pointed at authorizer version 9, but CloudTrail showed a later deployment to version 10 and alias movement around 22:30 UTC. The suspicious change was in `auth-utils:10`: its Python source still looked normal, but the bundled Python 3.12 bytecode had different behavior.
2. Static inspection showed the bytecode reads four SSM secrets, including `/gridlink/order-hmac-key`, and uses selected secret data as the telemetry beacon. The authorizer execution role could read and decrypt `/gridlink/*`, enabling this behavior — this explains the unusual correlation telemetry without an obvious source-code change.
3. Correlation tokens encode two beacon bytes per order ID. The ciphertext was decoded using the logged request ID and salt (`SHA256(request_id + salt)[:2]`), and each candidate plaintext was checked against the token's CRC-16.
4. The order-HMAC-key fragments were emitted for order IDs divisible by five; ordering the recovered fragments by token index `0` through `7` reassembled the key. That reassembled hex is the secret behind the flag, so it is redacted here.

**Why it works**

A malicious dependency layer (`auth-utils:10`) shipped bytecode that diverged from its apparent source, slipping past source-only review. Over-privileged SSM/KMS permissions on the authorizer execution role let the trojan read the order-HMAC key, and the correlation-token beacon trickled it out two bytes per order, hidden in routine telemetry. The per-fragment CRC-16 made the covert channel self-locating: valid fragments could be identified and ordered by token index, reconstructing the full key from orders whose IDs were divisible by five.

Remediation: remove the unauthorized layer version and roll back the alias; rotate the exposed signing key and other readable secrets. Restrict the authorizer's SSM/KMS permissions to only the specific configuration parameter it needs, and validate deployed bytecode/artifact hashes — not only source files.

**Validation**

The reassembled key material was verified piecewise against each token's CRC-16 during recovery, and the reassembled value was accepted as the flag (`CSCTF{REDACTED}`).
