### Ash Relay — Operation Dawn Annex 14

> [fill in] · [fill in] · [fill in]
> Points at solve: [fill in]

**Tools used**

Not specified.

**Approach**

The relay used a signed cookie with a vulnerable SHA-1 secret-prefix MAC. A length-extension attack changed the operator session payload to add `role=admin`, and the internal provisioning service behind an SSRF probe then disclosed the standing order.

1. The initial cookie was:

   ```text
   session=<redacted>
   ```

   The first segment decodes to `user=guest&role=operator`; the signature is SHA-1 sized. A SHA-1 length-extension attack with a 16-byte secret length, appending `&role=admin`, generated a valid elevated session. Visiting `/relay` with that cookie exposed the internal service and the `/relay/probe` interface.

2. The command console's probe was then used with an alternate numeric loopback address:

   ```sh
   curl --get 'http://<instance>/relay/probe' \
     --data-urlencode 'target=http://127.1:9091/order' \
     -H 'Cookie: session=<forged-session>'
   ```

   The probe returned the contents of the internal order endpoint, including the flag.

**Why it works**

A secret-prefix MAC (`SHA1(secret || message)`) is vulnerable to length extension: given a valid signature and message, the attacker can compute a valid signature over `message || padding || glue` without knowing the secret, so the session payload could be extended with `&role=admin` and still verify. The probe's loopback check blocked dotted loopback forms but not numeric IPv4 representations, so `http://127.1:9091/order` was accepted as a probe target and reached the local provisioning service on port 9091.

Remediation: use HMAC-SHA-256 (not a secret-prefix hash MAC) for sessions, and avoid placing mutable authorization claims in client-controlled cookies. For SSRF defenses, parse and canonicalize IP addresses before blocking all loopback/private destinations, and enforce an explicit destination allowlist.

**Validation**

The forged session was accepted (`/relay` and `/relay/probe` became accessible), and the probe response contained the internal standing order and the flag, `CSCTF{REDACTED}`.
