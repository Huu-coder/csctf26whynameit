### Operation Dawn — ParsnipLocker Certificate

> OSINT · Easy · Created by [Covert Security](https://covsec.ee)
> Points at solve: [fill in]

**Tools used**

Tor (local SOCKS proxy); OpenSSL (`openssl x509`).

**Approach**

Reached the provided `.onion` leak blog through Tor and inspected the TLS certificate presented by the service.

1. Connected to the onion host through the local Tor SOCKS proxy.
2. Captured its DER certificate.
3. Extracted the serial with OpenSSL:

   ```sh
   openssl x509 -inform DER -in parsnip-cert.der -noout -serial
   ```

   Serial reported: `<redacted>`.

**Why it works**

A TLS endpoint — including a Tor onion service — reveals its server certificate to any connecting client; the certificate serial number was chosen as the secret for this challenge, so simply connecting and reading the DER certificate was sufficient to recover it. No exploitation beyond client-side certificate capture was required.

**Validation**

OpenSSL extracted the certificate serial (`<redacted>`), which was used as the flag, `CSCTF{REDACTED}`. No independent service-side verification is recorded in the source.
