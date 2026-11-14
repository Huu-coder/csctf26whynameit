### Onion Deanon 2

> OSINT · Easy · Created by [Covert Security](https://covsec.ee)
> Points at solve: [fill in]

**Tools used**

OpenSSL; curl/Tor for fetching the certificate (already captured as DER at `/tmp/parsnip-cert.der`).

**Approach**

1. The TLS certificate presented by the ParsnipLocker onion service was captured from the onion service as DER at `/tmp/parsnip-cert.der`.
2. OpenSSL computes the requested uppercase, colon-separated SHA-256 fingerprint:

```sh
openssl x509 -inform DER -in /tmp/parsnip-cert.der -noout -fingerprint -sha256
```

Output:

```text
sha256 Fingerprint=14:BF:CD:53:D5:09:FE:DF:0C:A4:FE:7E:9A:3D:6F:E2:A0:45:1F:4E:DA:F7:76:39:EB:BC:0F:ED:93:EB:23:80
```

**Why it works**

The challenge asked for the SHA-256 fingerprint of the exact certificate the onion service presents. `openssl x509 -fingerprint -sha256` computes that hash over the DER-encoded certificate and prints it uppercase and colon-separated, which is the required format. The only network step (retrieving the cert through Tor) had already been done; everything after is local deterministic hashing.

**Validation**

The computed fingerprint was submitted as the flag, `CSCTF{REDACTED}`. The certificate digest above is kept as analysis evidence; the flag wrapper itself is redacted.
