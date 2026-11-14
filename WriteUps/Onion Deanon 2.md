### Onion Deanon

> OSINT · Easy · Created by [Covert Security](https://covsec.ee)
> Points at solve: [fill in]

**Tools used**

Tor SOCKS proxy, base64, MurmurHash3 (x86, 32-bit, seed 0).

**Approach**

1. The DarkPigeon portal's HTML points to `/favicon.ico`. The favicon was retrieved from the onion service using the already-running Tor SOCKS proxy; the response was HTTP 200 with `Content-Type: image/x-icon` and a length of 6,434 bytes.
2. Base64-encode the raw bytes using 76-character lines with a trailing newline, as used by Shodan's favicon hashing convention.
3. Compute the MurmurHash3 x86 32-bit hash (seed 0) over that base64 text and interpret the result as a signed 32-bit integer.

Measured values:

- Favicon SHA-256: `195873a07c938f21ef8c016048230bc84861d08653e8c01ccf3620089c848dea`
- Base64 input length: 8,693 bytes
- MurmurHash3 signed value: `-209798607`

**Why it works**

Shodan indexes favicons by the MurmurHash3 of their base64 encoding wrapped the MIME way (76-character lines plus a trailing newline), not of the raw bytes or of unwrapped base64. Reproducing that exact convention — line wrapping, trailing newline, seed 0, signed interpretation — yields the hash Shodan would report, which is what the challenge asks for. Deviating from the wrapping or the signed interpretation changes the result.

**Validation**

The signed MurmurHash3 value above was submitted as the flag, `CSCTF{REDACTED}`. The favicon digest and hash are kept as analysis evidence; the flag wrapper itself is redacted.
