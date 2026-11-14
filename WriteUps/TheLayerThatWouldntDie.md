### The Layer That Wouldn't Die

> Forensics · Easy · Mohamed Amine Mzoughi
> Points at solve: [fill in]

**Tools used**

python (hmac/hashlib) with manual OCI image layer inspection

**Approach**

1. The OCI image's final layer whiteouted `.sealed_marker`, but the earlier layer still contains its bytes. The image config history explains that `historian.key.sealed` was XOR-encrypted using the repeating HMAC-SHA256 digest of that marker, keyed by the hex-decoded `build.seal` label.
2. Inspected the layer archives in manifest order, recovered the marker from the layer where it was first added, and the sealed credential from the next layer.
3. Computed the HMAC pad and XORed it with the sealed bytes:

```python
pad = hmac.new(bytes.fromhex(build_seal), marker, hashlib.sha256).digest()
credential = bytes(b ^ pad[i % len(pad)] for i, b in enumerate(sealed))
```

**Why it works**

An OCI whiteout only removes a file from the merged filesystem view; it does not erase the file's bytes from the preserved earlier layers. Anything derived from those bytes — here the repeating HMAC-SHA256 keystream keyed by the `build.seal` label — remains reproducible from the layer archives, so the sealed credential can be decrypted offline.

**Validation**

The sealed credential was recovered and the flag `CSCTF{REDACTED}` was obtained (flag redacted).
