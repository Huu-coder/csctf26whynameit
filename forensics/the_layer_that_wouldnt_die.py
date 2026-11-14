#!/usr/bin/env python3
"""
The Layer That Wouldn't Die — forensics.

An OCI image layer whiteouts `.sealed_marker`, but an earlier layer still
contains its bytes. The sealed credential (`historian.key.sealed`) was
XOR-encrypted with a repeating HMAC-SHA256 keystream of the marker, keyed by
the hex-decoded `build.seal` image-config label. Whiteouts hide files from the
merged view; they do not erase bytes from preserved earlier layers.

Usage:
    python3 the_layer_that_wouldnt_die.py <oci-image-layout-dir>

The OCI image layout directory must contain `index.json` and `blobs/sha256/`.
The CTF instance is retired; this PoC documents the exploit path as a purely
offline analysis of the image artifact.
"""

import gzip
import hashlib
import hmac
import io
import json
import os
import sys
import tarfile

MARKER_NAME = ".sealed_marker"
SEALED_NAME = "historian.key.sealed"
SEAL_LABEL = "build.seal"


def load_json(path: str):
    with open(path, "rb") as fh:
        return json.load(fh)


def blob_path(layout: str, digest: str) -> str:
    algo, hexd = digest.split(":", 1)
    return os.path.join(layout, "blobs", algo, hexd)


def open_layer(path: str) -> tarfile.TarFile:
    raw = open(path, "rb").read()
    candidates = [raw]
    if raw[:2] == b"\x1f\x8b":
        candidates.append(gzip.decompress(raw))
    for candidate in candidates:
        try:
            return tarfile.open(fileobj=io.BytesIO(candidate))
        except tarfile.TarError:
            continue
    raise SystemExit(f"[!] cannot open layer as tar: {path}")


def member_bytes(archive: tarfile.TarFile, suffix: str) -> bytes | None:
    for member in archive:
        base = os.path.basename(member.name.rstrip("/"))
        # Skip whiteout entries (.wh.<name>) — they only mask the file.
        if base.startswith(".wh."):
            continue
        if member.isfile() and (member.name == suffix or base == suffix):
            fh = archive.extractfile(member)
            if fh is not None:
                return fh.read()
    return None


def walk_layers(layout: str, layer_digests: list[str]):
    marker = None
    sealed = None
    for i, digest in enumerate(layer_digests):
        archive = open_layer(blob_path(layout, digest))
        layer_marker = member_bytes(archive, MARKER_NAME)
        layer_sealed = member_bytes(archive, SEALED_NAME)
        if layer_marker is not None and marker is None:
            marker = layer_marker
            print(f"[*] layer {i}: recovered {MARKER_NAME} ({len(marker)} bytes)")
        if layer_sealed is not None and sealed is None:
            sealed = layer_sealed
            print(f"[*] layer {i}: recovered {SEALED_NAME} ({len(sealed)} bytes)")
    return marker, sealed


def decrypt(sealed: bytes, marker: bytes, build_seal_hex: str) -> bytes:
    pad = hmac.new(bytes.fromhex(build_seal_hex), marker, hashlib.sha256).digest()
    return bytes(b ^ pad[i % len(pad)] for i, b in enumerate(sealed))


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 1
    layout = sys.argv[1]

    index = load_json(os.path.join(layout, "index.json"))
    manifest_desc = index["manifests"][0]
    manifest = load_json(blob_path(layout, manifest_desc["digest"]))
    config = load_json(blob_path(layout, manifest["config"]["digest"]))

    labels = (config.get("config") or {}).get("Labels") or {}
    build_seal = labels.get(SEAL_LABEL)
    if not build_seal:
        print(f"[!] image config has no {SEAL_LABEL!r} label")
        return 1
    try:
        bytes.fromhex(build_seal)
    except ValueError:
        print(f"[!] {SEAL_LABEL} is not valid hex")
        return 1
    print(f"[*] {SEAL_LABEL} label found ({len(build_seal) // 2} key bytes)")

    layers = [l["digest"] for l in manifest.get("layers", [])]
    print(f"[*] walking {len(layers)} layers in manifest order")
    marker, sealed = walk_layers(layout, layers)

    if marker is None:
        print(f"[!] {MARKER_NAME} not found in any preserved layer")
        return 1
    if sealed is None:
        print(f"[!] {SEALED_NAME} not found in any preserved layer")
        return 1

    credential = decrypt(sealed, marker, build_seal)
    print(f"[*] recovered credential: {credential.decode('utf-8', 'replace')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
