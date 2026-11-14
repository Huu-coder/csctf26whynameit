#!/usr/bin/env python3
"""
Operation Dawn (Annex Entry 03) — forensics.

Unencrypted, zlib-compressed Android Backup ("ANDROID BACKUP" v5) containing a
courier-app SQLite database whose WAL still holds a deleted, raw-deflate
message body (raw-deflate streams survive WAL checkpointing).

Usage:
    python3 medic.py <backup.ab>

The CTF instance is retired; this PoC documents the exploit path as a purely
offline analysis of the backup artifact.
"""

import io
import sys
import tarfile
import zlib

HEADER_LINES = 5  # "ANDROID BACKUP", version, compressed flag, encryption, ...


def parse_header(raw: bytes) -> tuple[dict, bytes]:
    """Split the five-line backup header from the compressed payload."""
    lines = []
    offset = 0
    while len(lines) < HEADER_LINES:
        end = raw.index(b"\n", offset)
        lines.append(raw[offset:end].decode("utf-8", "replace").strip())
        offset = end + 1
    header = {
        "magic": lines[0],
        "version": lines[1],
        "compressed": lines[2],
        "encryption": lines[3],
    }
    return header, raw[offset:]


def decompress_payload(payload: bytes, compressed: str) -> bytes:
    if compressed == "1":
        return zlib.decompress(payload)
    return payload  # uncompressed backup: payload is already the tar archive


def find_wal(archive: tarfile.TarFile) -> bytes | None:
    for member in archive:
        if member.isfile() and member.name.endswith("messages.db-wal"):
            extracted = archive.extractfile(member)
            if extracted is not None:
                return extracted.read()
    return None


def scan_raw_deflate(wal: bytes, min_len: int = 16) -> list[tuple[int, bytes]]:
    """Try a raw-deflate decompression at every offset; return plausible text."""
    hits = []
    for offset in range(len(wal)):
        obj = zlib.decompressobj(-15)  # raw deflate, no zlib/gzip wrapper
        try:
            out = obj.decompress(wal[offset:])
        except zlib.error:
            continue
        if len(out) < min_len:
            continue
        try:
            text = out.decode("utf-8")
        except UnicodeDecodeError:
            continue
        if sum(c.isprintable() or c in "\r\n\t" for c in text) / len(text) > 0.9:
            hits.append((offset, out))
    return hits


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 1
    with open(sys.argv[1], "rb") as fh:
        raw = fh.read()

    header, payload = parse_header(raw)
    if header["magic"] != "ANDROID BACKUP":
        print(f"[!] not an Android backup (magic={header['magic']!r})")
        return 1
    if header["encryption"].lower() != "none":
        print(f"[!] backup is encrypted ({header['encryption']!r}); cannot proceed")
        return 1
    print(f"[*] Android backup v{header['version']}, compressed={header['compressed']}")

    tar_bytes = decompress_payload(payload, header["compressed"])
    try:
        archive = tarfile.open(fileobj=io.BytesIO(tar_bytes))
    except tarfile.TarError as exc:
        print(f"[!] decompressed payload is not a tar archive: {exc}")
        return 1

    wal = find_wal(archive)
    if wal is None:
        print("[!] messages.db-wal not found in backup archive")
        return 1
    print(f"[*] recovered messages.db-wal ({len(wal)} bytes); scanning for deflate streams")

    hits = scan_raw_deflate(wal)
    if not hits:
        print("[!] no raw-deflate streams recovered")
        return 1
    for offset, blob in hits:
        print(f"--- raw-deflate stream at WAL offset {offset} ---")
        print(blob.decode("utf-8", "replace"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
