### Operation Dawn — Annex Entry 03

> Forensics · Medium · Terminal43
> Points at solve: [fill in]

**Tools used**

Not specified (zlib decompression; SQLite WAL inspection of the Android backup).

**Approach**

The Android backup contains the courier app's SQLite database and its write-ahead log (WAL). The visible message database only shows the sender's withdrawal notice, but the WAL retains the earlier compressed message body with the platform assignment and flag.

1. Identify the backup as an unencrypted, zlib-compressed Android Backup (`ANDROID BACKUP` v5).
2. Decompress the payload after its five-line header.
3. Inspect the courier app's `messages.db-wal`.
4. Search for raw-deflate streams in the WAL; this reveals the deleted message body:

   ```text
   Movement order. Board the hospital train. Assignment follows: CSCTF{REDACTED} Acknowledge on receipt and destroy this message.
   ```

**Why it works**

SQLite WAL files may retain recently deleted or superseded records until checkpointing. The sender's withdrawal removed the current record from the visible database, but the pre-deletion compressed message body was still present in the WAL as a raw-deflate stream, so it was recoverable offline. Forensic note: preserve and examine the WAL alongside the main database during mobile backup analysis.

**Validation**

The flag was recovered directly from the WAL message body as shown above, `CSCTF{REDACTED}`. No remote service acceptance is recorded in the source.
