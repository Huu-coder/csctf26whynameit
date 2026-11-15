# CSCTF 2026 — WhyN@m31t writeups & PoCs

Team **WhyN@m31t** · Junior division · 8th at close

Challenge writeups and Python proof-of-concept scripts for the challenges our team solved at CSCTF 2026.

## Layout

```
WriteUps/     One card per solved challenge (Category · Difficulty · Author, points at solve,
              tools, approach, why it works, validation)
web/          Web exploitation PoCs
pwn/          Pwn / binary exploitation PoCs (pwntools)
rev/          Reverse engineering PoCs
crypto/       Cryptography PoCs
forensics/    Forensics PoCs
network/      Network / ICS-adjacent network PoCs
ics/          ICS / OT PoCs
misc/         Misc PoCs
mobile/       Mobile PoCs
osint/        OSINT PoCs
```

## Notes

- `WriteUps/` and the PoC folders also contain the writeups and solver scripts from the
  post-event archive (`2026-chronos-security.zip`; third-party, authorship unknown, not
  WhyN@m31t's work): the `WriteUps/` files `coderedfreight.md`, `groundlock.md`,
  `helious-rtu.md`, `operationdawn-radiorecovery.md`, `operationdawn-relaysnapshot.md`,
  `operationdawn-thesharedmodel.md`, `operationdawn-watchlistaudit.md`, `phantomdrift.md`,
  `telltale.md`, `watchword.md`, and the PoCs `rev/groundlock.py`,
  `rev/operationdawn_radiorecovery.py`, `forensics/operationdawn_relaysnapshot.py`,
  `misc/operationdawn_thesharedmodel.py`, `misc/operationdawn_watchlistaudit.py`,
  `forensics/phantomdrift.py`, `misc/telltale.py`, `crypto/watchword.py`. Flags are
  redacted; challenge artifacts are not redistributed.
- All writeups follow the CSCTF 2026 team writeup template. Flags are redacted as
  `CSCTF{REDACTED}`, instance hosts/URLs as `<instance>`, and credentials/tokens/cookies as
  `<redacted>`. Points at solve are left as `[fill in]` where not recorded.
- The CTF instances are retired. The PoC scripts document the exploit/analysis path taken
  during the event; web and network PoCs take the target as `sys.argv[1]`.
- Challenge category/difficulty/author metadata comes from the CSCTF 2026 scoreboard and is
  left as `[fill in]` where it could not be matched reliably.

## Members

- dvck
- moken
- fantup
- huu.pwndev
