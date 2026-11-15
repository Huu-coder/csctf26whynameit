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
community-writeups/  Third-party writeups/solvers from the post-event archive (NOT WhyN@m31t's
                      work; flags redacted; see community-writeups/README.md)
```

## Notes

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
