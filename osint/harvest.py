#!/usr/bin/env python3
"""
Harvest (CSCTF 2026, OSINT/Crypto - Not shown)

Replays the intercept analysis: Vigenere (A=0) with the day's callsign as key,
check-group validation (number of cipher groups, section 4.2 of the signals
instruction), and cross-checks against the flight schedule and logistics file.

Usage: python3 harvest.py

The CTF instance is retired; this PoC documents the exploit path.
"""

# The two encrypted intercepts exactly as printed in the handout/writeup.
INTERCEPT_1 = """141020
CVKEV DWGHT OVZEG KPZWZ NHKXB OEMTR DEMXN TZEDH NTZCL
XIXOW XLZMW CRXHY ZEDXN YZAXW QACAS TOXAV RMSDU HDMNA
SEDOV XJVNX X
21"""

INTERCEPT_2 = """141630
YCBZN YLMCE JBOUE PNOYB MNZBN SGYSF OLDSF OLUCF OOMZR
ILGDK YJRLF OOICF ZZPSK QFVAL VLJVR NHEOQ OGRHK OFZRG
NOKLO JFKLG MWUHF VHOQU ZHPFR SYFBR X
24"""

# Callsigns from the 417 OVE flight schedule (the day's keys per section 4.1).
CALLSIGNS = {
    "bort 22": ("ZHATVA", "Mi-8MTV-5, external sling load 09:00-10:55, 'LZ per separate order'"),
    "bort 34": ("VORON", "U/S, main gearbox, not before 18.08"),
    "bort 25": ("BEREG", ""),
    "bort 21": ("GRACH", ""),
}


def vigenere_decrypt(text: str, key: str) -> str:
    out, ki = [], 0
    key = key.upper()
    for ch in text.upper():
        if not ch.isalpha():
            out.append(ch)
            continue
        shift = ord(key[ki % len(key)]) - ord("A")
        out.append(chr((ord(ch) - ord("A") - shift) % 26 + ord("A")))
        ki += 1
    return "".join(out)


def parse_intercept(raw: str):
    lines = [ln for ln in raw.strip().splitlines() if ln.strip()]
    dtg, declared_check = lines[0].strip(), lines[-1].strip()
    groups = " ".join(lines[1:-1]).split()
    return dtg, groups, int(declared_check)


def analyze(raw: str, assumed_bort: str | None = None):
    dtg, groups, declared = parse_intercept(raw)
    actual = len(groups)
    print(f"=== intercept DTG {dtg}: {actual} groups, declared check group {declared}"
          f" -> {'OK' if actual == declared else 'MISMATCH (check group fails, section 4.2)'}")
    keys = [CALLSIGNS[assumed_bort][0]] if assumed_bort else [v[0] for v in CALLSIGNS.values()]
    for key in keys:
        letters = vigenere_decrypt(" ".join(groups), key).replace(" ", "")
        words = " X ".join(word for word in letters.split("X") if word)
        print(f"--- key {key}: {words}")


def main() -> None:
    print("[*] Intercept #1 (the real report, bort 22 / ZHATVA):")
    analyze(INTERCEPT_1, "bort 22")
    print()
    print("[*] Intercept #2 (the forgery, claims bort 34 / VORON):")
    analyze(INTERCEPT_2, "bort 34")
    print()
    print("[*] Verdict: intercept #1 reconciles (21 groups, key ZHATVA, bort 22 airborne")
    print("    09:00-10:55, SNOP x4 to PP-7). Intercept #2 fails the check group outright")
    print("    and contradicts the schedule (bort 34 U/S), the site list (PP-2 closed),")
    print("    and the flying window (no flights after 15:00), so the open-source claim")
    print("    that bort 34 delivered to PP-2 is corroborated by nothing.")


if __name__ == "__main__":
    main()
