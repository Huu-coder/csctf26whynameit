### Harvest

> OSINT · Not shown · Kevin Sander
> Points at solve: [fill in]

**Tools used**

Manual cryptanalysis (Vigenère), the handout material (417 OVE flight schedule, radio-discipline instruction, logistics working file, two encrypted intercepts). Source category was OSINT / Crypto.

**Approach**

Task: on 14 August 2026 a Telegram channel claimed that Mi-24 "bort 34" delivered cargo near Staroselye (PP-2). The handout contains the 417 OVE flight schedule, a radio-discipline instruction, the logistics working file and two encrypted intercepts. Determine where the sling-load cargo actually went and what it was.

The signals instruction fixes the scheme:

- §4.1 — Vigenère (A=0) over transliterated Russian, **key = the crew's callsign for the day** (from the flight schedule), letter `X` marks word boundaries.
- §4.2 — `DDHHMM` date-time group / cipher groups of five / **check group = number of groups**.
- §4.3 — landing sites by PP number only; naming a settlement is prohibited.
- §4.4/§4.5 — cargo code words and the numeric glossary.

Callsigns from the schedule: bort 22 = **ZHATVA** (Mi-8MTV-5, external sling load 09:00–10:55, "LZ per separate order"); bort 34 = **VORON** (U/S, main gearbox, not before 18.08); bort 25 = BEREG; bort 21 = GRACH.

1. **Intercept #1 — the real report.**

```
141020
CVKEV DWGHT OVZEG KPZWZ NHKXB OEMTR DEMXN TZEDH NTZCL
XIXOW XLZMW CRXHY ZEDXN YZAXW QACAS TOXAV RMSDU HDMNA
SEDOV XJVNX X
21
```

Received 10:21, DTG 141020, **21 groups** (20×5 plus the short final `X`), check group 21 — consistent. Decrypting with **ZHATVA**:

```
DOKLAD X ZHATVA X GRUZ X SNOP X CHETYRE X MESTA
X DOSTAVLEN X PP X SEM X VREMYA X DESYAT X DVADTSAT
X BORT X DVADTSAT X DVA X KONEC
```

> Report ZHATVA: cargo SNOP, four pieces, delivered to PP-7 at 10:20, bort 22, end.

This matches the paper trail:

- logistics: `bort 22  SNOP ×4  sling  → PP per order`; SNOP = portable EW jamming set;
- PP-7 = Mirnoe, harvested field west of the dairy farm;
- schedule: bort 22 airborne 09:00–10:55, and the message was logged at 10:21.

2. **Intercept #2 — the forgery.**

```
141630
YCBZN YLMCE JBOUE PNOYB MNZBN SGYSF OLDSF OLUCF OOMZR
ILGDK YJRLF OOICF ZZPSK QFVAL VLJVR NHEOQ OGRHK OFZRG
NOKLO JFKLG MWUHF VHOQU ZHPFR SYFBR X
24
```

Received 16:34, DTG 141630. It contains **25 groups** but declares check group **24** — the check fails outright. Decrypting with **VORON**:

```
DOKLAD X VORON X GRUZ X KORZINA X SHEST X MEST X DOSTAVLEN
X PP X DVA X STAROSELYE X VREMYA X SHESTNADTSAT X TRIDTSAT
X BORT X TRIDTSAT X CHETYRE X KONEC
```

> Report VORON: cargo KORZINA, six pieces, delivered to PP-2 Staroselye at 16:30, bort 34, end.

It is fabricated, and every independent check says so:

1. **Check group mismatch** — 25 groups sent, 24 declared (§4.2).
2. **Names a settlement** — `STAROSELYE` instead of a PP number, prohibited by §4.3.
3. **Aircraft grounded** — bort 34 (VORON) is U/S awaiting a main gearbox replacement, not before 18 August.
4. **Site closed** — PP-2 Staroselye has been closed since 02.08 (mines, order 88).
5. **Outside the flying window** — no flights after 15:00 (thunderstorm warning 15:00–22:00), yet the message claims 16:30.

The forged message simply reproduces the Telegram claim (bort 34 → Staroselye), which is therefore not corroboration of anything.

Answer: the squadron's sling-load cargo went to **PP-7 (Mirnoe)**, flown by **bort 22** (Mi-8MTV-5, ZHATVA), delivered at **10:20** on 14 August. The cargo was **SNOP — portable EW jamming sets — four pieces**.

**Why it works**

Vigenère (A=0) keyed by the day's callsign is only as strong as the callsign schedule, which the handout itself provides — so each intercept is decryptable once the right key is selected, and the schedule independently tells us which callsign is even airworthy. The check group (§4.2) turns the format itself into an integrity control: intercept #1's group count matches its declared check group, while intercept #2 declares 24 for 25 groups, exposing the forgery before any content analysis. Everything else (serviceability, flying window, closed sites, settlement-naming prohibition) is then cross-corroboration against the logistics sheet, the site list and the schedule — a message matching the open-source claim is not confirmation when it fails every independent check.

Takeaways:

- Validate the check group before trusting any intercept; a single extra group exposed the forgery.
- Cross-check decrypted content against every other source: the schedule (callsign, airframe serviceability, flying window), the logistics sheet (code words, load plan), and the site list (closed PP-2).
- A message that matches the open-source claim is not confirmation — here the claim and the forged intercept were consistent with each other and with nothing else.

**Validation**

Intercept #1 decrypts cleanly under ZHATVA and its check group reconciles (21 = 21); its contents match the logistics load plan and the flight schedule window. Intercept #2 fails the check group outright and contradicts the schedule, the site list and the flying-window restriction. The flag, `CSCTF{REDACTED}`, is redacted here.
