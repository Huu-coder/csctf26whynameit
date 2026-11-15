---
title: Telltale
ctf: Chronos Security 2026 (directory label)
date: 2026-11-07
category: misc
difficulty: easy (estimated)
points: unknown
flag_format: "CSCTF{...}"
author: unknown
---

# Telltale

## Summary
The supplied mono PCM WAV contains Manchester-encoded digital data. Thresholding the waveform and sampling each half-bit recovers the flag.

## Solution
The WAV is 16-bit mono at 48 kHz. A threshold of 14000 isolates the pulse train; transitions are separated by 24 or 48 samples. Thus each half-bit lasts 24 samples and the data rate is 1000 bits/second. Starting at sample 12000, each pair of half-bits has opposite levels. Taking the second level gives the data bits, packed most-significant-bit first.

The packet starts with eight 0xAA preamble bytes, 0x7E, then 0x30 (the 48-byte flag length). The decoder checks these framing properties and finds exactly one flag in the recovered packet. The supplied corpus consists of this single WAV.

Run `python3 solve.py` with Python 3 and NumPy:

```python
import re
import wave
from pathlib import Path
import numpy as np

with wave.open('telltale.wav') as wav:
    assert (wav.getnchannels(), wav.getsampwidth(), wav.getframerate()) == (1, 2, 48000)
    samples = np.frombuffer(wav.readframes(wav.getnframes()), dtype='<i2')
levels = samples > 14000
edges = np.flatnonzero(np.diff(levels.astype(int))) + 1
assert set(np.diff(edges)) == {24, 48}
halves = levels[np.arange(edges[0] - 12, edges[-1], 24)]
assert len(halves) % 2 == 0
assert np.all(halves[::2] != halves[1::2])
packet = np.packbits(halves[1::2]).tobytes()
flags = re.findall(rb'CSCTF\{[^}]+\}', packet)
assert len(flags) == 1
assert packet[:9] == b'\xaa' * 8 + b'\x7e'
assert packet[9] == len(flags[0])
Path('decoded.bin').write_bytes(packet)
print(flags[0].decode())
```

## Flag

```
CSCTF{REDACTED}
```

Validated locally against Manchester pairs and packet framing. No platform submission was performed; the trailing byte was not interpreted.
