# Third-party solver from the CSCTF 2026 archive (authorship unknown); flags redacted here if present.
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
