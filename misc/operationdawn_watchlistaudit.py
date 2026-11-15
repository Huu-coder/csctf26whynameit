# Third-party solver from the CSCTF 2026 archive (authorship unknown); flags redacted here if present.
import hashlib
import io
import zipfile

import numpy as np


with zipfile.ZipFile('watch-list-audit.zip') as archive:
    history = np.loadtxt(io.BytesIO(archive.read('history.csv')), delimiter=',', skiprows=1)
    probes = np.loadtxt(io.BytesIO(archive.read('probes.csv')), delimiter=',', skiprows=1)

x = np.column_stack((np.ones(len(history)), history[:, :10]))
y = history[:, 10]
px = np.column_stack((np.ones(len(probes)), probes))

# Eleven parameters (intercept plus ten weights) need eleven independent rows.
matches = []
for cut in range(11, len(history) - 10):
    before = np.linalg.lstsq(x[:cut], y[:cut], rcond=None)[0]
    after = np.linalg.lstsq(x[cut:], y[cut:], rcond=None)[0]
    error = max(np.max(abs(x[:cut] @ before - y[:cut])),
                np.max(abs(x[cut:] @ after - y[cut:])))
    if error < 1e-10:
        matches.append((cut, after, error))

assert len(matches) == 1, 'Expected one identifiable deployment boundary'
cut, coefficients, error = matches[0]
assert np.linalg.matrix_rank(x[:cut]) == np.linalg.matrix_rank(x[cut:]) == 11
q = np.floor(1000 * (px @ coefficients) + 0.5).astype(np.int64)

# Independent halves of the latest deployment must predict the same integers.
mid = (cut + len(history)) // 2
for segment in (slice(cut, mid), slice(mid, None)):
    fitted = np.linalg.lstsq(x[segment], y[segment], rcond=None)[0]
    assert np.linalg.matrix_rank(x[segment]) == 11
    assert np.max(abs(x[cut:] @ fitted - y[cut:])) < 1e-10
    assert np.array_equal(q, np.floor(1000 * (px @ fitted) + 0.5).astype(np.int64))

payload = ''.join(f'{value}\n' for value in q).encode('ascii')
print(f'Deployment change after observation {cut}; max residual {error:.3g}')
print('Quantized scores:', q.tolist())
print('CSCTF{REDACTED}')
