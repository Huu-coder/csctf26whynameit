# Watch List Audit — Misc

**Flag:** `CSCTF{REDACTED}`

## Overview

The ZIP contains 500 chronological observations in `history.csv` and 32 inputs in
`probes.csv`. Each score is an intercept plus a weighted sum of ten features.
Exactly one deployment change occurred, and the latest rule applies to the probes.
There is no added measurement noise.

## Solution

Append a column of ones to the feature matrix to fit the intercept alongside the
ten weights. Try each split with at least 11 observations on either side, fitting
two independent linear models with `numpy.linalg.lstsq`. Check their residuals
against the corresponding history segments.

The unique split with maximum absolute residual below `1e-10` is **209**:
observations 1–209 use the old rule, and 210–500 use the latest rule. The maximum
residual is approximately `9.77e-15`, consistent with floating-point rounding.
For comparison, splitting at 208 leaves a maximum residual of about `0.139`.
Both fitted matrices have full rank, so the coefficients are identifiable.

Apply the latest model to the probes in their original order. Quantize each score
using `floor(1000 * score + 0.5)`—including negative scores. This gives:

```text
-6601, -4919, -4288, 3009, 5755, 14714, 1364, -2462,
8499, -6223, -8083, 2257, 8517, -6836, -2970, 9814,
948, 8346, -7808, -6608, -4755, 10249, -4631, 6878,
-5717, -9458, -8243, 4831, -8337, 569, -3425, -4477
```

Serialize these as ASCII decimal integers, one per line, with an LF after **every**
integer, including the last. The commas above are only for display. SHA-256 of
those bytes is the flag digest.

## Reproduce

With Python 3 and NumPy installed, run from this directory:

```bash
python3 solve.py
```

The solver reads the ZIP directly, locates the boundary, and prints the flag.
As a stability check, it separately fits each half of the latest deployment:
both fits reproduce the entire latest segment and yield the same quantized vector.
The nearest prediction is about `0.00858` away from a rounding boundary in scaled
score units, comfortably above the observed numerical errors.

## Reference

Writeup organization follows the overview / walkthrough / reproduction style of
the [CSCTF 2025 challenge compendium](https://github.com/ChronosPK/CSCTF-2025-challenges/blob/main/README.md).
Its README does not contain this adapted challenge; the solution above is derived
from the supplied `watch-list-audit.zip`. The local brief credits the original
numerical history to Terminal43, Operation Dawn, and the adaptation to Marin Radu.
