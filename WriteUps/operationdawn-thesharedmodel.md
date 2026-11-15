# Operation Dawn — The Shared Model

**Category:** Reverse engineering / Misc

**Flag:** `CSCTF{REDACTED}`

## Overview

The supplied `dispatch-authenticator.npz` contains a neural network's parameters,
saved logits and label, and arrays named `update_W1`, `update_b1`, `update_W2`,
and `update_b2`. The first layer has 50 inputs and 64 hidden units; the output
layer has eight classes.

This writeup follows the overview and walkthrough style of the
[CSCTF challenge compendium](https://github.com/ChronosPK/CSCTF-2025-challenges/blob/main/README.md).
Its README does not describe this challenge; the solution below was derived and
verified against the supplied artifact.

## Solution walkthrough

### 1. Recognize the gradient leak

For a dense layer `z = W @ x + b`, backpropagation gives:

```text
dL/dW[i, j] = delta[i] * x[j]
dL/db[i]    = delta[i]
```

For a single training example, dividing any nonzero bias-gradient row out of
the weight gradient reveals the entire input:

```python
row = np.argmax(np.abs(model["update_b1"]))
x = model["update_W1"][row] / model["update_b1"][row]
```

Choosing the largest absolute bias gradient avoids division by zero and reduces
numerical sensitivity. A common learning-rate multiplier would cancel too.

### 2. Decode the input

The recovered values are byte values normalized by 255. Multiplying by 255 and
rounding gives the first bytes `67, 83, 67, 84, 70, 123`, or `CSCTF{`.
Decoding all 50 bytes yields:

```text
CSCTF{REDACTED}
```

### 3. Verify the reconstruction

The recovered input reproduces the saved logits using a ReLU hidden layer.
Backpropagating softmax cross-entropy with the saved label also reproduces all
four update arrays, confirming that they are single-example gradients. In the
initial numerical check, the largest logit error was about `1.45e-15`, and every
gradient error was below `9e-16`.

Run the accompanying solver with Python and NumPy installed:

```bash
python3 solve.py dispatch-authenticator.npz
```

The solver checks byte normalization, the forward pass, and all saved gradients
before printing the flag. No training or brute force is needed: the first-layer
gradient already exposes the input.

Validation is local; the flag has not been submitted to a challenge server.
