# Third-party solver from the CSCTF 2026 archive (authorship unknown); flags redacted here if present.
import sys

import numpy as np


with np.load(sys.argv[1] if len(sys.argv) > 1 else "dispatch-authenticator.npz",
             allow_pickle=False) as model:
    bias = model["update_b1"]
    row = np.argmax(np.abs(bias))
    assert bias[row] != 0, "No nonzero bias gradient"
    x = model["update_W1"][row] / bias[row]
    values = np.rint(x * 255)
    assert np.all((values >= 0) & (values <= 255)), "Input is not byte-valued"
    np.testing.assert_allclose(x * 255, values, rtol=0, atol=1e-10)

    # Check the decoded bytes against the forward pass and every saved gradient.
    x = values / 255
    hidden = np.maximum(model["global_W1"] @ x + model["global_b1"], 0)
    logits = model["global_W2"] @ hidden + model["global_b2"]
    delta2 = np.exp(logits - logits.max())
    delta2 /= delta2.sum()
    delta2[int(model["label"])] -= 1
    delta1 = (model["global_W2"].T @ delta2) * (hidden > 0)
    for name, expected in {
        "logits": logits,
        "update_W1": np.outer(delta1, x),
        "update_b1": delta1,
        "update_W2": np.outer(delta2, hidden),
        "update_b2": delta2,
    }.items():
        np.testing.assert_allclose(model[name], expected, rtol=1e-10, atol=1e-12)

    print(bytes(values.astype(np.uint8)).decode("ascii"))
