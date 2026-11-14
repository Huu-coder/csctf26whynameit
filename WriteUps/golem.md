### Golem — GASM interpreter

> Misc · Easy · Iulian Schifirnet
> Points at solve: [fill in]

**Tools used**

Python 3 (custom GASM interpreter script).

**Approach**

The audit service presented 100 short programs for a 16-register virtual machine and required the exact output stream for each one.

1. The attachment contained `SPEC.md` and `examples.txt`. The specification described 16-bit unsigned registers, modular arithmetic, tape input, output, and nested `rep`/`ifz`/`ifn` blocks. The worked examples covered the edge cases, including division/modulo by zero and exhausted input.
2. An interpreter was written that parses blocks into a nested representation and executes them with 16-bit masking on register writes.
3. For each service round, the script read the program and tape, evaluated the program, and sent the space-separated output values. Run it with:

```sh
python3 -I /home/kali/csctf2026/scripts/golem_solve.py <instance> 42145
```

**Why it works**

The challenge is a deterministic VM, so implementing the specified GASM semantics exactly — including 16-bit register masking and the documented zero-edge cases — reproduces the required output stream for every program, allowing all rounds to be answered automatically.

Remediation: this is a deterministic interpreter exercise and there is no service-side vulnerability to remediate. For real interpreters, validate instruction operands and bound execution resources even when the language is intended to be safe.

**Validation**

The interpreter passed all supplied examples, and the service accepted all 100 answers, returning the flag.
