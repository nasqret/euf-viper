# Finite-Domain Cap Experiment Rejected

Date: 2026-07-08

Build job: `139736`

A/B array: `139766`; corrected merge: `139775`

## Hypothesis

The eager finite-domain detector stops at domain size 8. Raise the opt-in cap
to 11 and test whether the one-hot encoding solves PEQ sizes 9-11 that generic
EUF leaves in the hard tail.

## Protocol

The baseline and candidate used the same isolated binary and `auto` backend.
Only the finite-domain maximum differed: 8 versus 11. Four expected-UNSAT PEQ
instances ran once per configuration with a 120-second timeout:

- `PEQ014_size9`
- `PEQ014_size10`
- `PEQ014_size11`
- `PEQ018_size7` as an in-cap control

## Result

| Metric | Cap 8 | Cap 11 |
|---|---:|---:|
| Correct | 0/4 | 0/4 |
| Timeouts | 4 | 4 |
| Total | 480.50s | 480.77s |

There were no wrong answers or execution errors. Timeout-inclusive speedup was
0.9994x, slightly favoring the baseline. Peak task memory remained below the
8 GiB allocation, so this is a search failure rather than an OOM result.

## Decision

Reject and remove the knob. A larger copy of the same one-hot encoding does
not solve the proof-complexity problem. Revisit these instances only with a
different encoding, symmetry breaking, pseudo-Boolean reasoning, or a lazy
route.
