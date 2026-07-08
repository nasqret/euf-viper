# Sequential At-Most-One Encoding Rejected

Date: 2026-07-08

Build: `139888`

Target A/B array: `139894`; merge: `139898`

## Hypothesis

Replace each pairwise at-most-one constraint in finite-domain one-hot encoding
with the propagation-complete Sinz sequential encoding. Its extension
variables can shorten resolution proofs that are difficult in the direct
pairwise encoding.

## Protocol

The candidate was opt-in and used the same binary, backend selection, and
CaDiCaL invalid-model fallback as the baseline. Four expected-UNSAT hard-tail
instances ran once per encoding with a 120-second timeout:

- `NEQ023_size7`
- `NEQ048_size8`
- `PEQ018_size7`
- `SEQ005_size8`

The implementation had an exhaustive unit test over every primary assignment
of a four-literal at-most-one constraint before the WMI run.

## Result

| Metric | Pairwise | Sequential |
|---|---:|---:|
| Correct | 0/4 | 0/4 |
| Timeouts | 4 | 4 |
| Timeout-inclusive total | 480.4604s | 480.4609s |

There were no wrong answers or execution errors. The 1.0000x aggregate ratio
contains no evidence of improvement.

## Decision

Reject and remove the encoding option. Sequential per-term at-most-one clauses
do not address the cross-term proof structure in these finite-model formulas.
