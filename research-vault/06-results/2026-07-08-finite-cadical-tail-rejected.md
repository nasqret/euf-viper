# Direct CaDiCaL Finite-Tail Route Rejected

Date: 2026-07-08

Target A/B array: `139900`; merge: `139904`

## Hypothesis

Keep the accepted finite-domain clauses unchanged but route the hard finite
tail directly to CaDiCaL instead of the Linux automatic Kissat path.

## Protocol

The same binary and four-instance manifest used for the sequential at-most-one
test ran once per backend with a 120-second timeout. Both configurations used
pairwise finite-domain encoding and the accepted invalid-model fallback.

## Result

| Metric | Auto / Kissat | Direct CaDiCaL |
|---|---:|---:|
| Correct | 0/4 | 0/4 |
| Timeouts | 4 | 4 |
| Timeout-inclusive total | 480.4649s | 480.4643s |

There were no wrong answers or execution errors. The 1.0000x aggregate ratio
is timeout noise.

## Decision

Reject. SAT-backend selection alone does not remove the proof-complexity wall
on these formulas. Do not add a hard-tail CaDiCaL router from this evidence.
