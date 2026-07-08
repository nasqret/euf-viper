# Root-Level Pigeonhole Detector Rejected

Date: 2026-07-08

Initial A/B array: `139798`; merge: `139799`

Corrected profile build: `139873`; profile: `139875`

## Hypothesis

After finite-domain clauses are emitted, root-level Boolean propagation might
expose `n + 1` finite terms that are pairwise disequal over an `n`-element
domain. Detecting that clique would allow an immediate UNSAT result without a
resolution proof of the one-hot encoding.

## Result

The 69-instance tail A/B preserved coverage at 9/69 versus 9/69. Candidate
timeout-inclusive total was 3,823.19s versus 3,826.03s, only a 1.0007x change.
There were no wrong answers or complementary solves.

That first build did not normalize duplicate literals during root propagation,
so a corrected implementation was profiled before interpreting the small
timing movement. Job `139875` tested five representative hard instances. One
did not enter finite-domain routing; all four eligible instances reported
`profile_finite_pigeonhole ... count=0`. Detector overhead ranged from 63 ms to
486 ms.

## Decision

Reject and remove the detector. The 1.0007x aggregate movement was noise, the
shortcut did not fire on the target family, and its preprocessing cost was
measurable. A future symmetry or cardinality pass must first demonstrate that
its structural predicate matches real corpus instances.
