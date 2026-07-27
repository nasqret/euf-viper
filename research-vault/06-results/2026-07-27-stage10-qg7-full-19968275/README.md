# Staged-10 Complete qg7 Gate

Date: 2026-07-27

Decision: reject broad staging; retain a narrow post-hoc hypothesis for fresh
confirmation

## Measured Result

Helios array `19968275` ran 64 one-core AMD EPYC 9654 shards over all 418 qg7
sources. Baseline and staged-10 used the same revision-`e9fef17` binary,
SHA-256 `68855954be123c4cac0cab81b4c0594f23492bc313334a7aaf06b7986a182a9d`.
Two complete Williams repetitions per source produced 1,672 parser-inclusive
observations at a two-second timeout.

| Metric | Baseline | Staged-10 |
| --- | ---: | ---: |
| Correct | 380/418 | 374/418 |
| SAT correct | 294 | 286 |
| UNSAT correct | 86 | 88 |
| Common correct | 372 | 372 |
| Common total time | 65.7912s | 70.0434s |
| Common aggregate factor | `1.0x` | `0.939291x` |
| Common geometric factor | `1.0x` | `0.711269x` |

Staging gains UNSAT `gensys_icl002.smt2` and `gensys_icl004.smt2`. It loses SAT
`iso_brn_nogen_sk{006,007,008,009,016,017,018,020}.smt2`. With zero wrong
answers and zero execution errors, the six-solve net regression is a terminal
rejection of the broad route.

## Structural Projection

The attached 418/418 finite census finds 52 rows with the existing dense-seven
signature and at most 147 binary table applications. Both gains and no losses
lie there. The first loss appears at 154 applications. Recombining measured
staged observations only on those 52 rows projects:

| Metric | Baseline | Projected hybrid |
| --- | ---: | ---: |
| Correct | 380/418 | 382/418 |
| Gains / losses | - | 2 / 0 |
| Common aggregate factor | `1.0x` | `0.978319x` |
| Common geometric factor | `1.0x` | `0.970901x` |

This is post-hoc discovery on exposed outcomes, not an independently measured
candidate. `structural-projection.json` says so explicitly. The narrowed code
must be rebuilt at a clean revision and repeat the complete qg7 gate before any
full-corpus run.

## Integrity

- source selection SHA-256: `b9f0b5581954cd06577060bfb3b9b835e111f069369c51ac1753d89f81409dbd`
- rebased manifest SHA-256: `deede0b54e3c4f1af733bbd691a6acfe7907751ed9862abbf3af0ca0f669ef63`
- matrix audit self-hash: `58a586225621c55d85041b655dbefc72af25bbd4bc81ffff669c0ea6509f6c85`
- exact `audit.json` SHA-256: `2b0f63f81ee1e120fb9f68d71ff7c0ef6926fee4bf60092da94be65461b3effc`
- census SHA-256: `cc3722b3aaca4b3bc77452232e4fc29ea3bdd604fceaea883c073c5cae5a044c`
- 52-row selector manifest SHA-256: `f8451eb86331f9f236bed3d1c3fb1a6532d37bc3b738746e945c06a4ccf5f681`
- projection self-hash: `6c0cb0e458cadad953d4c10c2f98472688f50481f1609d6c0d2f6f5418c3eab0`
- exact `structural-projection.json` SHA-256: `c95a7163cf5c84d4f4d0b48558ca5b4ee55447e75ed79da3b8046a31f3d01dd5`
