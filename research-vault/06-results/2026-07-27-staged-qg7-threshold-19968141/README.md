# Staged qg7 Threshold Matrix

Date: 2026-07-27

Decision: select 10 conflicts for the complete qg7 gate; no promotion

## Contract

Helios array `19968141` ran six single-core AMD EPYC 9654 shards over the exact
36 qg7 rows solved by Yices2 but not the current Viper baseline. Every arm used
the same revision-`e9fef17` binary, SHA-256
`68855954be123c4cac0cab81b4c0594f23492bc313334a7aaf06b7986a182a9d`.
The six-arm Williams schedule contains six complete repetitions per source,
for 1,296 parser-inclusive observations at a two-second timeout.

Direct dense-seven routing was disabled in every arm. The only treatment was
the bounded Kissat conflict budget before explicit UNKNOWN and CaDiCaL
fallback.

| Arm | Correct / 36 | Coverage gain |
| --- | ---: | ---: |
| baseline | 0 | 0 |
| staged-0 | 1 | +1 |
| staged-10 | 2 | +2 |
| staged-100 | 1 | +1 |
| staged-1000 | 0 | 0 |
| staged-10000 | 0 | 0 |

There are zero wrong answers and zero execution errors. The two staged-10 gains
are `gensys_icl002.smt2` and `gensys_icl004.smt2`. Because the reference solves
none of this residual, timing comparison is undefined; this experiment chooses
a threshold only.

## Integrity

- selection SHA-256: `7f6beb21bf96fb891ef4b8d135172ca1e2239bd9c8232cabd01cd76fe2bf77ca`
- rebased manifest SHA-256: `89a36835154ab9a1f406d9aa2ec4b8dc6ce62b6720c75ffd40cb3c1f91c865cd`
- audit self-hash: `3d2248b066a8e70db9a8816f77305431ef6f8b6ee832186a95d8295255e09983`
- exact `audit.json` SHA-256: `042bf853435c42bfc9c4452a44e67f4028d4c8a24ce7894b6b570311dedf54f5`

`scripts/bench/audit_multiarm_matrix.py` verifies the selection/manifest pair,
round-robin shards, receipts, CPU and tool controls, source and executable
hashes, complete schedules, raw CSV hashes and row counts, and the full path
union before recomputing this audit.
