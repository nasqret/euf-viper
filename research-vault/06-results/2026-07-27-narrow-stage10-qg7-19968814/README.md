# Narrow Staged-10 qg7 Confirmation

Date: 2026-07-27

Decision: reject for speed; retain the two causal UNSAT gains as a reverse-stage target

## Frozen Run

- solver revision: `bc5f4c37154709a38b70773553bca9f761259d56`
- preparation job: `19968692`
- confirmation array: `19968814`
- candidate binary SHA-256: `989b93eff18d517f6b8b5b71023471886679c28038fa30c9d4126e22ad078f38`
- CPU: one physical AMD EPYC 9654 core per shard
- timeout: two seconds, parser-inclusive subprocess wall clock
- selection: all 418 qg7 sources, 64 round-robin shards
- observations: 1,672, with zero wrong answers and zero execution errors

## Measured Matrix

| Metric | Baseline | Narrow staged-10 |
| --- | ---: | ---: |
| Correct | 378/418 | 381/418 |
| SAT correct | 291 | 292 |
| UNSAT correct | 87 | 89 |
| Common total | 70.6210s | 72.6040s |
| Common aggregate factor | `1.0x` | `0.972687x` |
| Common geometric factor | `1.0x` | `0.970395x` |

The matrix reports three gains and no losses. Two are routed, repeatable UNSAT
gains: `gensys_icl002.smt2` and `gensys_icl004.smt2`. The third,
`iso_brn_nogen_sk014.smt2`, is outside the selector because it has 170 binary
table applications. Its baseline repetitions split SAT/timeout while both
candidate repetitions finished just below two seconds, so it is timeout-
boundary noise and is not credited to the mechanism.

## Selector Attribution

Recombining the measured baseline outside the preregistered 52-row selector
removes that non-causal boundary fluctuation. The routed result is 380/418,
two gains, and no losses. Across all 378 common solves its aggregate/geometric
factors are `0.977533x` and `0.971368x`.

The route itself is more expensive than those broad factors suggest. On the
52 selected rows, baseline covers 48 and staged-10 covers 50. The 48 common
rows take 8.4927s under baseline and 10.1158s under staging: `0.839544x`
aggregate and `0.795511x` geometric. A Kissat-first prefix therefore recovers
the two desired proofs but imposes a large cost on the easy selected mass.

The coverage gate passes, but the speed gate fails. No 7,503-row campaign is
authorized from this candidate. The next implementation should preserve the
two UNSAT gains while avoiding Kissat-first work on easy rows, preferably by a
bounded CaDiCaL-first handoff or an outcome-blind structural difficulty gate.

## Integrity

- matrix audit self-hash: `63386accbf9357688c943c124833dfca17fa001eede9f9a763274b9740189add`
- exact `audit.json` SHA-256: `85cd7813490388b879d16854be47ff1d05e90fb27a9e97f71e1d922a2ddfa746`
- selector attribution self-hash: `89d06e900fab516831c2a30df5686c1c862998b3b97dee46fe875e2d03b3f672`
- exact attribution SHA-256: `53aab375bbf4891312c9505b909b1c2e2676c86be04847916ae3d33a8829fc98`
- source selection SHA-256: `b9f0b5581954cd06577060bfb3b9b835e111f069369c51ac1753d89f81409dbd`
- rebased manifest SHA-256: `deede0b54e3c4f1af733bbd691a6acfe7907751ed9862abbf3af0ca0f669ef63`

Both the matrix audit and selector attribution replay byte-for-byte from this
archive.
