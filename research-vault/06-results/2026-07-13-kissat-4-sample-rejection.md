# Kissat 4.0.4 Sample Rejection

Date: 2026-07-13

Status: rejected at the preregistered sample gate; broad timing did not run

## Decision

Do not replace the namespaced SAT Competition 2021 Kissat backend with
Kissat 4.0.4 unconditionally. The corrected same-CNF sample preserved coverage
and correctness but regressed paired end-to-end timing. Dependent broad job
`145906` and merge `145907` were cancelled automatically after sample job
`145905` returned the rejected gate status.

This result rejects the wholesale backend swap. It does not evaluate every
individual Kissat pass. Any congruence, sweeping, factor/BVA, vivification, or
phase experiment must be a new frozen same-binary causal ablation and may not
weaken or reinterpret this gate.

## Provenance

- Campaign revision: `45ba12c6d0933e6b5b14d744a5602ed172c45a57`
- Hosted campaign-contract run: `29274065472`, passed
- Validation job: `144945`
- SC2021 binary SHA-256: `d7321602...c70362`
- Kissat 4.0.4 binary SHA-256: `ecbcfebb...ea6b6`
- Source manifest: 7,503 rows, SHA-256 `32aba287...a2d4`
- Deterministic 64-row sample SHA-256: `2aaa3809...fa24`
- Sample job: `145905`, `COMPLETED` runner followed by rejected gate exit `1`
- Node and affinity: `c1n2`, CPU `6`, one allocated core
- Budget: 2 seconds; one warmup and three measured repeats per arm
- Candidate/base environments: identical
- Wrong answers: zero
- Execution errors: zero

The failed predecessor `145884` produced no timing evidence because inherited
absolute source paths named another checkout. Commit `45ba12c` rebound every
source from its hash-checked `relative_path`; job `145905` is the first valid
causal performance result.

## Result

| Metric | Kissat 4.0.4 / SC2021 |
| --- | ---: |
| Correct coverage | `53/64 -> 53/64` |
| Paired instance medians | 53 |
| Wins / losses / ties | `16 / 37 / 0` |
| Geometric speedup | `0.928694x` |
| Geometric 95% interval | `[0.868663, 0.970203]` |
| Common-total speedup | `0.963416x` |
| Common-total 95% interval | `[0.941532, 0.980834]` |
| Median speedup | `0.973994x` |
| All-total speedup | `0.9819x` |
| One-sided sign-flip p-value | `0.999500` |

Ratios are baseline over candidate, so values below one favor SC2021. The
sample required geometric, common-total, and median speedups of at least
`0.95`, including bootstrap lower bounds. Geometric point/lower-bound and
common-total lower-bound checks failed. Coverage, timeout policy, wrong-answer,
execution-error, pairing, and median checks passed.

## Artifacts

Remote immutable root:

`/home/bnaskrecki/euf-viper-campaigns/45ba12c6d093-kissat4-paired/results/kissat4-paired-145905/sample`

Local fetched archive:

`results/wmi/kissat4-sample-145905/`

The bound `result.json`, `promotion.json`, `summary.json`, `paired.csv`, sample
manifest, environment files, and script hashes are retained there. The result
artifact binds every child SHA-256; `promotion.json` SHA-256 is
`83d89bd8...70ae`.

## Next Action

Stop T0 wholesale promotion. Spend architecture budget on the broad mechanisms
that can change the Yices2 ranking: rollback EUF after its adapter repair,
typed parser/formula staging, adequate-range Hall/PB, component quotient cost
projection, and the theory-conditioned Boolean DAG. Generic Kissat passes are
controls for those mechanisms, not the primary novelty claim.
