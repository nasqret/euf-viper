# PGO Routing And Long-Timeout Frontier

Date: 2026-07-10

Status: global PGO rejected; PGO router not promoted; exact 60-second and
1,200-second campaigns complete.

## Fixed Baseline

Every experiment in this note uses standalone source `58efe9d` and the frozen
WMI binary with SHA-256
`4d5431135c95a2c528d287efd2803eaf895a5ec526c9642a570797b02fd47eb7`.
The remote checkout is
`/home/bnaskrecki/euf-viper-scoped-let-58efe9d`. No typed-parser experiment is
part of these results.

## Profile-Guided Build

An LLVM instrumentation build was trained on 512 deterministic corpus cases.
The disjoint 512-case holdout used source-SHA folds and contained no training
path. The merged profile SHA-256 was
`3fda8462670049381b5f5df6e0fb11799ca9bb8bb4a4ff3343dd406679ec6546`;
the PGO binary SHA-256 was
`c5c6148d40a83e5138eb6c5ca5173b289a31d90726cd224a25d5128eafb9efcf`.

The unconditionally selected PGO binary failed the holdout gate:

| Instances | Coverage | All-total | Common-total | Geometric | Baseline-only |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 512 | 480 -> 476 | 0.9964x | 0.9945x | 1.0203x | 4 |

The build improves most short paths but regresses enough long paths to lose
both coverage and aggregate time. Global PGO is rejected.

## Structural PGO Router

`scripts/bench/train_binary_router.py` aggregates repeated A/B rows by median,
extracts only lexical numeric features, and trains small threshold trees. The
allowed feature set is:

`bytes`, `lines`, `parens`, `max_depth`, `asserts`, `declarations`, `sorts`,
`lets`, `ands`, `ors`, `nots`, `ites`, `distincts`, `equalities`, and
`implications`.

Path, family, expected status, solver outcomes, and timing values are forbidden
as runtime features. Source SHA-256 is used only to assign stable validation
folds. A cross-validation result is valid only if it routes at least one case
to the candidate, preserves every baseline solve, introduces no wrong-answer
route, and has all three speed ratios strictly above one:

$$
\rho_{\mathrm{all}} = \frac{\sum_i t_i^B}{\sum_i t_i^R},\qquad
\rho_{\mathrm{common}} =
\frac{\sum_{i\in C}t_i^B}{\sum_{i\in C}t_i^R},
$$

$$
\rho_{\mathrm{geo}} =
\exp\left(\frac{1}{|C|}\sum_{i\in C}
\log\frac{t_i^B}{t_i^R}\right).
$$

Five-fold validation on the 512-case holdout selected depth 4 and minimum leaf
size 16:

| Routed to PGO | Coverage | All-total | Common-total | Geometric |
| ---: | ---: | ---: | ---: | ---: |
| 74/512 | 480 -> 480 | 1.00040x | 1.00075x | 1.00407x |

All five folds individually preserved coverage and had all three ratios above
one. Training on all 512 cases produced the single effective rule
`equalities <= 579 -> PGO`, routing 33 cases. The frozen rule was then applied
without retraining to the independent 40-case control:

| Routed to PGO | Coverage | All-total | Common-total | Geometric |
| ---: | ---: | ---: | ---: | ---: |
| 3/40 | 39 -> 39 | 1.00010x | 1.00016x | 1.00245x |

This is a reproducible signal, but not an operational win. The projected
all-time margins are smaller than realistic launcher or full-file prescan
overhead. No runtime router is promoted. The useful conclusion is narrower:
PGO should be retrained for a structurally isolated in-process Rust path, not
selected through a second process.

## Exact 60-Second Campaign

Prep `143248`, array `143249`, and merge `143254` resumed only timeout rows
from the exact two-second campaign. All 30,012 solver observations are present;
there are no wrong answers, decisive disagreements, execution errors, or
failed shards.

| Solver | Correct | Timeouts | Median | Timeout-charged total |
| --- | ---: | ---: | ---: | ---: |
| euf-viper | 7,478 | 25 | 0.0471s | 5,930.09s |
| Z3 4.16.0 | 7,490 | 13 | 0.1285s | 3,998.14s |
| cvc5 1.3.4 | 7,473 | 30 | 0.1888s | 7,752.73s |
| Yices 2.7.0 | 7,500 | 3 | 0.0243s | 1,307.54s |

Pairwise ratios below are comparator time divided by euf-viper time, so values
above one favor euf-viper:

| Comparator | Common | Viper only | Comparator only | Common-total | Geometric | Viper wins |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Z3 | 7,466 | 12 | 24 | 0.7233x | 1.8883x | 5,811 |
| cvc5 | 7,450 | 28 | 23 | 1.3582x | 2.7176x | 6,269 |
| Yices2 | 7,475 | 3 | 25 | 0.2290x | 0.4110x | 462 |

The hard-tail conclusion is now direct. Euf-viper beats Z3 on most shared
instances and has a much better geometric ratio, but its few slow cases reverse
the aggregate result. Yices2 dominates both the easy head and the tail. The
four-solver oracle solves all 7,503 instances; euf-viper is uniquely correct on
`PEQ014_size11.smt2` and `PEQ018_size7.smt2` at this timeout.

## Competition-Budget Resume

The exact 1,200-second continuation is prep `143382`, array `143383`, and merge
`143384`. It resumed run `143248` with `retry_results=timeout`, so only the 71
timeout observations executed. All 64 shards and the strict merge completed.

Coverage is 7,502 euf-viper, 7,500 Z3, 7,495 cvc5, and 7,503 Yices2. Full
timeout-charged totals are 8,575.78s, 8,676.80s, 19,511.55s, and 2,010.00s,
respectively. Euf-viper therefore narrowly exceeds Z3 on coverage and the full
timeout-charged metric, but loses common-solve aggregate time at `0.6939x`.
Yices2 remains complete and about `4.27x` faster by full total.

The measured binary has the separately confirmed Boolean-as-data soundness
defect. These are valid exact-corpus timings with zero observed mismatches, not
a general superiority claim. Full details are in
`2026-07-11-qf-uf-1200s-143382.md`.

## Artifacts

- `results/wmi/pgo-holdout512-143265/structural-router-cv.json`.
- `results/wmi/pgo-sample40-143302/structural-router-independent.json`.
- `results/wmi/four-solver-60s-143248/`, containing 326 campaign files and the
  exact manifest.
- `results/wmi/four-solver-1200s-143382/`, containing 330 campaign files,
  strict merge logs, metadata, and merged analysis.
- Merged CSV SHA-256:
  `f255208a70c7af4ef34039a577ba6642002397097ef3bb8ac73041293b980863`.
- Merged analysis SHA-256:
  `679e9b6367c4e58385aa39cd61800f24241a76897f04806a82b8eae59958705d`.
- Manifest SHA-256:
  `2ab1041d877d65befb41d5c7ae0c942a970bc4266aa37167dc8a77ec91bd2acf`.

## Decision

Do not enable global PGO and do not build an external-process PGO router. Keep
source `58efe9d` as the production baseline. Use the 1,200-second result to
classify the remaining standalone tail, then target mechanisms that change its
proof system rather than another global code-layout tweak.
