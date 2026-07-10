# Full QF_UF Four-Solver Campaign 143049

Date: 2026-07-10

Status: complete. This is the current exact-binary two-second comparator
checkpoint. It confirms a fast common-solve head against Z3, but not coverage
or overall superiority; Yices2 remains decisively ahead.

## Frozen Configuration

- Corpus: SMT-LIB 2025 QF_UF, 7,503 instances.
- Prepare/array/merge: `143049`/`143051`/`143052`.
- Timeout: 2 seconds per solver and instance.
- Shards: 64, at most four active; eight worker processes per shard.
- euf-viper source: `58efe9d`.
- euf-viper SHA-256:
  `4d5431135c95a2c528d287efd2803eaf895a5ec526c9642a570797b02fd47eb7`.
- Z3: pinned 4.16.0 wrapper.
- cvc5: pinned 1.3.4 Linux static release.
- Yices2: pinned 2.7.0 static-GMP release.

The euf-viper binary contains promoted direct-root CNF and scoped-let `auto`.
Equality abstraction facts and finite permutation support were off. The Linux
invalid-model path used its production `cadical-refine` default.

## Coverage And Latency

| Solver | Correct | Coverage | Median | Timeout-charged total |
| --- | ---: | ---: | ---: | ---: |
| euf-viper | 6,948 | 92.60% | 0.0471s | 2,327.84s |
| Z3 | 7,176 | 95.64% | 0.1285s | 2,245.09s |
| cvc5 | 6,926 | 92.31% | 0.1888s | 3,188.03s |
| Yices2 | 7,434 | 99.08% | 0.0243s | 748.96s |

All 30,012 observations completed. There were zero wrong answers, solver
disagreements, or execution errors.

## Paired Comparisons

| Pair | Common | euf-only | Other-only | euf aggregate | euf geometric |
| --- | ---: | ---: | ---: | ---: | ---: |
| euf-viper vs Z3 | 6,907 | 41 | 269 | 1.119x | 2.083x |
| euf-viper vs cvc5 | 6,774 | 174 | 152 | 1.705x | 2.929x |
| euf-viper vs Yices2 | 6,944 | 4 | 490 | 0.289x | 0.438x |

Thus euf-viper is faster than Z3 on the common solved set and has 41 unique
two-second solves, but Z3 adds 228 net solves and has a smaller
timeout-charged total. Yices2 is about 3.46x faster by common aggregate time,
2.28x faster geometrically, and adds 486 net solves.

## Family Boundary

| Family | Instances | euf-viper | Z3 | Yices2 |
| --- | ---: | ---: | ---: | ---: |
| QG-classification | 6,396 | 5,932 | 6,133 | 6,353 |
| Goel hardware | 773 | 728 | 753 | 773 |
| NEQ | 48 | 33 | 31 | 37 |
| PEQ | 47 | 24 | 27 | 35 |
| SEQ | 56 | 48 | 49 | 53 |

The solver now beats Z3 coverage on NEQ but still loses the large QG stratum,
Goel, PEQ, and SEQ. The Yices gap is broad rather than one isolated family.

## Relation To Campaign 142480

The previous checkpoint solved 6,874 for euf-viper, 7,123 for Z3, 6,831 for
cvc5, and 7,420 for Yices2. The new campaign increases those counts by 74, 53,
95, and 14 respectively. Because this is not a same-binary paired A/B run,
those raw deltas include run and machine-boundary effects and are not assigned
entirely to scoped-let routing. The separate same-binary full gate
`142952`/`142996` is the causal evidence for that route (+30 solves).

## Artifacts

Complete ignored artifacts are under `results/wmi/four-solver-143049/`:

- merged CSV/JSON and pairwise/family analysis;
- 64 shard CSV/JSON/progress triplets;
- all prepare, array, and merge SLURM logs;
- solver-version and corpus-fetch logs;
- exact campaign metadata.

## Decision

Keep the fast-head claim against Z3 on common solves. Do not claim overall Z3
or Yices2 superiority. The next accepted standalone binary must rerun this
campaign after guarded equality routing; long-timeout 60-second and
1,200-second campaigns remain mandatory.
