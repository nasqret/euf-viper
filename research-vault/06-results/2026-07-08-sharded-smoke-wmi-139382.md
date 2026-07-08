# WMI Sharded Campaign Smoke 139382

Date: 2026-07-08

Revision: `0bb34c210957022f0e72a812f8c6f5f344d322f4`

Remote checkout: `~/euf-viper-sharded-smoke-0bb34c2`

## Dependency chain

| Stage | Job | State | Elapsed |
|---|---:|---|---:|
| prepare | 139382 | completed | 3m10s |
| array shard 0 | 139383_0 | completed | 8s |
| array shard 1 | 139383_1 | completed | 6s |
| strict merge | 139384 | completed | 6s |

The immutable campaign manifest contained eight deterministically sampled
instances. Each shard wrote checkpointed raw CSV and summary files. The merge
found exactly 32 solver-instance rows and reported no duplicates, omissions,
wrong answers, solver disagreements, or execution errors.

## Results

| Solver | Correct | Median | Total |
|---|---:|---:|---:|
| euf-viper | 7/8 | 0.0711s | 2.6581s |
| Z3 4.16.0 | 7/8 | 0.1605s | 3.2869s |
| cvc5 1.3.4 | 7/8 | 0.2256s | 4.4694s |
| Yices 2.7.0 | 7/8 | 0.0408s | 2.3013s |

This is an infrastructure smoke, not comparative evidence. Its acceptance
criterion was complete and internally consistent artifacts across the full
prepare-array-merge chain.
