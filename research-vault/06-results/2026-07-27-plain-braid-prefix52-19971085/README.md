# Plain Retained-State Braid Sweep

Date: 2026-07-27

Decision: reject every Plain-prefix arm on coverage and speed

## Frozen run

- solver revision: `9f86254110883ab751a88e24cdca0cb58eda15da`
- preparation test/actual jobs: `19970723` / `19970724`
- matrix test/actual jobs: `19971084` / `19971085`
- candidate binary SHA-256: `5af908d1e39c1f56d16c0ec75706e3ffe457cae55245eb8ffa29ae4b63c8a32d`
- CPU: one physical AMD EPYC 9654 core per task
- timeout: two seconds, parser-inclusive subprocess wall clock
- selection: the same exact 52-row, 147-binary-application cohort
- schedule: six Williams-balanced repeats for six arms
- observations: 1,872, with zero wrong answers and zero execution errors

The candidate runs a bounded CaDiCaL Plain prefix, gives Kissat ten conflicts
only after interruption, and resumes the same Plain solver if Kissat abstains.
Prefix budgets are 0, 10, 100, 1,000, and 10,000 conflicts.

## Audited result

| Arm | Correct | Common total | Aggregate | Geometric | Gains | Losses |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Baseline | 48/52 | 8.597050s | `1.0x` | `1.0x` | - | - |
| Plain 0 | 48/52 | 9.652787s | `0.890629x` | `0.863136x` | 0 | 0 |
| Plain 10 | 48/52 | 9.865897s | `0.871391x` | `0.845856x` | 0 | 0 |
| Plain 100 | 48/52 | 9.766187s | `0.880287x` | `0.863259x` | 0 | 0 |
| Plain 1,000 | 48/52 | 9.481570s | `0.906712x` | `0.887639x` | 0 | 0 |
| Plain 10,000 | 48/52 | 9.347763s | `0.919691x` | `0.895778x` | 0 | 0 |

No arm gains `gensys_icl002.smt2` or `gensys_icl004.smt2`, and every arm
fails both timing gates. This proves that the gains in the preceding sweep came
from resumed UNSAT-configured CaDiCaL, not from the bounded Kissat interlude.
No arm advances to complete qg7 or the 7,503-source corpus.

## Preparation manifest incident

The binary build is exact and independently hash-bound by the matrix, but its
preparation lock used tracked source manifest `smtcomp-2025/qf_uf_manifest.jsonl`
(SHA-256 `ed00b0e2...aaa6`, rebased as `1d55f007...6847`) instead of the prior
campaign's `smtlib-2025/qf_uf_manifest.jsonl` (`9c509b0f...08db`, rebased as
`f615ae80...a7bf`). Both resolve to corpus inventory `9b39c70a...eadc`.
Therefore preparation `19970724` is valid build provenance for this independent
matrix but is not eligible as a continuation of the broad competitor panel.

## Integrity

- audit self-hash: `edc65c5ddaf207c775ef8c16fe44acd4b0af29c7bdc3d49f28f14c7fccb195aa`
- exact `audit.json` SHA-256: `ec2cce94bc3e60704841f66d872369650a38fe1a1a6eb25c53b325037e12480e`
- selector SHA-256: `f8451eb86331f9f236bed3d1c3fb1a6532d37bc3b738746e945c06a4ccf5f681`
- rebased 52-row manifest SHA-256: `8caa354aa60b4ba0430b4cd974b2390a9075890a645afc240ae6a911836377e5`
- task script SHA-256: `89be0ea232a6e222a37b5018afddfdc1668465ffa40d020c74497ef18f537bcb`
- sbatch script SHA-256: `acc1272c89114a5443c675c3b50f96560fb7794c94d25b71942be207167a8014`
- runner SHA-256: `22cf14c72e8dc833fa6d6a251e9e911b14e09617e02856caa6474fa5002ab95d`
- toolchain SHA-256: `c4eedb72792e031b6e27ef50580f2ec8e77ccfd651d2d8862045686a8d0cb534`

The archived audit regenerates byte-for-byte from the raw shards.
