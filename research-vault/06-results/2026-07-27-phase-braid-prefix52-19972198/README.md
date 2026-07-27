# Lazy CaDiCaL Phase-Braid Sweep

Date: 2026-07-27

Decision: reject every arm on coverage and speed

## Frozen run

- solver revision: `823342079a7dca7095b88728b4e97af9979bc3cb`
- preparation test/actual jobs: `19971629` / `19971632`
- matrix test/actual jobs: `19972197` / `19972198`
- candidate binary SHA-256:
  `4ec0fb87ce1745b7ed73b60663a7451facfd00ddfff34a4149d7e2bb7bcb0fff`
- CPU: one physical AMD EPYC 9654 core per task
- timeout: two seconds, parser-inclusive subprocess wall clock
- selection: the same exact 52-row, 147-binary-application cohort
- schedule: six Williams-balanced repeats for six arms
- observations: 1,872, with zero wrong answers and zero execution errors

The candidate runs a bounded baseline-Plain CaDiCaL prefix. Only after an
explicit interruption does it lazily build a second UNSAT-configured CaDiCaL
solver for a 70,000-conflict sprint. If the sprint abstains, it resumes the
original Plain solver with its learned state intact. Prefix budgets are 0, 10,
100, 1,000, and 10,000 conflicts.

## Audited result

| Arm | Correct | Common total | Aggregate | Geometric | Gains | Losses |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Baseline | 48/52 | 8.724650s | `1.0x` | `1.0x` | - | - |
| Prefix 0 | 48/52 | 11.829395s | `0.737540x` | `0.726381x` | 0 | 0 |
| Prefix 10 | 49/52 | 12.296532s | `0.709521x` | `0.709376x` | 1 | 0 |
| Prefix 100 | 49/52 | 11.325078s | `0.770383x` | `0.769612x` | 1 | 0 |
| Prefix 1,000 | 48/52 | 9.599277s | `0.908886x` | `0.895842x` | 0 | 0 |
| Prefix 10,000 | 48/52 | 9.550745s | `0.913505x` | `0.900413x` | 0 | 0 |

Prefixes 10 and 100 gain only `gensys_icl002.smt2`; no arm gains both target
proofs. `gensys_icl004.smt2` reaches UNSAT in five of six repeats for prefixes
0 and 100, but one strict wall-clock timeout makes each arm uncovered. The
target therefore sits at the process deadline rather than below it robustly.
Increasing the sprint budget cannot repair the common-time regression.

No arm reaches the mandatory 50/52 coverage, and every arm fails both timing
gates. No arm advances to complete qg7 or the 7,503-source corpus.

## Provenance

This preparation uses the required tracked source manifest
`smtlib-2025/qf_uf_manifest.jsonl`. Its rebased SHA-256 is
`f615ae80b80d5a15521e1d285bb2bd9b5a538d64e9237500fcfc6dc2a700a7bf`,
and the content-addressed corpus inventory is
`9b39c70a794d52277a4e5d83731f0ebc50a2f3b804eb1dfc8cf32766a5ebeadc`.
Unlike the preceding Plain-braid preparation, this run is eligible to continue
the broad panel if its solver gate passes. The solver gate does not pass.

Preparation `19971632` completed in 6:34 with 1,505,528 KiB peak step RSS.
The slowest matrix task completed in 1:58 with 101,752 KiB peak step RSS.

## Integrity

- audit self-hash:
  `5f69a5ab8574ff495d72ad8b56517c64855fc48e367dea7fa66a597ed62732a1`
- exact `audit.json` SHA-256:
  `31029892df6a3ecaa003319ab10b5ec432595552f2692a361e8bd11aba78980a`
- selector SHA-256:
  `f8451eb86331f9f236bed3d1c3fb1a6532d37bc3b738746e945c06a4ccf5f681`
- rebased 52-row manifest SHA-256:
  `8caa354aa60b4ba0430b4cd974b2390a9075890a645afc240ae6a911836377e5`
- task script SHA-256:
  `c61622308d3979b97501f06a6e4a2906db046aa0b50daf579fe5a2f2ce84eb97`
- sbatch script SHA-256:
  `acc1272c89114a5443c675c3b50f96560fb7794c94d25b71942be207167a8014`
- runner SHA-256:
  `22cf14c72e8dc833fa6d6a251e9e911b14e09617e02856caa6474fa5002ab95d`
- toolchain SHA-256:
  `c4eedb72792e031b6e27ef50580f2ec8e77ccfd651d2d8862045686a8d0cb534`

The archived audit regenerates byte-for-byte from the raw shards.
