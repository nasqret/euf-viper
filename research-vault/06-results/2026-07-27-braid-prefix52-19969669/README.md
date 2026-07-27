# Retained-State Braid Prefix Sweep

Date: 2026-07-27

Decision: reject every measured prefix on route-local speed

## Frozen run

- solver revision: `b89c8ebca7f3b60de7f5474bdebc3dc2723204e1`
- preparation job: `19969487`
- failed pre-measurement array: `19969586`
- corrected matrix array: `19969669`
- candidate binary SHA-256: `5b6bcede0c02dbef7d1a92b354e27334c206cf09b653ab595f5a432a92c85882`
- CPU: one physical AMD EPYC 9654 core per task
- timeout: two seconds, parser-inclusive subprocess wall clock
- selection: exact 52-row, 147-binary-application cohort
- schedule: six Williams-balanced repeats for six arms
- observations: 1,872, with zero wrong answers and zero execution errors

The candidate loads CaDiCaL once, runs a bounded prefix, calls Kissat for ten
conflicts only after explicit interruption, and resumes the same CaDiCaL state
if Kissat abstains. Prefix budgets are 0, 10, 100, 1,000, and 10,000 conflicts.

## Audited result

| Arm | Correct | Common total | Aggregate | Geometric | Gains | Losses |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Baseline | 48/52 | 8.513687s | `1.0x` | `1.0x` | - | - |
| Braid 0 | 50/52 | 10.593032s | `0.803706x` | `0.777745x` | 2 | 0 |
| Braid 10 | 50/52 | 11.055131s | `0.770112x` | `0.759033x` | 2 | 0 |
| Braid 100 | 50/52 | 10.854133s | `0.784373x` | `0.767061x` | 2 | 0 |
| Braid 1,000 | 50/52 | 10.396109s | `0.818930x` | `0.792011x` | 2 | 0 |
| Braid 10,000 | 50/52 | 10.339517s | `0.823412x` | `0.790437x` | 2 | 0 |

Every arm gains exactly `gensys_icl002.smt2` and `gensys_icl004.smt2` and
loses no source. Coverage therefore passes, but every speed factor is below
one. No arm advances to full qg7 or the 7,503-source corpus.

## Orchestration incident

Array `19969586` failed before any solver execution because the manually
created experiment namespace omitted the empty `results/` parent required by
the task script. All tasks failed at `mkdir` and produced no raw timing rows.
The namespace is preserved under `failed-premeasurement/`. The corrected run
uses a new immutable namespace and unchanged source, executable, and script
hashes.

## Integrity

- audit self-hash: `65412fbf8facc20b7b7ca2103fb68732b115015b90bbcdd557da8486e9c24635`
- exact `audit.json` SHA-256: `5c4bdcfc0e976eeba800ff5aa74dc68a3ced28d212c355bebf266dfe6e0209f6`
- selector SHA-256: `f8451eb86331f9f236bed3d1c3fb1a6532d37bc3b738746e945c06a4ccf5f681`
- rebased manifest SHA-256: `8caa354aa60b4ba0430b4cd974b2390a9075890a645afc240ae6a911836377e5`
- task script SHA-256: `89be0ea232a6e222a37b5018afddfdc1668465ffa40d020c74497ef18f537bcb`
- sbatch script SHA-256: `acc1272c89114a5443c675c3b50f96560fb7794c94d25b71942be207167a8014`
- runner SHA-256: `22cf14c72e8dc833fa6d6a251e9e911b14e09617e02856caa6474fa5002ab95d`
- toolchain SHA-256: `c4eedb72792e031b6e27ef50580f2ec8e77ccfd651d2d8862045686a8d0cb534`

The archived audit regenerates byte-for-byte from the raw shards.
