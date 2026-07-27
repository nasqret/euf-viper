# Decision-Gated Proof-Seeding Matrix

Date: 2026-07-27

Decision: reject every arm on common-correct timing; retain the online decision
gate as diagnostic evidence

## Frozen Run

- solver revision: `2d4a372a77fa93e665d5a9c47d53c110dcd887dd`
- preparation test/actual jobs: `19977262` / `19977267`
- matrix test/actual jobs: `19977574` / `19977575`
- candidate binary SHA-256:
  `dcc31a2fbc5360f213e30d0a5fc6f6bff16f7a753c51a4ae1730c5e9f4bc0266`
- CPU: one physical AMD EPYC 9654 core per task
- timeout: two seconds, parser-inclusive subprocess wall clock
- selection: the exact 52-row, 147-binary-application cohort
- schedule: six Williams-balanced repeats for six arms
- observations: 1,872, with zero wrong answers and zero execution errors

After a fixed 100-conflict CaDiCaL Plain prefix, the experiment admits a fresh
70,000-conflict UNSAT-safe sprint only when the observed decision count lies in
the inclusive interval 131 through 150. The five candidate arms differ only in
the maximum length of Plain-prefix learned clauses imported into the sprint:
zero, 4, 8, 16, or 32 literals. Source paths, family labels, expected results,
and prior timing are unavailable to the gate.

## Audited Result

| Arm | Correct | Common total | Aggregate | Geometric | Gains | Losses |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Baseline | 48/52 | 8.330135s | `1.0x` | `1.0x` | - | - |
| Seed 0 | 50/52 | 8.829006s | `0.943496x` | `0.920255x` | 2 | 0 |
| Seed 4 | 50/52 | 8.930015s | `0.932824x` | `0.912486x` | 2 | 0 |
| Seed 8 | 50/52 | 8.870770s | `0.939054x` | `0.917655x` | 2 | 0 |
| Seed 16 | 50/52 | 8.880670s | `0.938008x` | `0.918708x` | 2 | 0 |
| Seed 32 | 50/52 | 8.870216s | `0.939113x` | `0.919948x` | 2 | 0 |

Every gated arm gains exactly `gensys_icl002.smt2` and
`gensys_icl004.smt2`, loses no baseline solve, and reaches the required 50/52
coverage. Clause transfer has no positive effect: the seed-free arm is best on
both timing metrics. Its 5.65% aggregate and 7.97% geometric regressions expose
the remaining cost as the explicit 100-conflict interruption and Rust-level
return before the gate decision, not a missing learned-clause bridge.

No arm advances to complete qg7 or the 7,503-source panel. The next admissible
experiment must decide and disarm the probe inside one uninterrupted CaDiCaL
solve. Nonselected rows must remain on the exact Plain search trajectory; only
selected rows may return to Rust and construct the UNSAT-safe sprint.

## Provenance

Preparation `19977267` completed in 5:22 with 1,356,816 KiB maximum step RSS.
The slowest matrix child completed in 1:47 and the maximum child step RSS was
91,912 KiB. The preparation binds the required `smtlib-2025` source manifest
and content-addressed corpus inventory.

- audit self-hash:
  `92d5e89026bc813f735030dbba31a9bff261982bd69b290a339015879ee5c957`
- exact `audit.json` SHA-256:
  `4113349dac712b77691adb66dc3beb633d6e88272cd13b483fcb4617184b23bf`
- corpus inventory SHA-256:
  `9b39c70a794d52277a4e5d83731f0ebc50a2f3b804eb1dfc8cf32766a5ebeadc`
- preparation manifest SHA-256:
  `f615ae80b80d5a15521e1d285bb2bd9b5a538d64e9237500fcfc6dc2a700a7bf`
- selector SHA-256:
  `f8451eb86331f9f236bed3d1c3fb1a6532d37bc3b738746e945c06a4ccf5f681`
- rebased 52-row manifest SHA-256:
  `8caa354aa60b4ba0430b4cd974b2390a9075890a645afc240ae6a911836377e5`
- task script SHA-256:
  `d03b6dde42cf2ef57d083158bafa572e0d2ab47b26d4f9d87892c997f20e9951`
- matrix sbatch SHA-256:
  `acc1272c89114a5443c675c3b50f96560fb7794c94d25b71942be207167a8014`
- runner SHA-256:
  `22cf14c72e8dc833fa6d6a251e9e911b14e09617e02856caa6474fa5002ab95d`
- toolchain SHA-256:
  `c4eedb72792e031b6e27ef50580f2ec8e77ccfd651d2d8862045686a8d0cb534`

The archived audit regenerates byte-for-byte from the raw shards.
