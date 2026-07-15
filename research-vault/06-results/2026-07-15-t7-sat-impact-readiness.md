# T7 SAT-Impact Explanation Falsifier Readiness

Date: 2026-07-15

This checkout contains a research-only T7 opportunity falsifier based on frozen
revision `6e402f0a9595bd3f9c1ba99ea193bf237474d9f7`. It does not implement
vivification and is not a production solver port.

## Implemented Boundary

- `EUF_VIPER_T7_EXPLANATION=off|on` is strict and forces
  `cadical-rollback`; unset retains the frozen route.
- Both arms reconstruct and replay the same bounded four-forest candidate pool,
  score every candidate, and select only from the shared minimum-width subset.
- Candidate, selector, timing, SAT, theory, model-check, duplicate, and replay
  evidence is buffered into a chain-hashed transcript.
- The independent transcript checker reconstructs the base CNF, checks every
  EUF clause, directly checks SAT models, and can require DRAT evidence for each
  distinct UNSAT base-CNF plus selected-suffix key.
- The fresh 24-source manifest builder binds the exact T2 selection and records
  that no missing historical manifest was reused.
- The one-pass gate permits ABBA work only after at least two exact M3 sources
  expose a replay-valid minimum-width selector disagreement.

## Execution State

The opportunity gate, 4-source canary, and 24-source comparison have not been
run. This worktree does not contain the exact three M3 source files or a full
source manifest from which the hash-bound T7 manifest can be built. The correct
state is therefore `not evaluated`, not `ready` or `stop`.

Once those inputs are present, the allowed sequence is:

1. Build and source-verify a fresh 24-row manifest.
2. Run the exact M3 one-pass opportunity gate and stop unless its report says
   `ready` with at least two qualifying sources.
3. Run the 4-source, 2-arm, 4-repeat ABBA canary with required UNSAT proofs.
4. Run the 24-source, 2-arm, 4-repeat contract only after the canary passes.

No broad corpus, publication, remote scheduling, or WMI action belongs to this
falsifier implementation.
