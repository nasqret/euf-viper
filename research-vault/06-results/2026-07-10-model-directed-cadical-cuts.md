# Model-Directed CaDiCaL Cuts

Date: 2026-07-10

Status: explicit refinement strategy retained default-off; automatic replacement
of dynamic Ackermannization rejected.

## Hypothesis

The existing CaDiCaL refinement path generates and groups a heuristic pool of
congruence clauses before solving. A smaller alternative is to keep one
incremental CaDiCaL instance, validate each complete Boolean model with the
explaining congruence closure, and add only the novel clauses that reject an
invalid EUF model.

Each cut is the negation of a set of SAT literals sufficient to derive a
forbidden equality. It is therefore an EUF consequence. No fresh equality
variables are introduced, and a SAT result is accepted only after complete EUF
validation.

## Implementation

- Commit: `ecbab83`.
- Runtime mode: `EUF_VIPER_REFINEMENT_MODE=current|model-cuts`.
- Default: `current`.
- Portable candidate source is included in focused binary SHA-256
  `29326f8773bfe68386b37c753041e7b55e20c1d8cc81d86be74a808b077a427d`.
- Validation: 51 all-feature Rust tests at the implementation commit; 52 after
  the independent focused finite-policy test was added.

Telemetry separates SAT calls, validation time, generated/added/duplicate
cuts, widths, and avoided candidate/group clauses. Duplicate or no-progress
rounds abstain and fall back; the round cap never accepts an unvalidated model.

## Explicit Refinement Gate

Gate `142586` used 35 hard Goel instances, a 10-second timeout, three repeats,
and the same binary in both arms. Both arms forced
`EUF_VIPER_BACKEND=cadical-refine`; only the refinement mode changed.

| Metric | Current | Model cuts | Change |
| --- | ---: | ---: | ---: |
| Correct | 12 | 12 | 0 |
| All-total speed | - | - | 1.0019x |
| Common-total speed | - | - | 1.0132x |
| Geometric speed | - | - | 1.0156x |
| Pairwise wins | 3 | 9 | +6 |

There were no wrong answers, execution errors, or coverage-only cases. This is
enough to retain the implementation as an explicit experimental strategy, but
not enough to promote it broadly.

## Automatic Routing Rejection

Gate `142628` compared the real automatic routes on the same 35 files. Both
arms used `auto` plus CaDiCaL invalid-model fallback. The baseline retained the
current dynamic Ackermann route; the candidate selected model cuts and thereby
suppressed dynamic completion.

| Metric | Dynamic/current | Model cuts | Change |
| --- | ---: | ---: | ---: |
| Correct | 16 | 12 | -4 |
| All-total speed | - | - | 0.8830x |
| Common-total speed | - | - | 0.9867x |
| Geometric speed | - | - | 0.9885x |

The candidate lost `frogs.1`, `frogs.4`, `hanoi.2`, and `v_Unidec`, all
`ab_br_max` instances. There were no candidate-only solves or wrong answers.

## Decision

- Keep `current` as the default and preserve dynamic full Ackermannization.
- Keep `model-cuts` available for explicit experiments and as the complete-model
  reference path for a future partial-trail external propagator.
- Do not run a full-corpus promotion gate for this routing policy.
- The next architectural step is a rollback e-graph attached inside CDCL; a
  complete-model loop cannot recover the lost four Goel proofs by merely
  emitting fewer clauses.

Raw ignored artifacts are in `results/wmi/model-cuts-goel-hard-142586/` and
`results/wmi/model-cuts-auto-goel-hard-142628/`.
