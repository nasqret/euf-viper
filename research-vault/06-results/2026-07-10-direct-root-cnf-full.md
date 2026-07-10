# Direct-Root CNF Full-Corpus Gate

Date: 2026-07-10

Status: accepted and promoted as the default encoding. Set
`EUF_VIPER_DIRECT_ROOT_CNF=0` for an exact rollback to Tseitin root units.

## Candidate

- Implementation commit: `10cf9c0`.
- Promotion commit: `50edc7d`.
- Frozen portable binary SHA-256:
  `3dfc120e318bf0d3b0d1071edefdb2e63bd86c701d428424ff45122f29e240ea`.
- Both A/B arms used that binary. The only decision variable was
  `EUF_VIPER_DIRECT_ROOT_CNF=0|1`.

The candidate recursively emits clauses that assert each top-level formula
directly instead of creating a Tseitin variable and then adding a root unit.
Nested subformulas still use the normal atom table and sound CNF rules.

## Gates

| Gate | Instances | Timeout/repeats | Coverage | All-total | Common-total | Geometric |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Hot `142549` | 400 | 2s / 3 | 396 -> 397 | 1.015x | 1.016x | 1.018x |
| Finite tail `142554`/`142562` | 20 | 2s / 3 | 20 -> 20 | 0.993x | 0.993x | 0.983x |
| Full `142591`/`142596` | 7,503 | 2s / 1 | 6,825 -> 6,843 | 1.006x | 1.010x | 1.026x |

The full gate had 41 candidate-only and 23 baseline-only timeout-boundary
solves, for a net coverage gain of 18. It had 4,915 candidate timing wins and
1,887 baseline wins on 6,802 common correct instances. There were zero wrong
answers and zero execution errors.

The 20-case finite slice was a real local regression, but the predeclared
decision experiment was the complete corpus. The full result passed coverage,
timeout-charged total, common-total, and geometric gates. The hot gate and full
gate also ran on different WMI CPU classes.

## Soundness And Certificates

Three-atom exhaustive differential tests cover nested Boolean formulas and
atom-free constants under both encodings. SAT answers retain complete EUF model
validation, and eager UNSAT uses a logically equivalent CNF.

Certificate generation reconstructs its own proof CNF and does not depend on
the runtime direct-root setting. The all-feature test suite passed after the
default changed.

## Artifacts

- Hot gate: `results/wmi/direct-root-v1-hot-142549/`.
- Clean finite gate: `results/wmi/direct-root-v1-tail-142554/`.
- Full gate: `results/wmi/direct-root-v1-full-142591/`.
- Ranked full-corpus follow-ups:
  `results/wmi/direct-root-v1-full-142591/opportunities.json`.

## Decision

Promote direct-root CNF globally. Keep the strict `0|1` environment switch for
reproduction and rollback. Re-evaluate only if a later combined full-corpus
candidate loses one of the accepted metrics.
