# Dense-Seven Full-Corpus Helios Adjudication

This directory preserves the complete fixed two-second comparison of the
direct dense-seven CaDiCaL route. It is a rejected candidate, not the current
best Viper configuration.

## Provenance

- run: `20260727T003507Z-fd32ee2d1671-d2b45f5e`
- orchestration revision: `fd32ee2d167103a0a094c998fc6b280f56afe867`
- solver revision: `d2b45f5ea1263476405ca4da7fdeaf92328f1e8f`
- preparation job: `19962547`
- 64-task array: `19962695`
- finalizer: `19962708`
- candidate binary SHA-256:
  `9763f35f343b3d4b6b536a81ef6e6520840e332854117dee5e69c44062084cfc`
- analysis SHA-256:
  `a842d33d3620e0439a165a9a748daf3c4048f3c65cf2d3f20c24adb1f7661218`
- portable audit-index SHA-256:
  `8c39332dc719473e8b8eccc23b718843dccad3b9b8ae0a4a171fe73ef895087e`

The campaign contains 45,018/45,018 expected rows: six solver
configurations over all 7,503 sources. Local replay regenerated the portable
audit index byte-for-byte. There are no wrong answers, execution errors,
missing rows, or hash mismatches.

The first preparation attempt, job `19962244`, exited before measurement
because the dashboard campaign specification was supplied to a runner that
requires the executable comparator-list schema. The corrected submission used
`campaigns/best-overall-qf-uf-2026-07.json`. The failed preparation carries no
performance evidence and is not included here.

## Result

| Solver configuration | Correct solves |
| --- | ---: |
| euf-viper dense-seven candidate | 7,449 |
| Yices2 | 7,490 |
| Z3 default | 7,447 |
| Z3 `sat.euf=true` | 7,461 |
| cvc5 | 7,362 |
| OpenSMT | 7,292 |

Against Yices2, Viper's PAR-2, common-total, and common-geometric factors are
`0.321773x`, `0.316380x`, and `0.389452x`. Against cvc5, the factors are
`1.356612x`, `1.038289x`, and `1.203840x`; the common-total result misses the
registered `1.05x` floor. The global promotion decision is **rejected**.

Compared directly with the frozen dense-six run, Viper changes from 7,458 to
7,449 solves: four gains and thirteen losses, for a net loss of nine. The
common-correct aggregate is `1.008512x` faster, but coverage loss is terminal.
The direct dense-seven route must remain disabled. The next experiment is a
bounded Kissat-first stage followed by CaDiCaL only after an explicit
conflict-budget exhaustion.
