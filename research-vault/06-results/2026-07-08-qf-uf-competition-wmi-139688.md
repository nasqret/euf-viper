# QF_UF Competition-Budget WMI Campaign 139688

Date: 2026-07-08

Revision: `1f68ff1cb5f1c9ee951f181a6127427b2e6d3044`

Prepare: `139688`; array: `139689`; strict merge: `139690`

## Protocol

The campaign continued the 60-second run at a 1,200-second per-instance
budget. It retained 22,457 successful comparator rows from run `139420`,
reran all 7,503 `euf-viper` rows because the solver revision changed, and
reran 52 comparator timeout rows. The 64-shard array allowed at most four
active allocations with eight worker processes per shard.

The prepare-to-merge interval was 2h53m51s. Peak shard MaxRSS was 5,190,532
KiB. All 30,012 merged solver-instance rows passed strict completeness checks,
with zero wrong answers, execution errors, or decisive disagreements.

Pinned comparators were Z3 4.16.0, cvc5 1.3.4, and Yices 2.7.0.

## Results

| Solver | Correct | Coverage | Median | Timeout-inclusive total |
|---|---:|---:|---:|---:|
| euf-viper | 7,478 | 99.67% | 0.0910s | 50,674.22s |
| Z3 4.16.0 | 7,500 | 99.96% | 0.1426s | 11,435.55s |
| cvc5 1.3.4 | 7,491 | 99.84% | 0.2293s | 27,875.21s |
| Yices 2.7.0 | 7,503 | 100.00% | 0.0278s | 2,652.64s |

`euf-viper` converted 44 of its 69 prior timeouts and left 25. The remaining
set contains five Goel hardware instances, six NEQ, ten PEQ, and four SEQ
instances; 24 are expected UNSAT and one is expected SAT.

All four solvers cover every one of the 6,396 QG-classification instances. On
the 1,107 non-QG instances, coverage is 1,082 for `euf-viper`, 1,104 for Z3,
1,095 for cvc5, and 1,107 for Yices.

## Pairwise Interpretation

On 7,478 common `euf-viper`/Z3 solves, `euf-viper` wins 3,878 instances versus
3,600 and has a 1.069x geometric speedup. The tail reverses the aggregate:
common-correct totals are 20,668.55s for `euf-viper` and 5,365.05s for Z3. Z3
has 22 additional solves and `euf-viper` has none.

Against Yices, `euf-viper` wins 626 of 7,478 common solves; Yices wins 6,852,
has a 4.525x geometric advantage, and covers all 25 `euf-viper` gaps. Yices is
the unique solver for `PEQ013_size8`, `PEQ014_size11`, and `PEQ016_size7`.

The oracle portfolio covers all 7,503 instances, with Yices fastest on 6,821,
`euf-viper` on 612, Z3 on 62, and cvc5 on 8.

## Boundary

This campaign rejects any overall faster-or-more-complete claim against Z3 or
Yices. The supported claim is narrower: `euf-viper` is a low-overhead front
tier with a small geometric advantage over Z3 on common solved instances, but
its hard tail dominates aggregate cost. Further performance work must add
cross-term finite-model reasoning or a portfolio fallback rather than tuning
the existing one-hot SAT path.
