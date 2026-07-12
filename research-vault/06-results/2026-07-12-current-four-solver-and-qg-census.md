# Current Four-Solver And Source-Bound QG Census

Date: 2026-07-12

## Exact Four-Solver Campaign

The accepted chain is prepare `144328`, array `144329`, and merge `144330`.
An earlier chain `144321`/`144322`/`144323` was cancelled after detecting an
incorrect expanded revision label and is not evidence.

- euf-viper revision: `3c178dced8eb44e13a6381bdc43290c71658ac40`
- euf-viper binary SHA-256:
  `808c59ceef559062bb61befea2030b16b890bd18b8936a98d1ea3bc3172903ff`
- manifest SHA-256:
  `32aba287e33c5665847f0a0a71311da6214feb5e69f458877ba02ef96976a2d4`
- corpus: 7,503 SMT-LIB 2025 QF_UF inputs
- timeout: two seconds
- rows: 30,012, with zero wrong answers or execution errors

| Solver | Correct | Median | Timeout total |
| --- | ---: | ---: | ---: |
| euf-viper | 7,408 | 0.00939s | 885.69s |
| Z3 4.16.0 | 7,450 | 0.02199s | 639.66s |
| cvc5 1.3.4 | 7,373 | 0.03061s | 976.53s |
| Yices2 2.7.0 | 7,490 | 0.00504s | 228.56s |

Euf-viper beats cvc5 on coverage, median, full total, common aggregate, and
common geometric speed. Against Z3 it wins common geometric speed `1.5666x`
and 5,602/7,375 timing pairs, but loses common aggregate at `0.7467x`, coverage
by 42, and full total. Against Yices2 it has four unique solves versus 86 and
is `0.3543x` geometrically. This is not overall superiority.

## Source-Bound QG Census

Job `144349` ran from clean Git-backed commit
`9fc09e8a9d6eef4b40330b3e3a70e8817e7d0ed4`.

- source tree: `91acc25dda52f8565e21150d7dcd6de5d7c3fe56`
- source archive SHA-256:
  `9fc95dc7033db0507766293b652ff64d86a315c959b3c257b61429c5c67a13d2`
- wrapper SHA-256:
  `59fb39e7ffe70537da577b8de437cb397b95a0a38b8fe0885e58ed85e094b68a`
- output SHA-256:
  `854360a58ad8246b905ee5d602970750ecffd9e1e2c7b5a739da2f88d8a63950`

The artifact has exactly 419 records: one first provenance record and 418
unique cases. Every source/problem binding is verified.

| Classification | Count |
| --- | ---: |
| Ineligible, fail closed | 387 |
| Eligible shadow witness | 12 |
| Eligible abstention | 19 |
| Shadow refutation | 0 |

Ineligible reasons are 133 unconsumed-assertion cases, 122 non-exact pattern
orbits, 122 rejected pattern families, and 10 duplicate-pattern cases. All 19
eligible abstentions retain a source predicate not handled by the reduction.
`production_routing=false`; no record can answer SMT or change solver coverage.

## Round Disposition

- Bounded Ackermann passes Linux soundness `144317`, but corrected causal gate
  `144631` loses one solve and has `0.9894x` all-case speed. It is rejected.
  Job `144371` remains invalid because its old wrapper omitted mode variables.
- Fused quotient selection is parked at research commit `eae27d0`. All 136 Rust
  tests pass, but paired off-mode timing does not demonstrate a win.
- The paired exact-byte parser evidence harness is parked at research commit
  `58f015b`; 49 tests and 45 subtests pass. It is unmerged and no 7,503-file
  campaign was launched.
- All superseded pending `euf-viper` WMI jobs were cancelled. No solver campaign
  remains active.
