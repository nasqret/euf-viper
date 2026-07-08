# Structural euf-viper/Yices Portfolio

Date: 2026-07-08

Accepted exact-source binary SHA-256:
`2f2b90b94fd05e1b45e4067834a6045f39f2c1b7ddd80b79575ff61f3ffe6ea5`

## Model

`scripts/bench/train_structural_router.py` trained small greedy trees from the
competition-budget result. It uses source bytes, line and parenthesis counts,
maximum nesting depth, and lexical operator counts. Benchmark paths and
`:status` metadata are not features. Five folds are assigned from source
SHA-256.

The selected depth-3, minimum-leaf-50 model had no holdout coverage failures,
routed 55/7,503 holdout observations to `euf-viper`, and projected a 1.0030x
aggregate speedup over Yices. The frozen all-data leaf is:

```text
parentheses <= 1912
and occurrences("(not") <= 7
and occurrences("(declare-fun") <= 18
```

It routes 65 corpus instances to in-process `euf-viper`; all others replace
the current process with the user-supplied Yices binary. Standalone `solve`
behavior is unchanged.

## Target Gate

Build `139905`, array `139907`, and merge `139912` compared the 65 selected
instances at 1,200 seconds:

| Metric | Direct Yices | Portfolio |
|---|---:|---:|
| Correct | 65/65 | 65/65 |
| Total | 367.35s | 147.98s |
| Pairwise wins | 44 | 21 |

Aggregate speedup was 2.482x; geometric speedup was 0.896x. Most of the gain
came from `PEQ018_size7`, which fell from 359.96s to 141.81s.

## Fallback-Overhead Gate

Build `139924`, array `139925`, and merge `139930` ran five repeats on 200
Yices-routed cases. Coverage remained 200/200. Portfolio overhead was about
2.96ms per case: aggregate speed was 0.9486x and geometric speed was 0.8757x
versus direct Yices.

## Full-Corpus Gate

Prototype array `139942` and merge `139947` first established complete coverage
and a 1.0290x aggregate win. After rejecting the streaming follow-up, exact
current-source array `140030` and merge `140035` repeated one paired observation
for every one of the 7,503 SMT-LIB 2025 QF_UF instances at 1,200 seconds. The
64-shard confirmation used at most four allocations and completed in 12m13s;
peak task MaxRSS was 35,800 KiB.

| Metric | Direct Yices | Portfolio |
|---|---:|---:|
| Correct | 7,503 | 7,503 |
| Median | 0.0290s | 0.0334s |
| Total | 1,241.01s | 1,186.49s |
| Pairwise wins | 6,327 | 1,176 |

There were zero wrong answers or execution errors. The portfolio improved
aggregate time by 1.0460x while its median and geometric speed regressed. The
geometric speed was 0.8788x. This is an
aggregate hard-tail win, not a uniform per-instance speedup.

## Rejected Follow-Up

Streaming only enough input to reject the `euf-viper` leaf was tested by build
`140011`, array `140012`, and merge `140017`. On the same 200-case overhead
gate it regressed aggregate speed from 0.9486x to 0.9416x, so the full-read
implementation was restored before exact-source confirmation `140030`.

## Boundary

Accept as an explicit opt-in portfolio. It depends on Yices for complete
coverage and does not establish an independent win over Yices. The model was
trained and fully measured on the same corpus; content-hash cross-validation
is positive but a frozen evaluation on a new benchmark release is still
required before making a generalization claim. Fallback answers inherit the
Yices trust boundary and are not covered by `euf-viper` certificates.
