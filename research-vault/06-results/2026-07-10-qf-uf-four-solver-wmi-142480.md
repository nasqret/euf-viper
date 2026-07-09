# Full QF_UF Four-Solver Campaign 142480

Date: 2026-07-10

Campaign revision: `d9fe1edd8b36d50af9c07bc248e453f598974d2d`

`euf-viper` binary SHA-256:
`e262a27d93e63c9073ba721fb6097344ee645fc98ad1134b3dd166f18bc610ab`

Corpus: SMT-LIB 2025 QF_UF, 7,503 instances

Budget: 2 seconds per solver-instance, 64 shards, at most 4 shards active,
8 solver processes per shard

WMI jobs: prepare `142480`, array `142481`, strict merge `142482`

## Integrity

- Complete observations: `30,012/30,012`.
- Wrong answers: `0`.
- Execution errors: `0`.
- Decisive solver disagreements: `0`.
- Failed array tasks: `0`.
- The preparation job checked the exact prebuilt binary SHA-256.

## Final Table

| Solver | Correct | Coverage | Timeouts | Median | Timeout-charged total |
| --- | ---: | ---: | ---: | ---: | ---: |
| euf-viper | 6,874 | 91.62% | 629 | 0.0532s | 2,562.49s |
| Z3 4.16.0 | 7,123 | 94.94% | 380 | 0.1353s | 2,485.35s |
| cvc5 1.3.4 | 6,831 | 91.04% | 672 | 0.2106s | 3,508.39s |
| Yices 2.7.0 | 7,420 | 98.89% | 83 | 0.0265s | 831.23s |

`euf-viper` now has higher coverage than cvc5 and a much lower median than Z3
and cvc5. Z3 retains a 249-solve coverage lead, which is enough to make its
timeout-charged total 1.031x better despite losing strongly on common solves.
Yices2 still leads both the head and the tail.

## Pairwise Results

### euf-viper versus Z3

- Common correct: `6,833`.
- euf-viper-only: `41`.
- Z3-only: `290`.
- Common totals: `1,247.93s` versus `1,386.40s`.
- euf-viper common-total speedup: `1.1110x`.
- euf-viper geometric speedup: `2.0353x`.
- Pairwise wins: `5,628` versus `1,205`.

This is a strong and direct faster-than-Z3 result on common solved instances.
The remaining obstacle to an overall Z3 win is coverage, not common-instance
speed.

### euf-viper versus cvc5

- Common correct: `6,684`.
- euf-viper-only: `190`.
- cvc5-only: `147`.
- Common totals: `1,126.54s` versus `1,946.01s`.
- euf-viper common-total speedup: `1.7274x`.
- euf-viper geometric speedup: `2.9364x`.
- Pairwise wins: `5,920` versus `764`.

At this timeout, euf-viper beats cvc5 in coverage, median, common aggregate,
geometric speed, and timeout-charged total.

### euf-viper versus Yices2

- Common correct: `6,865`.
- euf-viper-only: `9`.
- Yices2-only: `555`.
- Common totals: `1,282.50s` versus `357.80s`.
- euf-viper common-total ratio: `0.2790x`; Yices2 is `3.5844x` faster.
- euf-viper geometric ratio: `0.4155x`; Yices2 is `2.4069x` faster.
- Pairwise wins: `332` versus `6,533`.

The nine euf-viper-only solves show real complementarity, but they do not
offset Yices2's broad speed and coverage advantage.

## Consequences For The Research Program

1. Beating Z3 overall is plausible if the 290 Z3-only cases can be attacked
   without losing the current common-instance advantage.
2. Beating Yices2 requires both a roughly 2x head reduction and a new tail
   engine; low-level optimization alone is insufficient.
3. The finite-symmetry path is valuable because it contributes unique solves,
   but the 555 Yices-only cases require structural classification before the
   next solver architecture is chosen.
4. The next long-timeout campaign must rerun exactly the current euf-viper
   binary while preserving comparator rows, with retry semantics recorded.
5. The direct-root CNF experiment should first target the common-solve head;
   native Hall/`AllDifferent` and IPASIR-UP target the two distinct coverage
   deficits.

## Evidence

Ignored local artifacts:

- `results/wmi/four-solver-142480/qf-uf-corpus-142480.csv`
- `results/wmi/four-solver-142480/qf-uf-corpus-142480.json`
- `results/wmi/four-solver-142480/qf-uf-corpus-142480-analysis.json`
- `results/wmi/four-solver-142480/qf-uf-campaign-142480.json`

No general superiority claim is accepted from this run. The supported claim is
that euf-viper is faster than Z3 and cvc5 on common solved instances at two
seconds, beats cvc5 overall at that timeout, and still trails Z3 in coverage
and Yices2 in both speed and coverage.
