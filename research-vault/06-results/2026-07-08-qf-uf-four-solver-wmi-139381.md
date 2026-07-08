# Full QF_UF Four-Solver Campaign 139381

Date: 2026-07-08

Revision: `e65ccd9fb8a0dd477d41bf4e70938259a306a044`

Corpus: SMT-LIB 2025 QF_UF, 7,503 instances

Budget: 2 seconds per solver-instance, 8 concurrent processes

WMI job: `139381`, completed in 28m02s, MaxRSS 1,007,880 KiB

## Final table

| Solver | Correct | Coverage | Timeouts | Median | Total |
|---|---:|---:|---:|---:|---:|
| euf-viper | 6,471 | 86.25% | 1,032 | 0.0886s | 3,668.11s |
| Z3 4.16.0 | 6,911 | 92.11% | 592 | 0.1705s | 3,494.35s |
| cvc5 1.3.4 | 6,505 | 86.70% | 998 | 0.2956s | 4,909.17s |
| Yices 2.7.0 | 7,394 | 98.55% | 109 | 0.0450s | 1,169.43s |

All 30,012 solver-instance rows completed. There were zero wrong answers,
execution errors, or decisive solver disagreements.

## Pairwise timing

On the 6,437 instances solved correctly by both `euf-viper` and Z3,
`euf-viper` won 5,428, had a 1.834x geometric speedup, and used 1,551.48s
versus 1,711.39s. This is the defensible fast-head result.

On the 6,463 instances solved correctly by both `euf-viper` and Yices, Yices
won 6,166 and used 456.60s versus 1,577.97s. Yices is approximately 3.46x
faster by paired total and also solves 923 more corpus instances.

## Corpus strata

QG-classification contains 6,396/7,503 instances (85.24%).

| Stratum | Solver | Correct | Coverage | Median | Total |
|---|---|---:|---:|---:|---:|
| QG | euf-viper | 5,512 | 86.18% | 0.0887s | 3,193.37s |
| QG | Z3 | 5,895 | 92.17% | 0.1699s | 2,986.14s |
| QG | cvc5 | 5,576 | 87.18% | 0.2991s | 4,201.50s |
| QG | Yices2 | 6,326 | 98.91% | 0.0465s | 982.06s |
| non-QG | euf-viper | 959 | 86.63% | 0.0876s | 474.74s |
| non-QG | Z3 | 1,016 | 91.78% | 0.1839s | 508.21s |
| non-QG | cvc5 | 929 | 83.92% | 0.2526s | 707.67s |
| non-QG | Yices2 | 1,068 | 96.48% | 0.0377s | 187.37s |

## Interpretation

The Yices comparison changes the claim. The current solver is not a plausible
overall fastest QF_UF solver. Its publishable position is a faster-than-Z3
front tier on common easy instances with explicit certificate architecture,
followed by a portfolio fallback. The 60-second and competition-budget runs
must quantify whether that niche survives when the tail gets more time.
