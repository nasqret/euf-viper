# EUF Campaign Scorecard

- Campaign: `euf-world-leader-2026-07`
- Candidate: `euf-viper` at `8368d21de96eec77f3bb5f6820c11d1363d3041b`
- Source registry: `euf-viper-world-leader-progress` (`0d6ef9625e53a01b9f5bf61912aa73fc874e1e1ce83821232b0cf4d7319ba6f9`)
- Broad current-route baseline: **AVAILABLE**. At least one complete verified broad whole-corpus panel is available.
- Selected panels: 13 (187 excluded; claim boundaries are not pooled)

## Victory Gates

| Gate | State | Evidence | Reason |
|---|---:|---|---|
| V0 | **UNKNOWN** | `panel-07e69f4abc38cc0e`, `panel-0f3e537b85853559`, `panel-11b52e27d3604d98`, `panel-168b065ccb0389ce`, `panel-19275909c33ff08d`, `panel-2e1e2403bc884402`, `panel-2fd70bb629f8b487`, `panel-3e5c463cd01acad0`, `panel-4123cee98a4f3257`, `panel-4d5d09f822121064`, `panel-5bf9f54563dfae67`, `panel-6387fd1864146f38`, `panel-6a1104e0474213a6`, `panel-6de4979a366aed69`, `panel-78222df7cdcbb8d5`, `panel-7a64fb2ce67123fe`, `panel-855e9752a433555d`, `panel-86f8222ce9c1fbe8`, `panel-92b37e0cee865cc7`, `panel-92d6e75920d3e24f`, `panel-95189c7f7e3f0e51`, `panel-c6943e6f8a21960a`, `panel-cadbdf60dae050ca`, `panel-cce4ebc63bc3a66e`, `panel-ddf2b002f5ecc0a3`, `panel-e3ac265e08610cea` | Dashboard model v1 does not attest independent model/proof checks, hash drift, or missing-row audits. |
| V1 | **UNKNOWN** | none | Missing complete verified exact-candidate all-comparator panels: smtcomp-2025-qf-uf@0.05s, smtcomp-2025-qf-uf@0.2s, smtcomp-2025-qf-uf@2s, smtcomp-2025-qf-uf@24s, smtcomp-2025-qf-uf@60s, smtcomp-2025-qf-uf@1200s |
| V2 | **FAIL** | `panel-cce4ebc63bc3a66e` | Viper loses coverage on smtlib-2025-full at 2 s. |
| V3 | **FAIL** | `panel-cce4ebc63bc3a66e` | cvc5 ratio is 1.02573 for common_total on smtlib-2025-full@2s; 1.05 is required. |
| V4 | **UNKNOWN** | none | Dashboard model v1 contains no RSS, instruction, or cache metrics. |
| V5 | **UNKNOWN** | none | Dashboard model v1 does not attest CPU classes or sealed-holdout status. |
| V6 | **UNKNOWN** | none | Dashboard model v1 contains no independent proof/model checks or novelty ablation record. |

Overall `best_overall_QF_UF_solver` state: **FAIL**.

## Broad Whole Corpus: SMT-LIB 2025 QF_UF full

`panel-500b5f5f1cba2726` | revision `30828a4f0c1e7e478a9c6f406ccb245eeefc4961` | status `verified` | family `all` | expected `all` | timeout `2s` | host `wmi-locked-x86-64` | class `audited-staged-locked`

Instances: 7503; complete: `true`; leader solves: 7445.

| Solver | Solved | Coverage | PAR2 (s) |
|---|---:|---:|---:|
| cvc5 (`cvc5`) | 7222 | 96.25% | 0.370182 |
| Viper (`euf-viper`) | 7269 | 96.88% | 0.284089 |
| OpenSMT (`opensmt`) | 6916 | 92.18% | 0.505144 |
| Yices2 (`yices2`) | 7445 | 99.23% | 0.0813753 |
| Z3 default (`z3-default`) | 7412 | 98.79% | 0.209545 |
| Z3 sat.euf (`z3-sat-euf`) | 7395 | 98.56% | 0.237811 |

| Competitor | Metric | Common solved | Ratio | Signed | Required Viper reduction |
|---|---|---:|---:|---:|---:|
| cvc5 (`cvc5`) | par2 | 7165 | 1.30305 | +30.31% | 0.00% |
| cvc5 (`cvc5`) | common total | 7165 | 1.42511 | +42.51% | 0.00% |
| cvc5 (`cvc5`) | common geometric | 7165 | 2.51992 | +151.99% | 0.00% |
| OpenSMT (`opensmt`) | par2 | 6879 | 1.77812 | +77.81% | 0.00% |
| OpenSMT (`opensmt`) | common total | 6879 | 1.86642 | +86.64% | 0.00% |
| OpenSMT (`opensmt`) | common geometric | 6879 | 1.73187 | +73.19% | 0.00% |
| Yices2 (`yices2`) | par2 | 7261 | 0.286444 | -71.36% | 71.36% |
| Yices2 (`yices2`) | common total | 7261 | 0.251488 | -74.85% | 74.85% |
| Yices2 (`yices2`) | common geometric | 7261 | 0.517074 | -48.29% | 48.29% |
| Z3 default (`z3-default`) | par2 | 7243 | 0.737606 | -26.24% | 26.24% |
| Z3 default (`z3-default`) | common total | 7243 | 0.898977 | -10.10% | 10.10% |
| Z3 default (`z3-default`) | common geometric | 7243 | 1.6573 | +65.73% | 0.00% |
| Z3 sat.euf (`z3-sat-euf`) | par2 | 7231 | 0.8371 | -16.29% | 16.29% |
| Z3 sat.euf (`z3-sat-euf`) | common total | 7231 | 1.03295 | +3.30% | 0.00% |
| Z3 sat.euf (`z3-sat-euf`) | common geometric | 7231 | 1.90269 | +90.27% | 0.00% |

## Broad Whole Corpus: SMT-LIB 2025 QF_UF full

`panel-cce4ebc63bc3a66e` | revision `8368d21de96eec77f3bb5f6820c11d1363d3041b` | status `verified` | family `all` | expected `all` | timeout `2s` | host `helios-epyc-9654` | class `audited-build-once-sharded-locked`

Instances: 7503; complete: `true`; leader solves: 7490.

| Solver | Solved | Coverage | PAR2 (s) |
|---|---:|---:|---:|
| cvc5 (`cvc5`) | 7364 | 98.15% | 0.178151 |
| Viper (`euf-viper`) | 7436 | 99.11% | 0.140919 |
| OpenSMT (`opensmt`) | 7289 | 97.15% | 0.255699 |
| Yices2 (`yices2`) | 7490 | 99.83% | 0.0423575 |
| Z3 default (`z3-default`) | 7446 | 99.24% | 0.107313 |
| Z3 sat.euf (`z3-sat-euf`) | 7459 | 99.41% | 0.11132 |

| Competitor | Metric | Common solved | Ratio | Signed | Required Viper reduction |
|---|---|---:|---:|---:|---:|
| cvc5 (`cvc5`) | par2 | 7339 | 1.26421 | +26.42% | 0.00% |
| cvc5 (`cvc5`) | common total | 7339 | 1.02573 | +2.57% | 0.00% |
| cvc5 (`cvc5`) | common geometric | 7339 | 1.22566 | +22.57% | 0.00% |
| OpenSMT (`opensmt`) | par2 | 7278 | 1.81451 | +81.45% | 0.00% |
| OpenSMT (`opensmt`) | common total | 7278 | 1.58239 | +58.24% | 0.00% |
| OpenSMT (`opensmt`) | common geometric | 7278 | 0.968037 | -3.20% | 3.20% |
| Yices2 (`yices2`) | par2 | 7429 | 0.300581 | -69.94% | 69.94% |
| Yices2 (`yices2`) | common total | 7429 | 0.288925 | -71.11% | 71.11% |
| Yices2 (`yices2`) | common geometric | 7429 | 0.393365 | -60.66% | 60.66% |
| Z3 default (`z3-default`) | par2 | 7399 | 0.761527 | -23.85% | 23.85% |
| Z3 default (`z3-default`) | common total | 7399 | 0.72377 | -27.62% | 27.62% |
| Z3 default (`z3-default`) | common geometric | 7399 | 0.885829 | -11.42% | 11.42% |
| Z3 sat.euf (`z3-sat-euf`) | par2 | 7409 | 0.789959 | -21.00% | 21.00% |
| Z3 sat.euf (`z3-sat-euf`) | common total | 7409 | 0.817004 | -18.30% | 18.30% |
| Z3 sat.euf (`z3-sat-euf`) | common geometric | 7409 | 0.954398 | -4.56% | 4.56% |

## Broad Whole Corpus: SMT-LIB 2025 QF_UF full

`panel-af881b5571f6827b` | revision `30828a4f0c1e7e478a9c6f406ccb245eeefc4961` | status `verified` | family `all` | expected `all` | timeout `60s` | host `wmi-locked-x86-64` | class `audited-staged-locked`

Instances: 7503; complete: `true`; leader solves: 7500.

| Solver | Solved | Coverage | PAR2 (s) |
|---|---:|---:|---:|
| cvc5 (`cvc5`) | 7478 | 99.67% | 0.978437 |
| Viper (`euf-viper`) | 7480 | 99.69% | 0.805221 |
| OpenSMT (`opensmt`) | 7444 | 99.21% | 1.75157 |
| Yices2 (`yices2`) | 7500 | 99.96% | 0.13691 |
| Z3 default (`z3-default`) | 7489 | 99.81% | 0.470622 |
| Z3 sat.euf (`z3-sat-euf`) | 7483 | 99.73% | 0.561115 |

| Competitor | Metric | Common solved | Ratio | Signed | Required Viper reduction |
|---|---|---:|---:|---:|---:|
| cvc5 (`cvc5`) | par2 | 7457 | 1.21512 | +21.51% | 0.00% |
| cvc5 (`cvc5`) | common total | 7457 | 1.36358 | +36.36% | 0.00% |
| cvc5 (`cvc5`) | common geometric | 7457 | 2.48455 | +148.46% | 0.00% |
| OpenSMT (`opensmt`) | par2 | 7427 | 2.17527 | +117.53% | 0.00% |
| OpenSMT (`opensmt`) | common total | 7427 | 2.1292 | +112.92% | 0.00% |
| OpenSMT (`opensmt`) | common geometric | 7427 | 1.77428 | +77.43% | 0.00% |
| Yices2 (`yices2`) | par2 | 7478 | 0.170028 | -83.00% | 83.00% |
| Yices2 (`yices2`) | common total | 7478 | 0.199587 | -80.04% | 80.04% |
| Yices2 (`yices2`) | common geometric | 7478 | 0.49009 | -50.99% | 50.99% |
| Z3 default (`z3-default`) | par2 | 7467 | 0.584463 | -41.55% | 41.55% |
| Z3 default (`z3-default`) | common total | 7467 | 0.572315 | -42.77% | 42.77% |
| Z3 default (`z3-default`) | common geometric | 7467 | 1.56614 | +56.61% | 0.00% |
| Z3 sat.euf (`z3-sat-euf`) | par2 | 7462 | 0.696845 | -30.32% | 30.32% |
| Z3 sat.euf (`z3-sat-euf`) | common total | 7462 | 0.566289 | -43.37% | 43.37% |
| Z3 sat.euf (`z3-sat-euf`) | common geometric | 7462 | 1.79195 | +79.19% | 0.00% |

## Broad Whole Corpus: SMT-LIB 2025 QF_UF full

`panel-aca6d862dfff3430` | revision `30828a4f0c1e7e478a9c6f406ccb245eeefc4961` | status `verified` | family `all` | expected `all` | timeout `1200s` | host `wmi-locked-x86-64` | class `audited-staged-locked`

Instances: 7503; complete: `true`; leader solves: 7503.

| Solver | Solved | Coverage | PAR2 (s) |
|---|---:|---:|---:|
| cvc5 (`cvc5`) | 7495 | 99.89% | 3.78824 |
| Viper (`euf-viper`) | 7502 | 99.99% | 1.14019 |
| OpenSMT (`opensmt`) | 7498 | 99.93% | 3.75534 |
| Yices2 (`yices2`) | 7503 | 100.00% | 0.165777 |
| Z3 default (`z3-default`) | 7500 | 99.96% | 1.54322 |
| Z3 sat.euf (`z3-sat-euf`) | 7492 | 99.85% | 4.15568 |

| Competitor | Metric | Common solved | Ratio | Signed | Required Viper reduction |
|---|---|---:|---:|---:|---:|
| cvc5 (`cvc5`) | par2 | 7494 | 3.32248 | +232.25% | 0.00% |
| cvc5 (`cvc5`) | common total | 7494 | 1.55034 | +55.03% | 0.00% |
| cvc5 (`cvc5`) | common geometric | 7494 | 2.47776 | +147.78% | 0.00% |
| OpenSMT (`opensmt`) | par2 | 7497 | 3.29362 | +229.36% | 0.00% |
| OpenSMT (`opensmt`) | common total | 7497 | 2.6962 | +169.62% | 0.00% |
| OpenSMT (`opensmt`) | common geometric | 7497 | 1.78923 | +78.92% | 0.00% |
| Yices2 (`yices2`) | par2 | 7502 | 0.145395 | -85.46% | 85.46% |
| Yices2 (`yices2`) | common total | 7502 | 0.20207 | -79.79% | 79.79% |
| Yices2 (`yices2`) | common geometric | 7502 | 0.483825 | -51.62% | 51.62% |
| Z3 default (`z3-default`) | par2 | 7499 | 1.35349 | +35.35% | 0.00% |
| Z3 default (`z3-default`) | common total | 7499 | 0.717195 | -28.28% | 28.28% |
| Z3 default (`z3-default`) | common geometric | 7499 | 1.55216 | +55.22% | 0.00% |
| Z3 sat.euf (`z3-sat-euf`) | par2 | 7491 | 3.64474 | +264.47% | 0.00% |
| Z3 sat.euf (`z3-sat-euf`) | common total | 7491 | 0.794726 | -20.53% | 20.53% |
| Z3 sat.euf (`z3-sat-euf`) | common geometric | 7491 | 1.77323 | +77.32% | 0.00% |

## Broad Whole Corpus: SMT-LIB 2025 QF_UF official

`panel-e1512e3b9c3f17d0` | revision `30828a4f0c1e7e478a9c6f406ccb245eeefc4961` | status `verified` | family `all` | expected `all` | timeout `2s` | host `wmi-locked-x86-64` | class `audited-staged-locked`

Instances: 3521; complete: `true`; leader solves: 3490.

| Solver | Solved | Coverage | PAR2 (s) |
|---|---:|---:|---:|
| cvc5 (`cvc5`) | 3384 | 96.11% | 0.388011 |
| Viper (`euf-viper`) | 3400 | 96.56% | 0.306735 |
| OpenSMT (`opensmt`) | 3215 | 91.31% | 0.547308 |
| Yices2 (`yices2`) | 3490 | 99.12% | 0.0860356 |
| Z3 default (`z3-default`) | 3474 | 98.67% | 0.223966 |
| Z3 sat.euf (`z3-sat-euf`) | 3469 | 98.52% | 0.2497 |

| Competitor | Metric | Common solved | Ratio | Signed | Required Viper reduction |
|---|---|---:|---:|---:|---:|
| cvc5 (`cvc5`) | par2 | 3354 | 1.26497 | +26.50% | 0.00% |
| cvc5 (`cvc5`) | common total | 3354 | 1.3881 | +38.81% | 0.00% |
| cvc5 (`cvc5`) | common geometric | 3354 | 2.54132 | +154.13% | 0.00% |
| OpenSMT (`opensmt`) | par2 | 3193 | 1.7843 | +78.43% | 0.00% |
| OpenSMT (`opensmt`) | common total | 3193 | 1.85955 | +85.96% | 0.00% |
| OpenSMT (`opensmt`) | common geometric | 3193 | 1.77228 | +77.23% | 0.00% |
| Yices2 (`yices2`) | par2 | 3397 | 0.280489 | -71.95% | 71.95% |
| Yices2 (`yices2`) | common total | 3397 | 0.241967 | -75.80% | 75.80% |
| Yices2 (`yices2`) | common geometric | 3397 | 0.498627 | -50.14% | 50.14% |
| Z3 default (`z3-default`) | par2 | 3388 | 0.730163 | -26.98% | 26.98% |
| Z3 default (`z3-default`) | common total | 3388 | 0.888302 | -11.17% | 11.17% |
| Z3 default (`z3-default`) | common geometric | 3388 | 1.61015 | +61.02% | 0.00% |
| Z3 sat.euf (`z3-sat-euf`) | par2 | 3384 | 0.814058 | -18.59% | 18.59% |
| Z3 sat.euf (`z3-sat-euf`) | common total | 3384 | 1.01853 | +1.85% | 0.00% |
| Z3 sat.euf (`z3-sat-euf`) | common geometric | 3384 | 1.8512 | +85.12% | 0.00% |

## Broad Whole Corpus: SMT-LIB 2025 QF_UF official

`panel-035950d89cc20cb2` | revision `30828a4f0c1e7e478a9c6f406ccb245eeefc4961` | status `verified` | family `all` | expected `all` | timeout `60s` | host `wmi-locked-x86-64` | class `audited-staged-locked`

Instances: 3521; complete: `true`; leader solves: 3518.

| Solver | Solved | Coverage | PAR2 (s) |
|---|---:|---:|---:|
| cvc5 (`cvc5`) | 3510 | 99.69% | 0.953343 |
| Viper (`euf-viper`) | 3508 | 99.63% | 0.878514 |
| OpenSMT (`opensmt`) | 3496 | 99.29% | 1.74901 |
| Yices2 (`yices2`) | 3518 | 99.91% | 0.185341 |
| Z3 default (`z3-default`) | 3514 | 99.80% | 0.493209 |
| Z3 sat.euf (`z3-sat-euf`) | 3511 | 99.72% | 0.600286 |

| Competitor | Metric | Common solved | Ratio | Signed | Required Viper reduction |
|---|---|---:|---:|---:|---:|
| cvc5 (`cvc5`) | par2 | 3498 | 1.08518 | +8.52% | 0.00% |
| cvc5 (`cvc5`) | common total | 3498 | 1.33051 | +33.05% | 0.00% |
| cvc5 (`cvc5`) | common geometric | 3498 | 2.49363 | +149.36% | 0.00% |
| OpenSMT (`opensmt`) | par2 | 3486 | 1.99087 | +99.09% | 0.00% |
| OpenSMT (`opensmt`) | common total | 3486 | 2.15338 | +115.34% | 0.00% |
| OpenSMT (`opensmt`) | common geometric | 3486 | 1.81645 | +81.65% | 0.00% |
| Yices2 (`yices2`) | par2 | 3506 | 0.210971 | -78.90% | 78.90% |
| Yices2 (`yices2`) | common total | 3506 | 0.187949 | -81.21% | 81.21% |
| Yices2 (`yices2`) | common geometric | 3506 | 0.470225 | -52.98% | 52.98% |
| Z3 default (`z3-default`) | par2 | 3502 | 0.561413 | -43.86% | 43.86% |
| Z3 default (`z3-default`) | common total | 3502 | 0.587256 | -41.27% | 41.27% |
| Z3 default (`z3-default`) | common geometric | 3502 | 1.5184 | +51.84% | 0.00% |
| Z3 sat.euf (`z3-sat-euf`) | par2 | 3499 | 0.683297 | -31.67% | 31.67% |
| Z3 sat.euf (`z3-sat-euf`) | common total | 3499 | 0.603995 | -39.60% | 39.60% |
| Z3 sat.euf (`z3-sat-euf`) | common geometric | 3499 | 1.73836 | +73.84% | 0.00% |

## Broad Whole Corpus: SMT-LIB 2025 QF_UF official

`panel-94f499a4a81aa0db` | revision `30828a4f0c1e7e478a9c6f406ccb245eeefc4961` | status `verified` | family `all` | expected `all` | timeout `1200s` | host `wmi-locked-x86-64` | class `audited-staged-locked`

Instances: 3521; complete: `true`; leader solves: 3521.

| Solver | Solved | Coverage | PAR2 (s) |
|---|---:|---:|---:|
| cvc5 (`cvc5`) | 3517 | 99.89% | 3.831 |
| Viper (`euf-viper`) | 3520 | 99.97% | 1.72556 |
| OpenSMT (`opensmt`) | 3519 | 99.94% | 3.80605 |
| Yices2 (`yices2`) | 3521 | 100.00% | 0.179721 |
| Z3 default (`z3-default`) | 3520 | 99.97% | 1.50817 |
| Z3 sat.euf (`z3-sat-euf`) | 3516 | 99.86% | 4.15837 |

| Competitor | Metric | Common solved | Ratio | Signed | Required Viper reduction |
|---|---|---:|---:|---:|---:|
| cvc5 (`cvc5`) | par2 | 3516 | 2.22015 | +122.02% | 0.00% |
| cvc5 (`cvc5`) | common total | 3516 | 1.08037 | +8.04% | 0.00% |
| cvc5 (`cvc5`) | common geometric | 3516 | 2.47584 | +147.58% | 0.00% |
| OpenSMT (`opensmt`) | par2 | 3518 | 2.2057 | +120.57% | 0.00% |
| OpenSMT (`opensmt`) | common total | 3518 | 2.36296 | +136.30% | 0.00% |
| OpenSMT (`opensmt`) | common geometric | 3518 | 1.82622 | +82.62% | 0.00% |
| Yices2 (`yices2`) | par2 | 3520 | 0.104153 | -89.58% | 89.58% |
| Yices2 (`yices2`) | common total | 3520 | 0.172124 | -82.79% | 82.79% |
| Yices2 (`yices2`) | common geometric | 3520 | 0.463528 | -53.65% | 53.65% |
| Z3 default (`z3-default`) | par2 | 3519 | 0.874019 | -12.60% | 12.60% |
| Z3 default (`z3-default`) | common total | 3519 | 0.796122 | -20.39% | 20.39% |
| Z3 default (`z3-default`) | common geometric | 3519 | 1.50253 | +50.25% | 0.00% |
| Z3 sat.euf (`z3-sat-euf`) | par2 | 3515 | 2.40987 | +140.99% | 0.00% |
| Z3 sat.euf (`z3-sat-euf`) | common total | 3515 | 0.730376 | -26.96% | 26.96% |
| Z3 sat.euf (`z3-sat-euf`) | common geometric | 3515 | 1.71759 | +71.76% | 0.00% |

## Targeted Structural Combined: SMT-LIB 2025 QF_UF PEQ SEQ NEQ

`panel-75093baeabe12046` | revision `9a0763538a496898bace0325a456d0a86771a3c5` | status `provisional` | family `structural-combined` | expected `all` | timeout `2s` | host `macbook-air-airbartek-local-darwin-arm64` | class `local-one-repeat-discovery`

Instances: 151; complete: `true`; leader solves: 148.

| Solver | Solved | Coverage | PAR2 (s) |
|---|---:|---:|---:|
| cvc5 (`cvc5`) | 113 | 74.83% | 1.28377 |
| Viper (`euf-viper`) | 148 | 98.01% | 0.221847 |

| Competitor | Metric | Common solved | Ratio | Signed | Required Viper reduction |
|---|---|---:|---:|---:|---:|
| cvc5 (`cvc5`) | par2 | 113 | 5.78671 | +478.67% | 0.00% |
| cvc5 (`cvc5`) | common total | 113 | 5.59555 | +459.56% | 0.00% |
| cvc5 (`cvc5`) | common geometric | 113 | 5.04927 | +404.93% | 0.00% |

## Targeted Structural Combined: SMT-LIB 2025 QF_UF PEQ SEQ NEQ

`panel-4787f20fa17158fe` | revision `9a0763538a496898bace0325a456d0a86771a3c5` | status `provisional` | family `structural-combined` | expected `all` | timeout `2s` | host `macbook-air-airbartek-local-darwin-arm64` | class `local-one-repeat-discovery`

Instances: 151; complete: `true`; leader solves: 148.

| Solver | Solved | Coverage | PAR2 (s) |
|---|---:|---:|---:|
| Viper (`euf-viper`) | 148 | 98.01% | 0.225051 |
| Yices2 (`yices2`) | 140 | 92.72% | 0.408758 |

| Competitor | Metric | Common solved | Ratio | Signed | Required Viper reduction |
|---|---|---:|---:|---:|---:|
| Yices2 (`yices2`) | par2 | 140 | 1.81629 | +81.63% | 0.00% |
| Yices2 (`yices2`) | common total | 140 | 1.06015 | +6.02% | 0.00% |
| Yices2 (`yices2`) | common geometric | 140 | 0.750846 | -24.92% | 24.92% |

## Targeted Structural Combined: SMT-LIB 2025 QF_UF PEQ SEQ NEQ

`panel-dde479db840588c5` | revision `9a0763538a496898bace0325a456d0a86771a3c5` | status `provisional` | family `structural-combined` | expected `all` | timeout `2s` | host `macbook-air-airbartek-local-darwin-arm64` | class `local-one-repeat-discovery`

Instances: 151; complete: `true`; leader solves: 148.

| Solver | Solved | Coverage | PAR2 (s) |
|---|---:|---:|---:|
| Viper (`euf-viper`) | 148 | 98.01% | 0.221579 |
| Z3 (`z3`) | 126 | 83.44% | 0.789486 |

| Competitor | Metric | Common solved | Ratio | Signed | Required Viper reduction |
|---|---|---:|---:|---:|---:|
| Z3 (`z3`) | par2 | 126 | 3.563 | +256.30% | 0.00% |
| Z3 (`z3`) | common total | 126 | 2.10334 | +110.33% | 0.00% |
| Z3 (`z3`) | common geometric | 126 | 1.67796 | +67.80% | 0.00% |

## Targeted Structural Combined: SMT-LIB 2025 QF_UF PEQ SEQ NEQ

`panel-bae3258a75eab20a` | revision `9a0763538a496898bace0325a456d0a86771a3c5` | status `provisional` | family `structural-combined` | expected `unsat` | timeout `2s` | host `macbook-air-airbartek-local-darwin-arm64` | class `local-one-repeat-discovery`

Instances: 139; complete: `true`; leader solves: 136.

| Solver | Solved | Coverage | PAR2 (s) |
|---|---:|---:|---:|
| cvc5 (`cvc5`) | 101 | 72.66% | 1.38141 |
| Viper (`euf-viper`) | 136 | 97.84% | 0.235544 |

| Competitor | Metric | Common solved | Ratio | Signed | Required Viper reduction |
|---|---|---:|---:|---:|---:|
| cvc5 (`cvc5`) | par2 | 101 | 5.86477 | +486.48% | 0.00% |
| cvc5 (`cvc5`) | common total | 101 | 5.95427 | +495.43% | 0.00% |
| cvc5 (`cvc5`) | common geometric | 101 | 5.34065 | +434.07% | 0.00% |

## Targeted Structural Combined: SMT-LIB 2025 QF_UF PEQ SEQ NEQ

`panel-0fbdb314f98c66a3` | revision `9a0763538a496898bace0325a456d0a86771a3c5` | status `provisional` | family `structural-combined` | expected `unsat` | timeout `2s` | host `macbook-air-airbartek-local-darwin-arm64` | class `local-one-repeat-discovery`

Instances: 139; complete: `true`; leader solves: 136.

| Solver | Solved | Coverage | PAR2 (s) |
|---|---:|---:|---:|
| Viper (`euf-viper`) | 136 | 97.84% | 0.239047 |
| Yices2 (`yices2`) | 128 | 92.09% | 0.441775 |

| Competitor | Metric | Common solved | Ratio | Signed | Required Viper reduction |
|---|---|---:|---:|---:|---:|
| Yices2 (`yices2`) | par2 | 128 | 1.84807 | +84.81% | 0.00% |
| Yices2 (`yices2`) | common total | 128 | 1.09053 | +9.05% | 0.00% |
| Yices2 (`yices2`) | common geometric | 128 | 0.75658 | -24.34% | 24.34% |

## Targeted Structural Combined: SMT-LIB 2025 QF_UF PEQ SEQ NEQ

`panel-8918a673d988377f` | revision `9a0763538a496898bace0325a456d0a86771a3c5` | status `provisional` | family `structural-combined` | expected `unsat` | timeout `2s` | host `macbook-air-airbartek-local-darwin-arm64` | class `local-one-repeat-discovery`

Instances: 139; complete: `true`; leader solves: 136.

| Solver | Solved | Coverage | PAR2 (s) |
|---|---:|---:|---:|
| Viper (`euf-viper`) | 136 | 97.84% | 0.235309 |
| Z3 (`z3`) | 114 | 82.01% | 0.855538 |

| Competitor | Metric | Common solved | Ratio | Signed | Required Viper reduction |
|---|---|---:|---:|---:|---:|
| Z3 (`z3`) | par2 | 114 | 3.63581 | +263.58% | 0.00% |
| Z3 (`z3`) | common total | 114 | 2.25674 | +125.67% | 0.00% |
| Z3 (`z3`) | common geometric | 114 | 1.79196 | +79.20% | 0.00% |
