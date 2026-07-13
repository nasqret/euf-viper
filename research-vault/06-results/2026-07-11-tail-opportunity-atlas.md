# QF_UF Tail Opportunity Atlas

Date: 2026-07-11; authoritative post-fix update 2026-07-13

Status: the selector derivation below is historical discovery analysis. The
post-fix update is authoritative for current ranking requirements; neither is
a mechanism-promotion result.

## Authoritative post-fix 60-second update

The frozen P0 continuation at revision
`30828a4f0c1e7e478a9c6f406ccb245eeefc4961` supersedes the old `58efe9d`
scoreboard. Jobs `144990`-`144993` produced the exact two-second base and chain
`145036` produced the audited 60-second continuation. The full audit is
`p0-144990/continuations/chain-145036/audit/full-60.json`, SHA-256
`2458b01872a290c89f715a277dfd41e2c28091fc649925c9acbfefeb6e72686a`.
It rejects promotion.

| Solver | Solved / 7,503 | Timeouts | Timeout-charged wall | Median wall | p95 wall |
| --- | ---: | ---: | ---: | ---: | ---: |
| euf-viper | 7,480 | 23 | 4,512.684s | 0.02677s | 1.23385s |
| cvc5 | 7,479 | 24 | 5,580.626s | 0.08970s | 1.45948s |
| OpenSMT | 7,448 | 55 | 9,277.443s | 0.04644s | 3.08234s |
| Yices2 | 7,500 | 3 | 833.987s | 0.01715s | 0.18973s |
| Z3 default | 7,489 | 14 | 2,659.694s | 0.05704s | 0.79747s |
| Z3 `sat.euf=true` | 7,484 | 19 | 2,975.225s | 0.06523s | 0.94290s |

Against Z3 default, euf-viper is geometrically faster on 7,467 common solves
by `1.56851x`, but its common-wall aggregate ratio is only `0.58731`; 13
euf-viper-only solves do not offset 22 Z3-only solves. Beating Z3 without a
regression requires at least ten additional solves and a `1.7027x` reduction
of euf-viper's current common-solve aggregate.

Against Yices2, euf-viper has only two unique solves and misses 22 Yices-only
instances. It must add at least 21 solves to lead coverage. On 7,478 common
solves, its geometric and aggregate ratios are `0.49096` and `0.20452`;
matching Yices therefore requires about `2.04x` broad geometric and `4.89x`
common-aggregate improvement, not merely a hard-tail repair.

### Exact common deficit

The 22 instances solved within 60 seconds by both Z3 default and Yices2 but
missed by euf-viper are:

- nine Goel cases: both `firewire_tree.5` regularity properties,
  `frogs.{2,3,5}.prop1_ab_br_max`, `h_TicTacToe_ab_cti_max`,
  `hanoi.3.prop1_ab_br_max`, and `sokoban.{2,3}.prop1_ab_br_max`;
- `QF_UF/PEQ/PEQ012_size6.smt2`;
- `qg7/iso_icl_nogen{001,002,003,004,005,007}.smt2` and
  `qg7/iso_icl_nogen_sk{001,002,003,004,005,007}.smt2`.

The one instance missed by all three is outside this pairwise deficit.
euf-viper's two Yices-only wins are `PEQ003_size10` and `PEQ014_size11`; its
13 Z3-only wins are two NEQ, seven PEQ, and four SEQ instances. This makes the
current objective precise: T4/T5/T6/T8 must recover almost the entire common
22-instance deficit while also reducing broad QG and Goel aggregate cost.
Path names remain diagnostic evidence only and are forbidden runtime routing
features.

All sections below remain useful for frozen structural selectors and oracle
ceilings, but their performance numbers predate the Boolean-data parser fix
and must not be used as the current scoreboard.

## Decision summary

The archived campaigns imply two different competitive programs.

1. **Z3 is reachable with targeted work.** At 2 seconds, euf-viper already
   wins common-solve aggregate and geometric time, but needs 229 additional
   solves and 82.755 seconds less timeout-charged total time. At 60 seconds,
   83 slow solves and 25 timeouts contain enough opportunity to reverse the
   result. The domain-7 closed-table and large non-table graph populations are
   the primary targets.
2. **Yices2 cannot be beaten by repairing a few spectacular tail cases.** At
   60 seconds, only 1,578.935 of the 3,364.438-second common-solve deficit is
   in euf-viper solves taking at least 10 seconds. The rest is distributed
   across the broad table corpus and the medium-time head. At 2 seconds, the
   same effect is stronger: the `0.1-2s` euf-viper bins contribute 795.540 of
   the 857.863-second common-solve deficit.
3. **The strict Yices2 rank-changing envelope is broad.** The smallest
   mechanistically rounded envelope found in this atlas that has an oracle
   ceiling above Yices2 on solve count, all-instance total time, common total,
   and geometric speed at both budgets contains 7,305/7,503 formulas:
   `TABLE_CORE OR GRAPH_32`. Adding `DEEP_LET_512` produces a 7,309-formula
   envelope whose 60-second euf-viper/Yices2 oracle reaches all 7,503 solves.
4. **This is an opportunity ceiling, not a portfolio proposal.** The oracle
   calculations below use the faster correct incumbent after observing the
   result. They quantify how much opportunity a structural population
   contains; they are not an implementable runtime decision rule.
5. **No solver promotion is currently permissible.** Revision `58efe9d` has
   zero wrong answers on these 7,503 corpus instances, but it has the known
   Boolean-as-data soundness defect documented in
   [the soundness incident](2026-07-10-bool-as-data-unsoundness.md). Performance
   work must be replayed after that defect is repaired.

## Provenance

Both campaigns used euf-viper revision `58efe9d`, binary SHA-256
`4d5431135c95a2c528d287efd2803eaf895a5ec526c9642a570797b02fd47eb7`,
64 shards, and the same 7,503-formula SMT-LIB 2025 QF_UF corpus. The 60-second
campaign resumed the 2-second campaign and retried timeout observations.

| Artifact | SHA-256 |
| --- | --- |
| `results/wmi/four-solver-143049/qf-uf-corpus-143049.csv` | `b4d24b26bbb28250bf2b0cf16ca621ba2a615a6bbca9a9a6aab77faaa057beb0` |
| `results/wmi/four-solver-60s-143248/qf-uf-corpus-143248.csv` | `f255208a70c7af4ef34039a577ba6642002397097ef3bb8ac73041293b980863` |
| `results/wmi/finite-structures-full-c958-142731/finite-structures-full-c958.json` | `306ce4d6e4aa9f091e5ffeaf95444e13761e4f097bb456606231a7a483e10f03` |
| `results/wmi/four-solver-60s-143248/qf_uf_campaign_143248.jsonl` | `2ab1041d877d65befb41d5c7ae0c942a970bc4266aa37167dc8a77ec91bd2acf` |

The structural archive has successful parser-derived records for 7,499
formulas. Its four 2-second telemetry failures are
`NEQ015_size6`, `NEQ027_size11`, `NEQ046_size5`, and `NEQ046_size6`.
Lexical selectors can still classify them.

## Metrics

For solver $s$, all-instance time is the sum of every recorded wall time,
including timeout process time:

\[
T_s = \sum_{i=1}^{7503} t_{s,i}.
\]

For a pair of solvers, common total uses only formulas both solve correctly.
Geometric speed is

\[
G_{v,c} = \exp\left(\frac{1}{|C|}\sum_{i\in C}
\log\frac{t_{c,i}}{t_{v,i}}\right),
\]

where values greater than one favor euf-viper (v).

For selector $S$ and competitor $c$, the oracle opportunity keeps
euf-viper on every euf-viper-only solve and every faster common solve. Inside
$S$, it substitutes $c$ when $c$ is correct and euf-viper is slower or
times out. `Oracle savings` is the resulting reduction in $T_v$. It is an
upper bound that preserves current euf-viper wins.

## Exact ranking thresholds

### Solve count

The conversion minima assume no currently solved formula is lost.

| Budget | Rival | euf-viper | Rival | Convert to tie | Convert to beat | Convert for 7,503 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 2s | Z3 | 6,948 | 7,176 | 228 | **229** | 555 |
| 2s | Yices2 | 6,948 | 7,434 | 486 | **487** | 555 |
| 60s | Z3 | 7,478 | 7,490 | 12 | **13** | 25 |
| 60s | Yices2 | 7,478 | 7,500 | 22 | **23** | 25 |

The pairwise asymmetry is useful. At 2 seconds, euf-viper/Z3 has 41
euf-viper-only and 269 Z3-only solves; euf-viper/Yices2 has 4 euf-viper-only
and 490 Yices2-only solves. At 60 seconds these become 12/24 and 3/25.

### Timing

`Uniform x` is the algebraic speedup required if coverage and the observed
population were otherwise unchanged. A value marked `already` means the
current euf-viper result already wins that metric.

| Budget | Rival | All total: euf/rival | Gap | Uniform x needed | Common total: euf/rival | Uniform x needed | Current geo | Geo x needed |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 2s | Z3 | 2,327.841 / 2,245.087 | +82.754 | **1.0369x** | 1,169.787 / 1,309.391 | already | 2.0828x | already |
| 2s | Yices2 | 2,327.841 / 748.957 | +1,578.884 | **3.1081x** | 1,206.853 / 348.990 | **3.4581x** | 0.4377x | **2.2848x** |
| 60s | Z3 | 5,930.094 / 3,998.138 | +1,931.956 | **1.4832x** | 4,283.557 / 3,098.229 | **1.3826x** | 1.8883x | already |
| 60s | Yices2 | 5,930.094 / 1,307.536 | +4,622.558 | **4.5353x** | 4,363.808 / 999.370 | **4.3666x** | 0.4110x | **2.4329x** |

The required all-total reductions are 3.555%, 67.826%, 32.579%, and
77.951%, respectively. Conversion and speed improvements interact: solving a
current timeout faster than the budget improves both quality and all-total
time.

## Loss partitions

In the next tables, `net solves` is competitor-only minus euf-viper-only.
`Common delta` is euf-viper common time minus competitor common time; positive
values are deficits for euf-viper.

### Versus Z3 by family

| Family | N | 2s net solves | 2s common delta | 60s net solves | 60s common delta |
| --- | ---: | ---: | ---: | ---: | ---: |
| QG-classification | 6,396 | **+201** | -45.208s | **+10** | **+1,130.385s** |
| 2018-Goel-hwbench | 773 | **+25** | -87.376s | **+12** | **+234.997s** |
| NEQ | 48 | -2 | +1.122s | -2 | -56.003s |
| PEQ | 47 | +3 | -0.067s | -5 | -85.489s |
| SEQ | 56 | +1 | -0.477s | -3 | -30.963s |
| Other four families | 183 | 0 | -7.599s | 0 | -7.599s |
| **Total** | **7,503** | **+228** | **-139.605s** | **+12** | **+1,185.328s** |

At 2 seconds, Z3's advantage is almost entirely coverage in QG and Goel;
euf-viper is already faster on their common solves. At 60 seconds the same two
families become the time deficit. Improving only NEQ/PEQ/SEQ cannot change the
overall Z3 ranking because those families already offset the long-tail loss.

### Versus Yices2 by family

| Family | N | 2s net solves | 2s common delta | 60s net solves | 60s common delta |
| --- | ---: | ---: | ---: | ---: | ---: |
| QG-classification | 6,396 | **+421** | **+790.752s** | **+10** | **+2,701.878s** |
| 2018-Goel-hwbench | 773 | **+45** | +42.031s | **+12** | **+440.117s** |
| NEQ | 48 | +4 | +7.852s | +2 | +22.826s |
| PEQ | 47 | +11 | +8.426s | -2 | +122.717s |
| SEQ | 56 | +5 | +7.534s | 0 | +75.632s |
| Other four families | 183 | 0 | +1.268s | 0 | +1.268s |
| **Total** | **7,503** | **+486** | **+857.863s** | **+22** | **+3,364.438s** |

QG contributes 92.2% of the 2-second common deficit and 80.3% of the
60-second common deficit. Goel is the second strategic population. The small
finite families matter for full coverage but cannot close the Yices2 timing
gap by themselves.

### By expected status

| Budget | Rival | Status | Net solves | Common delta | Gross common loss |
| --- | --- | --- | ---: | ---: | ---: |
| 2s | Z3 | sat | +29 | -235.731s | 35.929s |
| 2s | Z3 | unsat | **+199** | +96.126s | 294.596s |
| 2s | Yices2 | sat | +71 | +135.763s | 148.362s |
| 2s | Yices2 | unsat | **+415** | **+722.099s** | 730.513s |
| 60s | Z3 | sat | +8 | +229.200s | 555.685s |
| 60s | Z3 | unsat | +4 | **+956.128s** | 1,746.350s |
| 60s | Yices2 | sat | +8 | +739.461s | 755.712s |
| 60s | Yices2 | unsat | +14 | **+2,624.977s** | 2,704.408s |

The dominant research target is therefore UNSAT proof search, while SAT
coverage in the Goel graph population remains necessary.

## Timeout behavior

Of the 555 euf-viper timeouts at 2 seconds, 530 solve by 60 seconds and 25
remain. The 2-second timeout set has 478 UNSAT and 77 SAT formulas.

| Diagnostic manifest | N | Canonical sorted-path SHA-256 |
| --- | ---: | --- |
| euf-viper 2s timeouts | 555 | `c1144c278d6ccf164d086fbf2ff0985f119e1cd77d26c75201a37d5531e5b4fa` |
| euf-viper/Yices2 both timeout at 2s | 65 | `f61c690819676a3f0deca3f162d074ab0c72cbbd51e84727f6db381c5580a44e` |
| all four solvers timeout at 2s | 56 | `f05a6752eb1cec9343b5a8d359004e5b1cd9e436773b762f3ff5919415e37cee` |
| euf-viper 60s timeouts | 25 | `67af4bd0e8ee685e24a803d780d9583d84ab5d64be99b77bdcceaecf4998fde5` |

| Family | 2s timeouts | Solved by 60s | Still timeout at 60s |
| --- | ---: | ---: | ---: |
| QG-classification | 464 | 454 | 10 |
| 2018-Goel-hwbench | 45 | 33 | 12 |
| NEQ | 15 | 13 | 2 |
| PEQ | 23 | 22 | 1 |
| SEQ | 8 | 8 | 0 |
| **Total** | **555** | **530** | **25** |

At 60 seconds, Z3 solves 24 of these 25 persistent cases and Yices2 solves
all 25. Their structural partition is exact and exhaustive:

- 10 domain-7 huge closed-table QG formulas;
- 12 non-table Goel formulas satisfying `GRAPH_2500`;
- 2 deep-let NEQ formulas;
- 1 finite guarded-Hall PEQ formula.

### Exact 60-second timeout manifest

| Relative path | Expected | Z3 | Yices2 | Structural class |
| --- | --- | ---: | ---: | --- |
| `QF_UF/2018-Goel-hwbench/QF_UF_firewire_tree.5.prop1_ab_reg_max.smt2` | unsat | 3.255s | 1.597s | `GRAPH_2500` |
| `QF_UF/2018-Goel-hwbench/QF_UF_firewire_tree.5.prop2_ab_reg_max.smt2` | sat | 1.939s | 1.883s | `GRAPH_2500` |
| `QF_UF/2018-Goel-hwbench/QF_UF_frogs.2.prop1_ab_br_max.smt2` | sat | 0.238s | 0.041s | `GRAPH_2500` |
| `QF_UF/2018-Goel-hwbench/QF_UF_frogs.3.prop1_ab_br_max.smt2` | sat | 0.320s | 0.171s | `GRAPH_2500` |
| `QF_UF/2018-Goel-hwbench/QF_UF_frogs.5.prop1_ab_br_max.smt2` | sat | 0.288s | 0.032s | `GRAPH_2500` |
| `QF_UF/2018-Goel-hwbench/QF_UF_h_TicTacToe_ab_cti_max.smt2` | sat | 0.152s | 0.045s | `GRAPH_2500` |
| `QF_UF/2018-Goel-hwbench/QF_UF_hanoi.3.prop1_ab_br_max.smt2` | sat | 0.199s | 0.039s | `GRAPH_2500` |
| `QF_UF/2018-Goel-hwbench/QF_UF_peg_solitaire.2.prop1_ab_br_max.smt2` | unsat | 0.278s | 0.047s | `GRAPH_2500` |
| `QF_UF/2018-Goel-hwbench/QF_UF_peg_solitaire.4.prop1_ab_br_max.smt2` | sat | 0.264s | 0.035s | `GRAPH_2500` |
| `QF_UF/2018-Goel-hwbench/QF_UF_sokoban.2.prop1_ab_br_max.smt2` | unsat | 0.499s | 0.098s | `GRAPH_2500` |
| `QF_UF/2018-Goel-hwbench/QF_UF_sokoban.3.prop1_ab_br_max.smt2` | unsat | 0.735s | 0.043s | `GRAPH_2500` |
| `QF_UF/2018-Goel-hwbench/QF_UF_sokoban.3.prop1_ab_reg_max.smt2` | sat | 2.396s | 0.272s | `GRAPH_2500` |
| `QF_UF/NEQ/NEQ027_size11.smt2` | unsat | 9.587s | 34.494s | `DEEP_LET_512` |
| `QF_UF/NEQ/NEQ046_size6.smt2` | unsat | timeout | 36.886s | `DEEP_LET_512` |
| `QF_UF/PEQ/PEQ012_size6.smt2` | unsat | 34.993s | 12.745s | `FINITE_HALL` |
| `QF_UF/QG-classification/qg7/gensys_icl_sk001.smt2` | unsat | 22.568s | 8.844s | `DOMAIN7_HUGE` |
| `QF_UF/QG-classification/qg7/iso_icl_nogen001.smt2` | unsat | 1.047s | 0.338s | `DOMAIN7_HUGE` |
| `QF_UF/QG-classification/qg7/iso_icl_nogen002.smt2` | unsat | 1.000s | 0.318s | `DOMAIN7_HUGE` |
| `QF_UF/QG-classification/qg7/iso_icl_nogen003.smt2` | unsat | 1.233s | 0.488s | `DOMAIN7_HUGE` |
| `QF_UF/QG-classification/qg7/iso_icl_nogen004.smt2` | unsat | 1.258s | 0.332s | `DOMAIN7_HUGE` |
| `QF_UF/QG-classification/qg7/iso_icl_nogen007.smt2` | unsat | 1.226s | 0.344s | `DOMAIN7_HUGE` |
| `QF_UF/QG-classification/qg7/iso_icl_nogen_sk001.smt2` | unsat | 18.055s | 11.566s | `DOMAIN7_HUGE` |
| `QF_UF/QG-classification/qg7/iso_icl_nogen_sk002.smt2` | unsat | 7.557s | 8.533s | `DOMAIN7_HUGE` |
| `QF_UF/QG-classification/qg7/iso_icl_nogen_sk003.smt2` | unsat | 7.263s | 6.967s | `DOMAIN7_HUGE` |
| `QF_UF/QG-classification/qg7/iso_icl_nogen_sk004.smt2` | unsat | 2.641s | 1.836s | `DOMAIN7_HUGE` |

At 2 seconds, the four-solver oracle still leaves 56 formulas unsolved: 37
QG, 10 PEQ, 7 NEQ, and 2 SEQ. Fifty-two satisfy `TABLE_CORE`; the remaining
four are the structural-telemetry failures covered by `DEEP_LET_512`. Full
2-second coverage therefore requires genuinely new solving power, not merely
copying any incumbent's observed behavior.

## Timing concentration

At 60 seconds, euf-viper has 83 correct solves taking at least 10 seconds.
Against Z3, 79 common formulas in that bin contribute a 1,285.148-second net
deficit and 1,416.326 seconds of gross loss. Against Yices2, 81 common formulas
contribute a 1,578.935-second net deficit and 1,585.172 seconds of gross loss.

The 25 euf-viper timeouts contain another 1,323.014 seconds of Z3 oracle
savings and 1,374.106 seconds of Yices2 oracle savings. This is enough to
reverse Z3 if coverage is preserved, but not enough to reverse Yices2. Against
Yices2, common solves below 10 seconds still contribute 1,785.503 seconds of
net deficit.

Gross loss is concentrated but not isolated:

| Budget | Rival | Top 10 | Top 50 | Top 100 | Top 500 | All slower common solves |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| 2s | Z3 | 14.544s | 60.697s | 103.045s | 264.795s | 330.525s |
| 2s | Yices2 | 17.971s | 82.637s | 151.005s | 495.647s | 878.876s |
| 60s | Z3 | 446.280s | 1,268.430s | 1,609.933s | 2,109.377s | 2,302.035s |
| 60s | Yices2 | 452.343s | 1,311.683s | 1,765.493s | 2,736.417s | 3,460.121s |

## Leak-free structural selectors

All runtime selectors below use only raw input bytes or parser-derived
structure available before SAT solving. They prohibit path, family, expected
status, result, and timing features. `parens` and `lets` are exact byte counts
of `b"("` and `b"(let"`.

| Name | Exact predicate |
| --- | --- |
| `TABLE_CORE` | `closed_table_functions >= 1 AND binary_table_apps >= 1` |
| `DOMAIN7_TABLE` | `domain_size = 7 AND closed_table_functions >= 1 AND binary_table_apps >= 49 AND guarded_disequality_clauses = 0` |
| `DOMAIN7_ONE_TABLE` | `DOMAIN7_TABLE AND closed_table_functions = 1` |
| `DOMAIN7_HUGE` | `DOMAIN7_TABLE AND parens >= 80000` |
| `HUGE_CLOSED_TABLE` | `domain_size > 0 AND closed_table_functions >= 1 AND binary_table_apps >= domain_size^2 AND parens >= 80000` |
| `GRAPH_32` | `closed_table_functions = 0 AND binary_table_apps = 0 AND equality_graph_vertices >= 32 AND equality_graph_edges >= 32` |
| `GRAPH_500` | `closed_table_functions = 0 AND binary_table_apps = 0 AND equality_graph_vertices >= 500 AND equality_graph_edges >= 1000` |
| `GRAPH_2500` | `closed_table_functions = 0 AND binary_table_apps = 0 AND equality_graph_vertices >= 2500 AND equality_graph_edges >= 5000 AND distinct_constants >= 3000` |
| `DEEP_LET_512` | `lets >= 512` |
| `FINITE_HALL` | `domain_size > 0 AND guarded_disequality_clique_lb >= domain_size` |
| `RANK_ENVELOPE` | `TABLE_CORE OR GRAPH_32` |
| `FULL60_ENVELOPE` | `RANK_ENVELOPE OR DEEP_LET_512` |

The thresholds were discovered using these archived results. They are now
frozen hypotheses. Their current-corpus measurements are in-sample and cannot
serve as independent validation; future gates must not retune them.

### Exact manifests

For each selector, the canonical manifest is its sorted relative paths, one
UTF-8 path per line with a final LF. The SHA-256 below fixes the exact set.

| Selector | N | Family composition | Canonical manifest SHA-256 |
| --- | ---: | --- | --- |
| `TABLE_CORE` | 6,542 | QG 6,396; NEQ 44; PEQ 47; SEQ 55 | `db920aa6eb9c30595bec5bcad360dc61f40e29721c0f996caf73de2cdf3b9439` |
| `DOMAIN7_TABLE` | 431 | QG 418; NEQ 5; PEQ 2; SEQ 6 | `3c40aa2d1a6a7a2751a73af3a1b20a589f23b601644dbcc3321c85fdf723f758` |
| `DOMAIN7_ONE_TABLE` | 261 | QG 258; NEQ 2; SEQ 1 | `feaee694c894b899938494ca70b9c1641e032452e217c21233bd12e4c688fbe5` |
| `DOMAIN7_HUGE` | 174 | QG 174 | `526f0a1ad9f791ec779ddde99590154003553fff42924b54319a6bf47307f4ef` |
| `HUGE_CLOSED_TABLE` | 234 | QG 234 | `8880a722c349598e602d7ea221bef5fbe73b10811006de8ca4adaea377896825` |
| `GRAPH_32` | 763 | Goel 656; eq_diamond 89; CLEARSY 17; SEQ 1 | `2b4e8cfd0d94df5cb3c1d5a3048e4d393bcc08b8616cf30b0264c77457119949` |
| `GRAPH_500` | 212 | Goel 212 | `59eb5891a106946223766345c3131242315aff2c01b2fb744ced177e06bbcccc` |
| `GRAPH_2500` | 39 | Goel 39 | `4973c78f7264d763131392529f0b7b900c229089361a1a537a8eebed618e721f` |
| `DEEP_LET_512` | 17 | NEQ 17 | `f8feeea91d3abc126d82e8db38efd808238a82d59a6319ffe2712d383b2eca68` |
| `FINITE_HALL` | 39 | NEQ 11; PEQ 24; SEQ 4 | `011df521d4e73fc92c5205ffe82762aae5cdba4f9c0b4f87c8d0d5feca21d90e` |
| `RANK_ENVELOPE` | 7,305 | QG 6,396; Goel 656; eq_diamond 89; NEQ 44; PEQ 47; SEQ 56; CLEARSY 17 | `a90665620ac5ab7183ff6fa5e760eaf067a7fae33f23fd68a3827bbc37a6c4e2` |
| `FULL60_ENVELOPE` | 7,309 | `RANK_ENVELOPE` plus four unique deep-let NEQ paths | `8e26e81302876c08adba542cecb058d62c806a39e9fb43a7b3338f405c24a3c0` |

`TABLE_CORE` and the stronger-looking closed-square-table predicate happen to
select the same 6,542 paths in this corpus. This equality is corpus-specific
and must not be assumed by implementation code.

## Opportunity ceilings by structure

Each cell is `competitor-only conversions / all-total oracle savings` for the
selected population. Savings preserve all current euf-viper-only and faster
common solves.

| Selector | N | 2s vs Z3 | 60s vs Z3 | 2s vs Yices2 | 60s vs Yices2 |
| --- | ---: | ---: | ---: | ---: | ---: |
| `TABLE_CORE` | 6,542 | 238 / 540.631s | 11 / 2,475.797s | 445 / 1,484.265s | 11 / 3,607.567s |
| `DOMAIN7_TABLE` | 431 | 52 / 73.685s | 10 / 1,466.035s | 70 / 150.875s | 10 / 1,592.640s |
| `DOMAIN7_HUGE` | 174 | 34 / 40.234s | 10 / 1,109.235s | 50 / 100.543s | 10 / 1,220.458s |
| `GRAPH_500` | 212 | 30 / 53.138s | 12 / 1,079.343s | 44 / 106.246s | 12 / 1,144.253s |
| `GRAPH_2500` | 39 | 16 / 25.617s | 12 / 862.175s | 27 / 49.849s | 12 / 898.772s |
| `DEEP_LET_512` | 17 | 2 / 3.491s | 1 / 82.435s | 3 / 8.220s | 2 / 77.948s |
| `FINITE_HALL` | 39 | 9 / 17.760s | 1 / 133.448s | 12 / 28.178s | 1 / 191.690s |
| `RANK_ENVELOPE` | 7,305 | 269 / 595.254s | 23 / 3,558.892s | 490 / 1,602.875s | 23 / 4,766.022s |
| `FULL60_ENVELOPE` | 7,309 | 269 / 595.254s | 24 / 3,624.980s | 490 / 1,602.875s | 25 / 4,833.246s |

### Which populations can change a ranking?

**Z3 at 2 seconds.** `TABLE_CORE` is large enough in principle: its ceiling
contains 238 of the 229 required conversions and 540.631 seconds of savings,
while only 82.754 seconds are required. Coverage is the hard part: at least
229/238 selected Z3-only cases must convert if no other population contributes.

**Z3 at 60 seconds.** The 213-formula union
`DOMAIN7_HUGE OR GRAPH_2500` has an oracle result of 7,500 solves and
3,958.684 seconds, narrowly ahead of Z3's 7,490 and 3,998.138. It does **not**
beat Z3 common total, remaining 461.329 seconds behind there. It is therefore
a tail milestone, not a no-compromise endpoint. `RANK_ENVELOPE` clears solve
count, all total, common total, and geometric speed in the oracle calculation.

**Yices2 at both budgets.** No isolated selector above is sufficient.
`TABLE_CORE OR GRAPH_500` can narrowly beat solve count and total time but its
oracle geometric ratios are only 0.9576 at 2 seconds and 0.9604 at 60 seconds.
Lowering the graph boundary to the predeclared power-of-two `GRAPH_32` is the
first tested rounded envelope to clear every metric:

| Budget | Effective solves | Yices2 solves | Effective total | Yices2 total | Effective common advantage | Effective geo |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 2s | 7,438 | 7,434 | 724.966s | 748.957s | 20.032s | 1.0077x |
| 60s | 7,501 | 7,500 | 1,164.072s | 1,307.536s | 76.318s | 1.0108x |

These oracle margins are thin. At 2 seconds, an implementation must realize
98.50% of the envelope's total-time ceiling and 487/490 of its available
Yices2-only conversions merely to win. At 60 seconds it must realize 96.99%
of the time ceiling and all 23 available conversions. `FULL60_ENVELOPE`
improves the 60-second ceiling to 7,503 solves and 1,096.848 seconds, but its
geometric advantage remains only 1.0108x.

Therefore the campaign must aim to become **faster than Yices2 inside the
selected populations**, not merely match it. An epsilon oracle victory is too
small to survive cross-node variance.

## Research allocation implied by the atlas

The populations define three implementation fronts without using family names
at runtime.

1. **Closed-table bulk (`TABLE_CORE`).** This is 87.2% of the corpus and
   contains 2,905.365 seconds of the 60-second common Yices2 deficit. Domain-7
   orbit canonization and Boolean-DAG sharing target its tail, but beating
   Yices2 also requires reducing ordinary table-instance overhead. A tail-only
   implementation cannot capture the required opportunity.
2. **Non-table equality graphs (`GRAPH_32`, with `GRAPH_2500` as the first
   hard gate).** `GRAPH_2500` captures every persistent Goel timeout; the broad
   selector is needed for geometric parity. Partial-trail conflict detection,
   rollback equality state, or another non-DPLL(T) graph mechanism must first
   pass the 39-case gate and then scale without overhead across `GRAPH_32`.
3. **Finite/deep residual (`DEEP_LET_512` and `FINITE_HALL`).** These sets are
   too small to change Yices2 timing rank, but they close the 60-second quality
   boundary and include all four structural-telemetry failures. They remain
   mandatory for full coverage.

The ordering should be target gate, broad structural gate, then the exact
rank envelope. Optimizing an isolated NEQ/PEQ case without demonstrating
movement on one of these aggregate populations does not advance the overall
ranking objective.

## Leak-control and acceptance contract

1. Treat this entire corpus analysis as discovery. Freeze the predicates and
   manifest hashes above before implementation.
2. Compute routing features before SAT search. The runtime decision may not
   inspect path, family, expected status, solver result, timing, or an incumbent
   solver.
3. Log the complete feature vector and selected route for every run. Regenerate
   the canonical manifest and require its SHA-256 to match this report before a
   target gate.
4. Use same-binary `off|candidate` WMI A/B runs, alternating order, at both 2s
   and 60s. Repeat on both CPU classes before a default change.
5. Require zero wrong answers and execution errors, no solve loss, and all of
   all-total, common-total, and geometric ratios above one at every promotion
   gate. The known Boolean-as-data regression must pass first.
6. For a superiority claim, require strict solve-count leadership and at least
   5% all-total plus 2% geometric margin in two independent full-corpus runs.
   The oracle shows that matching Yices2 is insufficient for this robust
   target; selected mechanisms must create new speed advantage.
7. Keep the exact target manifests for diagnosis, but evaluate generalization
   on source-family holdouts and a separately frozen external QF_UF corpus.
   Current-corpus success alone is not evidence of a generally superior
   solver.

## Bottom line

The Z3 deficit is a tractable tail-and-coverage problem. The Yices2 deficit is
an architectural breadth problem: the rank-changing envelope covers 97.36% of
the corpus, and even a perfect match inside it wins by less than 1.1% geometric
speed. The novelty campaign should use the narrow domain-7 and 39-case graph
sets as falsifiable mechanism gates, but it must ultimately reduce cost across
the full closed-table bulk and medium equality-graph populations. Anything
narrower can produce striking benchmark wins without changing the overall
ranking.
