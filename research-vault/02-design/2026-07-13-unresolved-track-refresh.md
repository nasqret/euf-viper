# Unresolved Track Refresh

Date: 2026-07-13

Status: bounded post-P0 opportunity ordering

## Frozen Deficit

At 60 seconds, both Z3 default and Yices2 solve 22 sources that euf-viper
misses:

| Stratum | Sources | SAT | UNSAT | Primary pressure |
| --- | ---: | ---: | ---: | --- |
| Goel `GRAPH_2500` | 9 | 6 | 3 | repeated complete-model validation |
| PEQ `FINITE_HALL` | 1 | 0 | 1 | finite-domain/Hall proof complexity |
| qg7 `DOMAIN7_HUGE` | 12 | 0 | 12 | finite-table canonical search |
| Total | 22 | 6 | 16 | heterogeneous |

Ten additional solves with no loss exceed Z3's full-corpus solve count. Twenty
one are needed to exceed Yices2. The 12 qg7 targets alone can cross the Z3
coverage threshold, but no single-family route can credibly close the Yices
timing and 21-solve requirement.

## Questions Already Answered

- **T0 broad backend replacement:** stop. Kissat 4.0.4 lost the frozen sample,
  and unconditional CaDiCaL clausal congruence reduced conflicts while slowing
  the local end-to-end control. Individual passes remain causal controls only.
- **T3 opportunity:** real but incomplete. Goel profiles show roughly 85-90%
  of hard-case time in repeated validation, while broad eager Ackermannization
  failed. Prediction quality and migration value remain unmeasured.
- **T7 opportunity:** plausible only on Goel. Existing data cannot establish
  that SAT-impact explanations or EUF-conditioned vivification outperform
  shortest-proof and Boolean-only controls.
- **T8 abstraction boundary:** the old right-translation abstraction is not an
  UNSAT engine; all 164 eligible abstract searches remained SAT. Source-exact
  frontier width, reuse, transition cost, and SIMD occupancy remain open.

## Ranked Experiments

### 1. T3 M0 Component-Pressure Atlas

Consume frozen output from every surviving fixed representation. Train and
evaluate only across family- and lineage-disjoint groups.

Gate:

- balanced held-out accuracy at least `0.80`;
- p95 telemetry overhead below `1%`;
- byte-identical replay when migration is disabled;
- oracle headroom at least `10%` between the best fixed arms;
- at least two fixed representations survive their own gates.

Stop if either headroom or survivor count fails. Only then implement one-way
eager-to-rollback migration at checked quiescent points. The timing gate is
`1.10x` on targets, at least one timeout conversion, and no baseline-only loss.

Target order: Goel `GRAPH_2500`, then `GRAPH_32` and `TABLE_CORE` controls.

### 2. T8 Scalar Source-Exact Frontier Quotient Transducer

Consume every source assertion and compare tiny cases against exhaustive
enumeration before optimizing state layout.

Gate:

- zero source/checker mismatch;
- at least 10 of 12 qg7 targets fit a `1,000,000`-state cap;
- build cost at most 10% on most targets;
- a credible direct Yices2 win including setup and reconstruction.

No SIMD or lane batching is justified before this scalar census passes.

### 3. T7 Explanation Economics

Enumerate valid alternative congruence reasons and compare fixed order,
shortest proof, width, predicted LBD/backjump, reuse, and certificate cost.

Gate:

- at least 20% fewer validation rounds or downstream propagations;
- selection overhead below 5%;
- target speedup at least `1.10x`;
- reject if shortest-proof alone explains the gain.

Targets: the nine frozen Goel losses.

### 4. T7 Theory-Conditioned Vivification

Run a fixed-budget factorial: none, Boolean-only, EUF-only, and combined.
Retain only independently replayed binary or ternary consequences.

Gate:

- EUF or combined beats Boolean-only;
- at least twice as many useful literals removed;
- at least 15% fewer later validation/propagation events;
- target speedup at least `1.05x` with no broad loss.

### 5. T8 Checked Lane-Batched Search

Only after the scalar route passes, require scalar/lane lockstep equality,
useful occupancy at least 70%, a checked UNSAT cube cover, at least 10 of 12
qg7 conversions, and a direct Yices2 win including extraction and model/proof
reconstruction.

## Prior-Art Boundaries

- DPLL(T), partial/dynamic Ackermannization, fixed portfolios, rollback e-graphs,
  and theory propagation are established. T3 is differentiated only by online
  per-component migration with stable semantic IDs and representation-neutral
  checked replay. See [DPLL(T)](https://doi.org/10.1145/1217856.1217859) and
  [partial Ackermannization](https://doi.org/10.1007/11916277_38).
- Small congruence explanations are established. A shortest-reason result
  collides with [Small Proofs from Congruence
  Closure](https://arxiv.org/abs/2209.03398).
- Clause vivification and clausal congruence are established. Novelty requires
  the EUF-conditioned arm to beat the Boolean control. See [clause
  vivification](https://arxiv.org/abs/1807.11061) and [Clausal Congruence
  Closure](https://doi.org/10.4230/LIPIcs.SAT.2024.6).
- Complete finite-model symmetry breaking and structural symmetry detection are
  established. T8 must be a source-exact, proof-carrying frontier quotient
  transition system, not another symmetry-clause generator. See [complete
  magma symmetry breaking](https://doi.org/10.1609/aaai.v39i11.33217) and
  [Satsuma](https://doi.org/10.4230/LIPIcs.SAT.2024.4).
- Kissat's current equivalence and vivification inventory is a control surface,
  not novelty. See [Kissat 4.0.4
  options](https://github.com/arminbiere/kissat/blob/rel-4.0.4/src/options.h).

This refresh does not prove novelty. It identifies the smallest experiments
that can falsify the remaining claims after T1/T2/T4/T5/T6 return.
