# Viper Fabric Novelty Boundaries

Date: 2026-07-22

Status: bounded prior-art audit; sufficient for experiment design, not for a
global first-in-history claim. Patents, dissertations, private implementations,
and unpublished work remain outside the search boundary.

## Decision Table

| Mechanism | Closest occupied territory | Plausible contribution | Cheapest falsifier | Current decision |
| --- | --- | --- | --- | --- |
| E2 canonical-partition CDCL | ACDCL, DPLL(T), MCSat, Dsat, rollback EUF | Orbit-invariant learning directly over a growing typed congruence partition | Exhaust all domains through four terms and every class relabeling; reject one unstable reason or nogood | Tiny fixed prototype only |
| E3 quotient-frontier memoization | SAT component caching, AND/OR search, CSP treewidth DP, canonical finite-model search | Source-complete canonical residual keys and checked reuse across different Boolean histories | Require at least 20% exact repetition, at least 5% corpus-time relevance, and key cost below 10% of avoided work | Highest-priority scalar census |
| X1 EUF-specific extended resolution | GlucosER, CaDiCaL-ER, CaDiCaL-FX | Exact recurring congruence-path or application-row definitions that generic factoring misses | Trace exact concrete recurrence and compare against generic FX; require 25% conflict-weighted coverage and 20% projected literal reduction | Trace-only census |
| X2 repeated semantic symmetry | SORB, Z3 symmetry reduction, Yices UF symmetry breaking | Recompute typed semantic automorphisms after EUF rewriting exposes symmetries absent from CNF | Require a verified second-round cut absent from both one-shot typed and SORB controls | Offline three-arm shadow only |
| X3 component-local migration | DPLL(T), portfolios, propagator switching, solver-state migration | Proof-carrying one-way per-component representation changes under one Boolean shell | Fixed-arm oracle lower bound must exceed 10% before migration code | Forbidden; observed oracle is 3.74% |

## E2 Soundness Boundary

Canonical class labels are history-relative. A learned object may mention only
stable source terms, stable atoms, or a checked orbit-invariant partition
predicate. A label whose meaning changes after merge or rollback cannot enter a
reason or nogood.

The E2 experiment is unsuccessful if useful learned objects expand to ordinary
pair-equality clauses without reducing explored states. That result would be a
decision heuristic variant of DPLL(T), not the intended new proof system.

The mandatory oracle enumerates:

1. every typed ground formula in the bounded generator;
2. every partition state through four terms;
3. every valid class relabeling;
4. every emitted propagation reason and learned nogood;
5. source truth before and after replay and backjump.

One relabeling counterexample kills behavioral E2 until the language is fixed.

## E3 Exact-Key Boundary

A frontier key must contain the live typed partition, disequalities, observed
function rows, residual Boolean obligations, assertion lineage, forgotten-state
summary, and structural position. Fingerprints may index a table but cannot be
the equality test. Every hit receives a full-key comparison.

The earlier repository frontier prototype omitted residual source state and is
therefore a warning, not reusable UNSAT evidence. The first campaign is
observe-only and no-forget.

## X1 Concrete-Recurrence Boundary

Alpha-isomorphic explanation shapes over different source terms are different
formulas. They cannot share one extension atom. The census must distinguish:

- exact concrete antecedent recurrence;
- typed shape recurrence;
- recurrence already found by generic CNF factoring;
- literal savings after adding complete extension definitions;
- proof expansion cost and clause lifetime.

Only exact concrete recurrence can authorize a behavioral extension.

## X2 Proof Boundary

Symmetry restrictions preserve satisfiability but need not be logical
consequences. The checker therefore needs an orbit or substitution-redundancy
witness; an EUF implication check is insufficient. Assignment-dependent
symmetries require guards.

The control arms are current one-shot typed breaking, generic SORB on emitted
CNF, and repeated semantic breaking. Identical mapped cuts reject the novelty
claim even when timings improve.

## Primary Sources

- [Abstract Conflict Driven Learning](https://www.kroening.com/papers/popl2013.pdf)
- [Dsat: A CDCL Solver for Finite Domain Constraint Satisfaction Problems](https://drops.dagstuhl.de/entities/document/10.4230/LIPIcs.SAT.2026.31)
- [Factoring Learned Clauses](https://drops.dagstuhl.de/entities/document/10.4230/LIPIcs.SAT.2026.28)
- [CaDiCaL 3.0](https://drops.dagstuhl.de/entities/document/10.4230/LIPIcs.SAT.2026.40)
- [SORB: Simplify, Order, Break, Repeat](https://drops.dagstuhl.de/entities/document/10.4230/LIPIcs.SAT.2026.4)
- [Migrating Solver State](https://drops.dagstuhl.de/entities/document/10.4230/LIPIcs.SAT.2022.27)
- [Lightweight Component Caching](https://doi.org/10.1007/978-3-540-72788-0_28)
- [Yices2 equality learner](https://github.com/SRI-CSL/yices2/blob/b11db7c43ef72f9bd77d66a9c588d3eae80eaf93/src/context/eq_learner.c#L152-L313)
- [Z3 EUF explanations](https://github.com/Z3Prover/z3/blob/efe5e946f16ec223a91d15101cefc49fb197534d/src/sat/smt/euf_solver.cpp#L279-L328)
