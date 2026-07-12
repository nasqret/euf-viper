# Primary-Source Refresh For The Best-Overall Campaign

Date: 2026-07-12

Status: bounded audit; novelty labels remain provisional

## Competitive Boundary

| System | Audited boundary | Campaign consequence |
| --- | --- | --- |
| Yices2 2.7 | Boolean-aware rollback e-graph, partial-trail propagation, explanations, dynamic Ackermannization, theory-clause caching, and range symmetry | Primary performance target; generic rollback EUF or dynamic Ackermann is not novel |
| Z3 4.16 | Classic CDCL(T) plus optional SAT-owned EUF, dynamic Ackermann, proof hints, user propagation | Compare default and `sat.euf=true`; neither architecture is a novelty target |
| cvc5 | Equality engine, UF cardinality/symmetry, broad proof formats, lazy `distinct` in tagged 1.3.3 | Proof-oriented control; the local `1.3.4` label needs an exact commit/hash |
| OpenSMT 2.9.2 | Mature QF_UF CDCL(T), second in SMT-COMP 2025 QF_Equality | Add as a mandatory speed/coverage comparator |
| Kissat 4.0.4 | Modern nonincremental SAT with congruence, sweeping, factor/BVA, vivification, and phase work | Current project uses SC2021 code; run a causal backend upgrade before new SMT attribution |
| CaDiCaL | Incremental proof-producing SAT and IPASIR-UP | Preferred foundation for rollback/user-propagator experiments |

Primary sources:

- [Yices 2.2 architecture](https://yices.csl.sri.com/papers/cav2014.pdf)
- [A Modern View on MCSat, 2026](https://arxiv.org/abs/2607.03777)
- [Z3 4.16.0 release](https://github.com/Z3Prover/z3/releases/tag/z3-4.16.0)
- [Z3 internals](https://z3prover.github.io/papers/z3internals.html)
- [cvc5 1.3.3 release](https://github.com/cvc5/cvc5/releases/tag/cvc5-1.3.3)
- [OpenSMT 2.9.2](https://github.com/usi-verification-and-security/opensmt/releases/tag/v2.9.2)
- [Kissat 4.0.4](https://github.com/arminbiere/kissat/releases/tag/rel-4.0.4)
- [IPASIR-UP](https://cs.stanford.edu/~preiner/publications/2023/FazekasNPKSB-SAT23.pdf)

## Armin Biere And Modern SAT Implications

[Clausal Congruence Closure](https://doi.org/10.4230/LIPIcs.SAT.2024.6)
extracts AND/XOR/ITE structure from CNF and merges isomorphic gates during
pre/inprocessing. It directly motivates two controls:

1. enable current Kissat congruence on unchanged euf-viper CNF;
2. compare that with source-level typed congruence before Tseitin emission.

Only the second can support a differentiated cross-layer claim, and only if it
beats the first after construction cost.

The
[SAT Competition 2025 solver report](https://cca.informatik.uni-freiburg.de/papers/BiereFallerFleuryFroleyksPollitt-SAT-Competition-2025-solvers.pdf)
records the transfer of clausal congruence, BVA/factoring, tick scheduling,
revisited vivification, lucky phases, equivalence sweeping, and semantic
definition mining from Kissat to CaDiCaL. It also emphasizes proof-generation
cost: CaDiCaL's LRAT-oriented path may lose raw solving time but win combined
production/checking time. The campaign must therefore report solve-only and
solve-plus-check scores.

[Revisiting Clause Vivification](https://ceur-ws.org/Vol-4008/POS_paper05.pdf)
shows that small implementation/scheduling choices can reverse a mature pass's
performance. Theory vivification must be budgeted and factorially ablated; a
literal-removal count is not evidence.

## Proof-Complexity Controls

- Plain resolution can be exponentially weak on pigeonhole encodings, but that
  does not imply every finite QF_UF tail is exponentially hard.
- DRAT with discovered auxiliary variables can have polynomial pigeonhole
  proofs; native cardinality/PB and theory literals change the proof system.
- [Automated Reencoding Meets Graph Theory](https://arxiv.org/abs/2603.27774)
  proves that idealized BVA cannot reach the best product-style AMO encodings.
  Typed source recovery therefore has a real role beyond better BVA heuristics.
- [Near-Optimal Cardinality Encodings](https://arxiv.org/abs/2603.28954)
  supplies a 2026 compact-CNF control, not a novelty claim.
- Matching/Hall propagation, native cardinality, PB explanations, and practical
  PB proof logging are established. The surviving integration question is
  automatic non-uniform QF_UF range proof plus checked EUF/PB bridges.

## Explanation And Certificate Boundary

[Small Proofs from Congruence Closure](https://arxiv.org/abs/2209.03398)
establishes efficient smaller explanation construction. A new claim must use a
different objective, such as predicted SAT impact, reuse, and certificate cost,
and compare against shortest/small-proof controls.

Z3 and cvc5 both have substantial proof infrastructure. The differentiated
deliverable is not “proof-producing EUF” in isolation; it is a low-overhead,
independently reconstructed chain from SMT-LIB through base CNF, migration
bridges, and the final SAT proof.

## Finite-Model Boundary

[Complete Symmetry Breaking for Finite Models](https://doi.org/10.1609/aaai.v39i11.33217),
cube-based isomorph-free search, certified symmetry breaking, MDD propagation,
and bitset filtering are established. Multi-table typed QF_UF integration may
still be publishable, but complete canonization alone is not.

The strongest surviving finite novelty candidate is a bounded live frontier of
canonical partition/function-memory states with independently checked
transitions and covers. A bit-sliced quotient swarm is plausible but high risk;
it remains blocked until scalar frontier width, state reuse, and lane occupancy
are measured.

## Provisional Novelty Ranking

| Candidate | Label |
| --- | --- |
| Canonical quotient-state/frontier transducer | Strong plausible algorithmic gap; requires deeper prior-art search |
| Per-component representation migration with stable IDs and checked bridges | Plausible narrowed combination |
| Conditional theory quotient before Tseitin with revocable shares | Plausible narrowed combination |
| Bit-sliced valid quotient models plus checked exhaustive cover | Plausible, high risk |
| Adequate-range Hall/PB bridge | New integration, known ingredients |
| Multi-table orbit pruning | Weak novelty unless every partial prune is typed and replayable |
| Parser, backend update, flat storage, PGO, generic inprocessing | Engineering only |

Before any “first” claim, search mechanism-level terms across SMT, SAT, finite
model finding, CP/PB, e-graphs, theorem proving, patents, and dissertations; pin
and inspect current Z3, Yices2, cvc5, OpenSMT, Kissat, CaDiCaL, and relevant
finite-model sources. Run known-ingredient ablations and withdraw the claim if
one ingredient explains the full gain.
