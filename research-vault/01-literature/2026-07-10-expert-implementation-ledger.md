# Expert QF_UF Implementation Ledger

Date: 2026-07-10

Scope: implementation candidates for making `euf-viper` exceptionally fast on
QF_UF, including techniques that are current, techniques that were tried and
later restricted or abandoned in their original setting, and techniques that
this repository has already tested negatively.

This is a research ledger, not a performance claim. Every proposed speed effect
is a hypothesis that must survive the stated A/B experiment.

## Evidence discipline

- **[S] Sourced fact**: stated by a linked primary paper, artifact, release, or
  official solver source.
- **[L] Local fact**: directly visible in this repository or in one of its
  recorded experiments.
- **[I] Inference**: an implementation hypothesis or explanation. It is not
  attributed to the cited authors and must be tested.
- **Reject** means reject the proposed implementation/configuration, not the
  underlying research idea in every solver or workload.

Priority means expected research value for this repository, not expected
speedup:

- **P0**: correctness, measurement, or proof prerequisite.
- **P1**: next controlled implementation experiment.
- **P2**: run after the relevant P0/P1 mechanism exists.
- **P3**: bounded exploratory work, not on the immediate critical path.
- **Archive**: do not repeat unchanged; revive only with the listed new
  discriminator.

## Reproducible source snapshot

### SAT engines and SAT techniques

1. **Clausal congruence closure (CCC).** Biere, Fazekas, Fleury, and Froleyks,
   "Clausal Congruence Closure," SAT 2024:
   [paper and metadata](https://doi.org/10.4230/LIPIcs.SAT.2024.6),
   [author PDF](https://cca.informatik.uni-freiburg.de/papers/BiereFazekasFleuryFroleyks-SAT24.pdf),
   [artifact](https://doi.org/10.5281/zenodo.11652423).
2. **Clausal equivalence sweeping.** Biere, Fazekas, Fleury, and Froleyks,
   "Clausal Equivalence Sweeping," FMCAD 2024:
   [paper and metadata](https://doi.org/10.34727/2024/isbn.978-3-85448-065-5_29),
   [author PDF](https://cca.informatik.uni-freiburg.de/papers/BiereFazekasFleuryFroleyks-FMCAD24.pdf).
3. **CaDiCaL 2.0.** Biere et al., CAV 2024:
   [Springer chapter](https://doi.org/10.1007/978-3-031-65627-9_7),
   [author PDF](https://cca.informatik.uni-freiburg.de/papers/BiereFallerFazekasFleuryFroleyksPollitt-CAV24.pdf).
4. **Current CaDiCaL snapshot.** Official
   [CaDiCaL 3.0.0 release](https://github.com/arminbiere/cadical/releases/tag/rel-3.0.0),
   commit `7b99c07f0bcab5824a5a3ce62c7066554017f641`;
   [external-propagator API](https://github.com/arminbiere/cadical/blob/rel-3.0.0/src/cadical.hpp#L1251-L1339),
   [example propagators](https://github.com/arminbiere/cadical/blob/rel-3.0.0/test/api/example_propagators.cpp),
   and [proof-related source](https://github.com/arminbiere/cadical/tree/rel-3.0.0/src).
5. **Current Kissat snapshot.** Official
   [Kissat 4.0.4 release](https://github.com/arminbiere/kissat/releases/tag/rel-4.0.4),
   commit `8af8e56f174b778aef3aa45af9f739b2a5f492c2`, and its
   [option declarations](https://github.com/arminbiere/kissat/blob/rel-4.0.4/src/options.h).
6. **Technique life span and ablation discipline.** Fleury and Kaufmann,
   "The Life Span of SAT Techniques," 2024:
   [arXiv](https://arxiv.org/abs/2402.01202).
7. **Structured bounded variable addition.** Haberlandt, Green, and Heule,
   "Effective Auxiliary Variables via Structured Reencoding," SAT 2023:
   [paper and metadata](https://doi.org/10.4230/LIPIcs.SAT.2023.11),
   [author PDF](https://www.cs.cmu.edu/~mheule/publications/SAT23-SBVA.pdf).

### EUF, DPLL(T), and eager versus lazy reasoning

8. **Incremental congruence closure.** Nieuwenhuis and Oliveras, "Fast
   Congruence Closure and Extensions," Information and Computation 2007:
   [author PDF](https://www.cs.upc.edu/~roberto/papers/IC06.pdf).
9. **Proof-producing congruence closure.** Nieuwenhuis and Oliveras, RTA 2005:
   [author PDF](https://www.cs.upc.edu/~roberto/papers/rta05.pdf).
10. **Exhaustive theory propagation.** Nieuwenhuis and Oliveras, CAV 2005:
    [author PDF](https://www.cs.upc.edu/~roberto/papers/cav05.pdf).
11. **DPLL(T).** Nieuwenhuis, Oliveras, and Tinelli, JACM 2006:
    [author PDF](https://www.cs.upc.edu/~roberto/papers/JACM2006.pdf).
12. **Small congruence proofs.** Flatt et al., "Small Proofs from Congruence
    Closure," FMCAD 2022:
    [arXiv](https://arxiv.org/abs/2209.03398),
    [author PDF](https://ztatlock.net/pubs/2022-fmcad-smallproofs/2022-fmcad-smallproofs.pdf).
13. **Partial Ackermannization.** Bruttomesso et al., "To Ackermann-ize or Not
    to Ackermann-ize?", LPAR 2006:
    [paper](https://disi.unitn.it/rseba/papers/lpar06_ack.pdf),
    [chapter DOI](https://doi.org/10.1007/11916277_38).
14. **Positive equality / eager PEUF.** Bryant, German, and Velev,
    "Exploiting Positive Equality in a Logic of Equality with Uninterpreted
    Functions," 1999: [arXiv](https://arxiv.org/abs/cs/9910014).
15. **Yices architecture and current policy.** Dutertre, "Yices 2.2," CAV 2014:
    [author PDF](https://yices.csl.sri.com/papers/cav2014.pdf). Official Yices
    documentation describes
    [dynamic Ackermann and theory-clause-cache parameters](https://yices.csl.sri.com/doc/parameters.html).
    In official source commit `b11db7c43ef72f9bd77d66a9c588d3eae80eaf93`,
    the [QF_UF defaults](https://github.com/SRI-CSL/yices2/blob/b11db7c43ef72f9bd77d66a9c588d3eae80eaf93/src/api/yices_api.c#L9456-L9470)
    enable non-Boolean and Boolean dynamic Ackermann lemmas and cache theory
    clauses up to size 12; the same snapshot has a dedicated
    [QF_UF symmetry implementation](https://github.com/SRI-CSL/yices2/blob/b11db7c43ef72f9bd77d66a9c588d3eae80eaf93/src/context/symmetry_breaking.c).
16. **Z3 current implementation.** Official
    [Z3 4.16.0 release](https://github.com/Z3Prover/z3/releases/tag/z3-4.16.0),
    [dynamic EUF Ackermann source](https://github.com/Z3Prover/z3/blob/z3-4.16.0/src/sat/smt/euf_ackerman.cpp),
    [SAT parameter declarations](https://github.com/Z3Prover/z3/blob/z3-4.16.0/src/params/sat_params.pyg#L57-L63),
    and [Programming Z3](https://z3prover.github.io/papers/programmingz3.html).

### External propagation, cardinality, and symmetry

17. **IPASIR-UP.** Fazekas et al., "Satisfiability Modulo User Propagators,"
    JAIR 2024:
    [journal article](https://doi.org/10.1613/jair.1.16163),
    [author PDF](https://cca.informatik.uni-freiburg.de/papers/FazekasNiemetzPreinerKirchwegerSzeiderBiere-JAIR24.pdf),
    [artifact](https://zenodo.org/records/13710465).
18. **AllDifferent filtering.** Regin, "A Filtering Algorithm for Constraints
    of Difference in CSPs," AAAI 1994:
    [AAAI PDF](https://cdn.aaai.org/AAAI/1994/AAAI94-055.pdf).
19. **Cardinality detection in CNF.** Biere, Le Berre, Lonca, and Manthey,
    SAT 2014:
    [author PDF](https://fmv.jku.at/papers/BiereLeBerreLoncaManthey-SAT14.pdf),
    [chapter DOI](https://doi.org/10.1007/978-3-319-09284-3_22).
20. **Encoding versus propagation.** Abio et al., "To Encode or to
    Propagate? The Best Choice for Each Constraint in SAT," CP 2013:
    [chapter DOI](https://doi.org/10.1007/978-3-642-40627-0_10),
    [author PDF](https://upcommons.upc.edu/bitstream/handle/2117/23253/Encode.pdf).
21. **SMT symmetry.** Deharbe et al., "Exploiting Symmetry in SMT Problems,"
    CADE 2011:
    [chapter DOI](https://doi.org/10.1007/978-3-642-22438-6_18),
    [author PDF](https://members.loria.fr/PFontaine/Deharbe6.pdf).
22. **Complete finite-model symmetry breaking.** Danco et al., "Complete
    Symmetry Breaking for Finite Models," AAAI 2025:
    [paper and metadata](https://doi.org/10.1609/aaai.v39i11.33217),
    [AAAI PDF](https://ojs.aaai.org/index.php/AAAI/article/download/33217/35372).
23. **Finite model finding baseline.** Claessen and Sorensson, "New Techniques
    that Improve MACE-style Finite Model Finding":
    [author PDF](https://fitelson.org/paradox.pdf).
24. **Symmetry-aware cube-and-conquer.** Araujo, Chow, and Janota,
    "Symmetries for Cube-And-Conquer in Finite Model Finding," CP 2023:
    [paper and metadata](https://doi.org/10.4230/LIPIcs.CP.2023.8).

### Proof production

25. **Flexible SMT proofs in cvc5.** Barbosa et al., IJCAR 2022:
    [chapter DOI](https://doi.org/10.1007/978-3-031-10769-6_3),
    [author PDF](https://theory.stanford.edu/~barrett/pubs/BRK%2B22.pdf).
26. **Alethe.** "Alethe: Towards a Generic SMT Proof Format":
    [arXiv](https://arxiv.org/abs/2107.02354),
    [official specification](https://verit.loria.fr/alethe.pdf).
27. **FRAT.** "FRAT: A Flexible Proof Format for SAT Solver-Elaborator
    Communication": [arXiv](https://arxiv.org/abs/2109.09665),
    [author PDF](https://www.cs.cmu.edu/~mheule/publications/FRAT-TACAS.pdf).
28. **LRAT.** "Efficient Certified RAT Verification":
    [arXiv](https://arxiv.org/abs/1612.02353).
29. **Proof logging for pseudo-Boolean solving.** "Practically Feasible Proof
    Logging for Pseudo-Boolean Optimization," CP 2025:
    [paper and metadata](https://doi.org/10.4230/LIPIcs.CP.2025.21).

## Local implementation baseline

The line references below identify the implementation observed for this ledger;
they will drift as `src/main.rs` changes.

- **[L]** `ExplainingTheory::close_congruence` repeatedly scans all
  applications and rebuilds a signature map until no class changes
  ([`src/main.rs`](../../src/main.rs#L1313)). `explain_equal` allocates fresh
  search arrays and performs a graph search for each explanation
  ([`src/main.rs`](../../src/main.rs#L1350)). The pure-conjunction shortcut has
  another repeated full application scan
  ([`src/main.rs`](../../src/main.rs#L4795)).
- **[L]** The normal CNF path builds `Vec<Vec<i32>>`
  ([`src/main.rs`](../../src/main.rs#L1410)), emits full pairwise Ackermann
  clauses when requested ([`src/main.rs`](../../src/main.rs#L1671)), and also
  has sparse chordal transitivity and full completion
  ([`src/main.rs`](../../src/main.rs#L1727)). Boolean subformulas are encoded
  recursively; equality atoms are shared, but arbitrary Boolean DAG nodes are
  not globally hash-consed ([`src/main.rs`](../../src/main.rs#L1476)).
- **[L]** The finite-domain path uses one-hot values with an at-least-one clause
  plus pairwise at-most-one clauses per term
  ([`src/main.rs`](../../src/main.rs#L2428)). It recognizes a small mandatory
  disequality clique and complete closed function tables, then adds verified
  adjacent-swap, value-precedence, diagonal-order, and table-lex constraints
  ([`src/main.rs`](../../src/main.rs#L2059),
  [`src/main.rs`](../../src/main.rs#L2165),
  [`src/main.rs`](../../src/main.rs#L2242)).
- **[L]** Direct finite equality channeling was accepted in
  [WMI smoke 139229](../06-results/2026-07-08-qf-uf-smoke-wmi-139229.md).
  Predicate-table channeling remains separately guarded and did not improve its
  recorded WMI experiment ([`JOURNAL.md`](../../JOURNAL.md#L67)).
- **[L]** The lazy CaDiCaL path solves a complete Boolean model, scans
  precomputed congruence candidate groups, adds violated clauses or at most 32
  explanation-derived conflicts, and calls `solve()` again
  ([`src/main.rs`](../../src/main.rs#L3379),
  [`src/main.rs`](../../src/main.rs#L3789)). It is model-level refinement, not a
  partial-trail theory propagator.
- **[L]** Linux x86_64 builds the vendored SAT Competition 2021 Kissat snapshot
  ([`vendor/kissat/README.md`](../../vendor/kissat/README.md)); other targets use
  the RustSAT binding. The local RustSAT CaDiCaL dependency is `0.7.5`
  ([`Cargo.toml`](../../Cargo.toml)) and does not expose CaDiCaL 3.0's complete
  external-propagator surface.
- **[L]** Certification writes a Boolean proof plus an EUF-CNF manifest
  ([`src/main.rs`](../../src/main.rs#L4301)). The finite-domain shortcuts are
  kept out of that route. Independent reconstruction of the base CNF remains a
  recorded proof obligation ([`PLAN.md`](../../PLAN.md)).
- **[L]** In the fixed 7,503-instance, two-second campaign, the current binary
  solved 6,874 instances, Z3 7,123, cvc5 6,831, and Yices 7,420, with no wrong
  answers or decisive disagreements. The report restricts its claims to that
  campaign and timeout
  ([campaign 142480](../06-results/2026-07-10-qf-uf-four-solver-wmi-142480.md)).
- **[L]** Prior local experiments rejected an unchanged root pigeonhole
  detector, global sequential AMO replacement, a direct finite-tail CaDiCaL
  swap, and a larger finite-domain cap:
  [pigeonhole](../06-results/2026-07-08-finite-pigeonhole-detector-rejected.md),
  [sequential AMO](../06-results/2026-07-08-finite-sequential-amo-rejected.md),
  [CaDiCaL tail](../06-results/2026-07-08-finite-cadical-tail-rejected.md), and
  [domain cap](../06-results/2026-07-08-finite-domain-cap-rejected.md).
  These are configuration-specific negative results, not universal results.

## Ranked implementation ledger

### L1. Incremental, proof-producing congruence closure

**Priority:** P1. **State:** absent as a shared implementation; the repository
has two scan-to-fixpoint closures.

**Mechanism and evidence**

- **[S]** Nieuwenhuis and Oliveras maintain pending class merges, use-lists for
  application occurrences, and a signature lookup table. Small-class merging
  bounds reprocessing and gives their stated `O(n log n)` incremental closure
  bound. Their proof-producing extension records merge justifications without
  worsening that closure bound (sources 8 and 9).
- **[S]** Their explanation algorithm uses a proof forest/union-find structure;
  source 12 later studies how to reduce the size of proofs extracted from
  congruence closure.
- **[L]** Both local closures rescan every application until fixed point, and
  `explain_equal` starts a fresh graph search for each requested reason.

**Why this may have been missed or underimplemented**

- **[I]** The scan implementation is compact and adequate when closure runs
  once on a small complete model. It becomes a different tradeoff when the
  model-refinement loop invokes closure and explanation repeatedly.
- **[I]** The existence of a fast SAT backend can hide theory-side repeated
  work on easy instances; current profiling must count signature visits and
  explanation work, not only wall time.

**Code mapping**

1. Introduce one rollback-capable `CongruenceEngine` used by
   `ExplainingTheory::close_congruence`, `congruence_closure`, and eventually the
   external propagator.
2. Store per-representative use-lists and canonical application signatures.
   On a merge, rehash only applications from the smaller affected use-list.
3. Preserve each asserted or congruence merge as a typed justification edge.
   Explanations must return existing SAT atom literals, not invent unregistered
   equalities.
4. Instrument `merges`, `signature_lookups`, `applications_rehashed`,
   `explanations`, `explanation_edges_visited`, and learned-clause width.

**Falsifiable microbenchmark**

- Add a direct engine test `cc-fanout(n,k)`: for every `i < n`, assert
  `a_i = b_i`; for every `j < k`, create both `f_j(a_i)` and `f_j(b_i)`, plus
  an equal number of unrelated applications. Increase `n` and `k` separately.
- Oracle: compare every equivalence class with the old closure and replay every
  returned explanation from only its antecedent equalities.
- Primary discriminator: application-signature visits as a function of
  `n * k`; wall time is secondary. **Reject** if the worklist engine does not
  reduce repeated signature visits on the scaling family, or if any partition
  or replayed reason differs semantically.
- After the unit test, run the existing hot-400 and full 7,503-instance gates
  with identical binaries and manifests. Do not promote on microbenchmark time
  alone.

**Risks**

- Rollback, path compression, and proof-parent maintenance interact. Use
  rollback-friendly union by size and avoid destructive compression unless its
  proof and undo semantics are explicit.
- A short closure operation can still yield a wide reason. L6 treats reason
  selection separately.

### L2. Staged CaDiCaL/IPASIR-UP EUF propagator

**Priority:** P1 after L1's rollback core; P0 proof contract before promotion.
**State:** model-level refinement exists; trail-level propagation does not.

**Mechanism and evidence**

- **[S]** IPASIR-UP provides assignment, decision-level, and backtrack
  notifications; callbacks for propagation with delayed reasons, complete-model
  checking, external clauses, and optional decisions; and a force-backtrack
  operation (source 17). CaDiCaL 3.0 exposes the corresponding official API and
  example propagators (source 4).
- **[S]** The paper describes the interface as usable with a proof-producing,
  incremental solver with inprocessing. It also states important restrictions:
  interactions use observed variables, observed variables are frozen for the
  discussed inprocessing model, and external clauses may contain only observed
  variables when that inprocessing is enabled.
- **[S]** The same paper warns that overriding the SAT decision heuristic has a
  high risk of damaging performance. Delayed explanations exist so a reason
  clause is materialized only if conflict analysis requests it.
- **[L]** The current loop learns only after a complete inconsistent Boolean
  model and restarts `solve()`.

**Why this may have been missed or underimplemented**

- **[I]** The current Rust binding/backend boundary offers ordinary incremental
  clause addition but not the complete CaDiCaL 3.0 callback surface. A small C++
  shim or a binding extension is prerequisite work.
- **[I]** Implementing full equality propagation first would combine too many
  risks: rollback correctness, reason generation, preprocessing visibility, and
  proof logging. A staged interface can test each claim independently.

**Code mapping and staged rollout**

1. **M0, model callback:** move the current final-model validator behind
   `cb_check_found_model`; emit the same conflict clauses through the external
   clause callback. Expected semantic behavior is intentionally unchanged.
2. **M1, trail conflicts:** observe only SAT variables for asserted equality and
   disequality atoms. Maintain rollback closure and report a conflict as soon as
   the partial trail makes a disequality's endpoints congruent.
3. **M2, theory propagation:** propagate an existing equality/disequality atom
   only when closure entails it. Supply its reason lazily through
   `cb_add_reason_clause_lit`.
4. **M3, optional decisions:** only after M1/M2 data exists, test a theory
   decision callback in a separate build. It is not part of the default plan.

**Falsifiable microbenchmark**

- Freeze a manifest of corpus instances for which the baseline reports more
  than one SAT call or at least one invalid model. Include the 2018 Goel hardware
  family, for example
  `QF_UF_pgm_protocol.3.prop5_ab_reg_max.smt2`, and stratify by baseline SAT-call
  count.
- M0 must produce the same result and same accepted/rejected model sequence as
  the existing loop. M1 is tested against M0; M2 against M1.
- Record `complete_models_checked`, `partial_theory_conflicts`,
  `theory_propagations`, requested reasons, reason width, SAT conflicts, and
  total time. **Reject M1/M2** if they do not reduce complete inconsistent
  models on the frozen target set, if callback overhead regresses the easy
  head, or if independent reason replay fails.

**Risks**

- Freezing every CNF variable would suppress useful inprocessing. Observe only
  theory atoms and required reason variables, then verify what CaDiCaL may still
  eliminate.
- External clauses added during search need an incremental proof semantics; a
  conventional final DRAT file alone does not establish that the theory clauses
  were valid.
- The SAT solver can report assignments in batches and backjump over levels.
  The external state must follow the API contract, not assume a naive push/pop
  event for every literal.

### L3. Per-function eager/lazy/online Ackermann hybrid

**Priority:** P1. **State:** dynamic whole-shape completion exists; per-function
selection and conflict-frequency activation do not.

**Mechanism and evidence**

- **[S]** Bruttomesso et al. report no absolute winner between full
  Ackermannization and lazy theory integration in their workloads. Their
  `PARTIAL` method greedily selects function symbols by estimated added
  Ackermann equalities versus removed interface equalities (source 13).
- **[S]** Current Yices QF_UF defaults enable dynamic Ackermann lemmas for both
  non-Boolean and Boolean applications, cap new lemmas/equality atoms, and cache
  only bounded-size theory clauses (source 15).
- **[S]** Z3 4.16's `euf_ackerman.cpp` keeps inference-frequency counters and
  limits generated Ackermann clauses relative to search activity/conflicts
  (source 16). Z3's integrated `sat.euf` path is marked preliminary in the
  official parameter source, so it is evidence for a mechanism, not a claim
  about Z3's default QF_UF route.
- **[L]** `euf-viper` has eager selection, full Ackermann clause generation, and
  an invalid-model path that can request full completion. The accepted dynamic
  Ackermann/chordal experiment is recorded in
  [its local report](../06-results/2026-07-09-dynamic-ackermann-chordal.md).

**Why this may have been missed or underimplemented**

- **[I]** The current decision is largely formula/shape level. A single hot
  function that repeatedly causes invalid models can justify eager clauses even
  when eagerly completing all functions is too expensive.
- **[I]** Predicate applications need a separate quota: Boolean Ackermann
  channeling can add many clauses while requiring different output literals
  from term-valued functions.

**Code mapping**

1. Compute per-symbol features before CNF emission: application count, distinct
   argument tuples, candidate-pair count, existing argument-equality atom count,
   output sort, and connected component.
2. Add an initial `none / selected symbols / all` Ackermann policy at the calls
   around `add_full_ackermann_axioms`.
3. During lazy refinement, increment a counter for the function responsible for
   each violated congruence. Promote only that function/component when a fixed,
   logged threshold is crossed; cap new equality atoms and clauses.
4. Keep the current complete-model validator as the soundness backstop.

**Falsifiable microbenchmark**

- Generate `ack-hot-cold(h,c,m)`: one symbol `hot` has `h` applications whose
  congruence is repeatedly relevant under Boolean choices; `c` other symbols
  each have `m` sparse applications whose argument pairs never become equal.
- Compare four fixed policies: fully lazy, fully eager, static per-function
  selection, and online frequency activation. Record generated equality atoms,
  Ackermann clauses, invalid models, SAT calls, and time.
- Add a corpus A/B over the frozen multi-call manifest from L2. **Reject** the
  selector if it cannot avoid cold-symbol clauses on the synthetic family, if it
  increases invalid models relative to fully lazy, or if its corpus gate loses
  current coverage/common-instance time.

**Risks**

- Pair-count estimates are only proxies for Boolean search. Never label a
  symbol "cheap" or "expensive" without logging the exact estimate.
- New equality atoms enlarge both SAT and e-graph state; enforce Yices-style
  absolute and term-relative quotas as hypotheses to tune, not copied constants.
- Learned clauses must remain valid if a symbol is promoted mid-search.

### L4. Native AllDifferent/Hall-set propagation over proved finite domains

**Priority:** P1 for the finite tail. **State:** one-hot plus binary/pairwise
clauses exists; native matching propagation does not.

**Mechanism and evidence**

- **[S]** Regin represents `AllDifferent` as a bipartite variable-value graph,
  finds a matching covering the variables, and filters edges using alternating
  paths/components so that unsupported values are removed (source 18). This is
  stronger than treating the constraint only as independent binary
  disequalities.
- **[S]** Biere et al. give syntactic and unit-propagation-based methods for
  detecting cardinality constraints after structure has been flattened into CNF
  (source 19).
- **[S]** Z3 4.16's SAT parameter source exposes native cardinality and
  pseudo-Boolean solving as well as several CNF encodings (source 16). The
  source establishes availability, not that generic QF_UF inputs reach or
  benefit from those handlers.
- **[L]** This encoder owns the one-hot/domain structure before flattening, so no
  CNF redetection is needed. The previous root pigeonhole detector did not fire
  on its target set, and global sequential AMO changed the per-term encoding
  without solving the cross-term Hall structure.

**Why this may have been missed or underimplemented**

- **[I]** The existing finite path treats exact-one constraints per term and
  disequalities between terms as separate clause families. Hall reasoning needs
  the combined variable-value graph.
- **[I]** A detected clique of pairwise-disequal constants establishes a lower
  bound on domain size, not an exhaustive finite universe. Native matching is
  sound only when each propagated variable's candidate-value list is proved
  exhaustive by emitted at-least-one semantics or an equivalent finite-model
  construction.

**Code mapping**

1. Retain a structured `FiniteDomainConstraint` beside the clauses emitted near
   the one-hot encoder: term nodes, value literals, exhaustive-domain witness,
   and distinctness edges/groups.
2. Start with complete-model Hall conflict detection. Then add incremental edge
   deletion/restoration and matching repair for the IPASIR-UP trail.
3. Explain a conflict with a Hall witness `X` where `|N(X)| < |X|`; explain a
   value removal by the Hall set that would become deficient if the edge were
   selected. Translate the witness to existing value literals and domain
   clauses.
4. Keep matching state separate per independently proved finite sort/domain.

**Falsifiable microbenchmark**

- `hall-k(k)`: create distinct values `a_1..a_(k+1)` and terms
  `x_1..x_k,z`. Each `x_i` has the exhaustive candidate set `a_1..a_k`; all
  `x_i` are different. Term `z` has candidates `a_1..a_(k+1)` and is different
  from every `x_i`; add `z != a_(k+1)`. Hall reasoning should derive that `z`
  must use `a_(k+1)` and expose the conflict.
- Check `k = 3..12`, then the exact finite-tail files
  `NEQ/NEQ023_size7.smt2`, `NEQ/NEQ048_size8.smt2`,
  `PEQ/PEQ018_size7.smt2`, and `SEQ/SEQ005_size8.smt2` under
  `benchmarks/smtlib-2025/QF_UF/QF_UF/`.
- Record matching repairs, Hall checks, propagations/conflicts, reason width,
  SAT conflicts, and end-to-end time. **Reject** if `hall-k` does not reduce the
  Boolean conflict search as `k` grows, if any reason fails replay, or if the
  exact tail remains unchanged while overhead appears on finite easy cases.

**Risks**

- A false exhaustiveness assumption is unsound. Every native constraint needs a
  checkable provenance object.
- Generalized arc consistency can spend more than it saves on sparse/easy
  domains. Schedule by activity and graph density, then test L10's adaptive
  encoding only if repeated explanations become the bottleneck.
- A Hall reason can be wide; proof logging may be cleaner in pseudo-Boolean form
  than as a large derived clause.

### L5. Independently reconstructable base CNF and replayable theory proofs

**Priority:** P0 before promoting L2, L4, or stronger symmetry. **State:** SAT
proof plus EUF manifest exists; independent base reconstruction is incomplete.

**Mechanism and evidence**

- **[S]** Proof-producing congruence closure records why equalities were merged
  and turns a contradictory disequality into an EUF-valid explanation (source
  9).
- **[S]** CaDiCaL 2.0/3.0 support multiple propositional proof interfaces,
  including DRAT, FRAT, LRAT, and VeriPB-related tracing in current official
  source (sources 3 and 4). FRAT is designed as solver-to-elaborator
  communication; LRAT supplies explicit checking hints (sources 27 and 28).
- **[S]** cvc5's proof architecture separates trusted proof rules from lazy
  proof construction and checking (source 25). Alethe is a candidate common SMT
  proof language, not a requirement for the first local checker (source 26).
- **[S]** IPASIR-UP notes that clauses inserted during an incremental derivation
  require incremental proof semantics; treating every such clause as if it were
  present before search loses that temporal distinction (source 17).
- **[L]** The current manifest can bind the generated CNF and theory clauses, but
  a checker does not yet reconstruct every base clause from the SMT input.

**Why this may have been missed or underimplemented**

- **[I]** Emitting the same CNF twice, once for solving and once for checking,
  can look redundant while the encoder is changing quickly. It is nevertheless
  the boundary that prevents a solver-side encoding bug from certifying itself.
- **[I]** Replacing the whole format with Alethe now would expand scope without
  first removing the local trusted-base gap.

**Code mapping**

1. Give every input atom, Tseitin node, transitivity edge, Ackermann clause, and
   learned theory clause a stable manifest identifier and provenance record.
2. Build a checker-side encoder from parsed SMT terms, independent of the
   solver's `CnfProblem` vectors. Compare the reconstructed base clause multiset
   and variable map with the manifest.
3. Replay each EUF clause by running proof-producing closure on its negated
   antecedents. For Hall or symmetry clauses, add a distinct checked rule or
   VeriPB-style subproof; never label them generic EUF lemmas.
4. Check the SAT proof only after base and theory additions have been accepted.
   Bind all files and solver options by digest.

**Falsifiable microbenchmark**

- Produce one independently checked SAT model and one UNSAT certificate for
  each active route. For UNSAT, mutate one at a time: an input atom map, a
  Tseitin clause, one theory antecedent, a congruence parent edge, and the final
  SAT proof. For SAT, mutate one model interpretation entry. Every mutation must
  be rejected at the intended layer.
- Regenerate a certificate twice and require deterministic semantic manifests
  (allowing explicitly normalized nondeterministic proof bytes if necessary).
- **Reject promotion of a new native rule** if the checker cannot reject a
  one-literal corruption of that rule or if the base CNF is accepted only by
  trusting the solver-emitted copy.

**Risks**

- Proof work is not expected to improve solve time; it is a promotion gate.
- Incremental clause deletion and extension variables complicate FRAT/LRAT
  elaboration. Keep the first checker route monotone if necessary and measure
  proof size separately from solve time.

### L6. Smaller, cached theory explanations

**Priority:** P2 after L1 instrumentation. **State:** graph-search explanations
exist; cost-aware selection and bounded cache do not.

**Mechanism and evidence**

- **[S]** Flatt et al. give algorithms for extracting smaller congruence proofs,
  including a greedy `O(n log n)` approach without changing the asymptotic
  closure bound (source 12). Their reported proof-size results apply to their
  benchmarks, not automatically here.
- **[S]** Current Yices exposes `cache-tclauses` and `tclause-size`; its QF_UF
  defaults cache only small theory clauses, with size 12 in the cited source
  snapshot (source 15).
- **[L]** Local explanation searches allocate fresh state, and the model
  conflict path caps the number of selected conflicts but does not optimize a
  global explanation cost.

**Why this may have been missed or underimplemented**

- **[I]** Any valid path is enough for correctness, so path quality becomes
  visible only after logging reason width, repeated pairs, and conflict utility.
- **[I]** Caching all explanations is likely counterproductive; equality classes
  and trails change, while small clauses are more reusable.

**Code mapping**

1. Reuse L1's proof forest and expose multiple candidate justifications for a
   congruence edge.
2. Add a deterministic greedy cost (`number of distinct SAT antecedents` first,
   then proof edges) and deduplicate antecedent literals.
3. Cache only clauses at or below a configurable width and key them by
   canonical SAT literals, not mutable union-find representatives.
4. Count reason requests separately from reasons generated; delayed IPASIR-UP
   reasons should not be built eagerly.

**Falsifiable microbenchmark**

- Build a diamond proof graph with one long asserted-equality path and one short
  path to the same equality, then make that equality contradict a disequality.
  Scale only the long branch.
- Require the greedy explanation to choose the bounded short antecedent set and
  replay as EUF valid. Add repeated conflicts for the same canonical clause and
  verify a cache hit without stale-state use.
- On the corpus target set, record reason width distribution, construction
  time, cache hit rate, SAT conflict quality, and total time. **Reject** if
  clauses shrink but construction plus cache overhead increases total work, or
  if SAT search worsens enough to fail the unchanged gate.

**Risks**

- The smallest local proof is not necessarily the best learned SAT clause.
  Preserve a switch between first-found, greedy-small, and activity-weighted
  cost.
- Caches across pop/backtrack are sound only for globally valid clauses over
  stable atom identifiers.

### L7. Complete symmetry breaking in its proved scope, then guarded extension

**Priority:** P1 for one-table finite instances; P2 for multiple tables.
**State:** strong but partial static symmetry constraints exist.

**Mechanism and evidence**

- **[S]** Deharbe et al. formalize SMT symmetries as formula-preserving
  permutations and derive symmetry-breaking predicates for interchangeable
  constants (source 21).
- **[S]** Danco et al. compute compact canonizing permutation sets for finite
  models with a single binary operation (magmas), yielding one canonical member
  per isomorphism class in that stated scope (source 22).
- **[S]** Paradox uses finite-model symmetry techniques such as assigning least
  available domain elements during model construction (source 23).
- **[S]** Current Yices has dedicated range/value symmetry code for QF_UF
  (source 15). Its presence is evidence that ordinary range symmetry is not a
  novel omission, not evidence for a local performance result.
- **[L]** The local encoder validates adjacent constant swaps against the whole
  formula and emits value precedence, diagonal order, and table lex leaders.
  It does not claim a complete canonizing set.

**Why this may have been missed or underimplemented**

- **[I]** Verified adjacent generators establish sound formula automorphisms,
  but a hand-selected lex family need not intersect every model orbit exactly
  once.
- **[I]** The 2025 complete result is narrow enough to use directly for a
  recognized single closed binary table. Extending its theorem to several
  functions, predicates, partial tables, or fixed constants is new work and must
  be labeled as such.

**Code mapping**

1. Add a recognizer for the exact single-binary-table conditions required by
   source 22. Fall back to current verified constraints outside that scope.
2. Generate the paper's canonizing permutations/constraints for domain size
   within a guarded cap. Record the automorphism witness for every permutation.
3. For multiple tables, first compute the actual formula automorphism group
   (respecting fixed constants and predicates), then test candidate canonizing
   sets by exhaustive small-domain orbit enumeration. This extension is **[I]**.
4. Emit symmetry clauses with distinct proof provenance; they are
   satisfiability-preserving additions, not EUF consequences.

**Falsifiable microbenchmark**

- Exhaustively enumerate all `3^9 = 19,683` binary tables on a three-element
  domain. Compute orbits under all six domain permutations. The guarded encoder
  must accept exactly one table per orbit in its proved single-table scope.
- For domain four, exhaustively check bounded structured families and randomly
  sampled full tables against all 24 permutations; this is a bug finder, not a
  completeness proof.
- Then run `PEQ014_size9.smt2`, `PEQ014_size10.smt2`, and
  `PEQ014_size11.smt2`, recording clauses, surviving symmetric models, SAT
  conflicts, and time. **Reject** if the exhaustive domain-three oracle finds
  zero or multiple representatives for any orbit, or if the target gate gains
  clauses without reducing search.

**Risks**

- Canonizing constraints can be larger than the search they remove.
- A formula constant with a special syntactic role is not interchangeable even
  if it shares a sort. The existing whole-formula invariance check remains a
  mandatory guard.
- Completeness in the single-operation paper must not be advertised for a
  multi-operation extension until independently proved.

### L8. Preserve Boolean DAGs and isolate clausal congruence closure

**Priority:** P1 for exact DAG sharing; P2 for solver-side CCC. **State:** atom
sharing exists; general Boolean DAG sharing and modern CCC do not.

**Mechanism and evidence**

- **[S]** CCC extracts AND, XOR, and ITE gate definitions from CNF, hashes gates
  modulo congruence, substitutes equivalent outputs, and can run again during
  inprocessing after units, shrinking, vivification, or elimination reveal new
  structure (source 1). Its implementation is proof-producing.
- **[S]** Clausal equivalence sweeping instead runs a small embedded SAT solver
  over a clausal environment to prove equivalences (source 2). It is a distinct,
  potentially more expensive mechanism.
- **[S]** Kissat 4.0.4 exposes options for congruence/gate extraction, sweeping,
  factorization, and related preprocessing (source 5).
- **[L]** The local encoder recursively Tseitin-encodes Boolean syntax and can
  duplicate an identical non-atom subformula reached from different parents.
  The Linux backend predates current Kissat CCC.

**Why this may have been missed or underimplemented**

- **[I]** Once the parser tree is flattened to clauses, a SAT solver must spend
  work rediscovering structure the front end already knew. Exact hash-consing is
  lower risk than relying first on gate recovery.
- **[I]** A previous whole-backend experiment cannot identify whether CCC,
  sweeping, a changed branching heuristic, or another pass caused the outcome.

**Code mapping**

1. Canonicalize immutable Boolean nodes (`not`, commutative `and/or/xor`, and
   ordered `ite`) and memoize their Tseitin literal. Do not merge theory atoms
   beyond the existing typed atom canonicalization.
2. Retain gate metadata next to emitted clauses so clause counts can be
   attributed to source nodes and compared with a solver's recovered gates.
3. In a pinned Kissat 4 backend, ablate `congruence` alone first, then
   `congruenceonce`, and only then combine it with sweeping. Keep every unrelated
   option fixed.

**Falsifiable microbenchmark**

- `bool-dag(k,r)`: construct one nested AND/XOR/ITE network of `k` nodes and
  reference the exact same immutable subexpressions from `r` independent
  top-level contexts. The memoized encoder must keep Tseitin variables/clauses
  independent of `r` except for the new parent connections.
- Compare baseline encoding, front-end DAG sharing, solver CCC only, and both.
  Verify SAT/UNSAT equivalence and certificates. Record source nodes, CNF
  variables/clauses, extracted gates/equivalences, preprocessing time, and total
  time.
- **Reject** DAG sharing on any semantic mismatch. Reject solver CCC for this
  project if it does not discover additional equivalences after front-end
  sharing or if its cost fails the unchanged corpus gate.

**Risks**

- Canonicalization rules must preserve ordered ITE branches and sort identity.
- Solver gate extraction is syntactic and can be quadratic without safeguards;
  Kissat 4.0.4's release specifically mentions a fix for quadratic ITE gate
  extraction. Pin the fixed tag.

### L9. Modern CaDiCaL/Kissat pass-by-pass backend ablation

**Priority:** P2. **State:** current releases are not the default local engines;
an earlier broad finite-tail swap was negative.

**Mechanism and evidence**

- **[S]** CaDiCaL 3.0.0's official release enables bounded variable addition and
  factorization by default, and changes incremental variable declaration to
  distinguish extension variables needed by proof/incremental workflows
  (source 4). Its release notes say factorization can help some hard
  combinatorial/pigeonhole formulas; that is not evidence for local QF_UF gains.
- **[S]** Kissat 4.0.4 includes CCC, sweeping, BVA/factorization, and many
  independently configurable passes. Its release notes disable `fastel` by
  default and delay BVA/factorization on larger formulas (source 5).
- **[S]** The SAT-technique life-span study finds that broad universal claims
  such as "this old technique always helps," "always hurts," or is fully
  simulated by another technique are not supported by its ablations (source 6).
- **[L]** A direct CaDiCaL finite-tail substitution timed out on all four chosen
  hard files. It tested a backend configuration, not native Hall reasoning or a
  particular modern preprocessing pass.

**Why this may have been missed or underimplemented**

- **[I]** The vendored Kissat was deliberately stabilized and namespaced. That
  makes upgrades nontrivial, while whole-version comparisons obscure the
  mechanism responsible for a regression.
- **[I]** BVA/factorization may match exact-one/table clauses, but extension
  variables may also complicate model projection and proof manifests.

**Code mapping**

1. Add side-by-side, version-stamped backend builds; do not replace the accepted
   default during the experiment.
2. Dump the effective solver options and binary digest into every result row.
3. Test one delta at a time: new baseline with conservative options; CCC;
   sweep; BVA; factor; then only combinations justified by single-pass data.
4. Validate model projection, incremental clause addition, interruption, and
   proof checking before any timing campaign.

**Falsifiable microbenchmark**

- Use four strata: tiny easy head, the L2 multi-call set, the four exact finite
  tail files from L4, and a deterministic `hall-k`/exact-one CNF series.
- For each pass record preprocessing CPU, peak RSS, input/output variables and
  clauses, extension variables, solved status, proof-check time, and total time.
- **Reject** any pass that gains no solves on its target stratum and worsens the
  accepted aggregate gate. A new release is not promoted merely because its
  version number is newer.

**Risks**

- Option names and defaults are release-specific. Persist the effective option
  table, not just command-line deltas.
- Proof and incremental behavior can change when variables are eliminated or
  introduced. This must pass L5 before speed evaluation counts.

### L10. Activity-driven switch from propagation to encoding

**Priority:** P2 after L4. **State:** neither native Hall propagation nor an
adaptive switch exists.

**Mechanism and evidence**

- **[S]** Abio et al. analyze the choice between native propagation with lazy
  explanations and CNF encoding; constraints that repeatedly generate many
  explanations can favor encoding (source 20). Their results concern their
  constraints and solvers, not this EUF workload.
- **[S]** Structured BVA introduces extension variables to compact repeated CNF
  structure and studies ordering-sensitive BVA heuristics (source 7).
- **[L]** Global sequential AMO did not solve the chosen finite tail. It changed
  every per-term exact-one constraint even when no constraint was active.

**Why this may have been missed or underimplemented**

- **[I]** The prerequisite native propagator did not exist. Once it does, the
  solver can distinguish dormant Hall constraints from a small number that emit
  repeated reasons.
- **[I]** The appropriate encoded object is a cross-term Hall/cardinality
  relation, not another unconditional encoding of each term's AMO.

**Code mapping**

1. For every `FiniteDomainConstraint`, count wakeups, matching repairs,
   propagations, conflicts, unique explanation clauses, and total literals
   emitted.
2. If a fixed logged threshold is crossed, add a selected totalizer/network/PB
   encoding for that constraint or Hall subset and retire only redundant future
   propagations. Keep the model checker active.
3. Compare a hand-selected encoding with CaDiCaL/Kissat BVA output; do not stack
   both blindly.

**Falsifiable microbenchmark**

- Create two constraints in one formula: a large dormant `AllDifferent` whose
  value edges stay unassigned, and a smaller active one forced through repeated
  edge removals. The adaptive policy must encode only the active constraint.
- Compare always-propagate, always-encode, and adaptive with the same SAT seed.
  Record emitted clauses/literals, explanations, propagator CPU, conflicts, and
  total time.
- **Reject** if the switch cannot identify the active constraint before most of
  the explanation cost has already been paid, or if the resulting proof cannot
  distinguish input-derived encoding clauses from theory-derived lemmas.

**Risks**

- Adding a large encoding late can duplicate already learned explanations.
- Thresholds tuned on four tail files will overfit. Freeze them before the full
  corpus run and report sensitivity around the chosen value.

### L11. Online symmetry pruning through the external-propagator boundary

**Priority:** P3 after L2 and L7. **State:** static symmetry breaking only.

**Mechanism and evidence**

- **[S]** IPASIR-UP was evaluated not only for SMT integration but also for SAT
  modulo Symmetries, where a propagator inspects partial assignments and adds
  symmetry information during search (source 17).
- **[S]** Static complete canonizing constraints are available only in the
  finite-model scope stated by source 22; online canonicality checks offer a way
  to prune richer structures without eagerly materializing every lex constraint.
- **[L]** The current finite encoder emits all selected symmetry constraints
  before SAT search and has no access to partial assignments.

**Why this may have been missed or underimplemented**

- **[I]** Static constraints were implementable with the existing black-box SAT
  API. Online pruning needs the same trail callback infrastructure as L2 and a
  canonicality certificate distinct from EUF reasoning.

**Code mapping**

1. Reuse observed finite-value literals from L4; maintain the partially assigned
   operation table under rollback.
2. When a proved formula automorphism maps the partial table to a lexicographically
   smaller compatible partial table, add the corresponding symmetry-breaking
   clause. Start with complete models, then partial models.
3. Keep static L7 and online L11 as separate configurations to measure duplicate
   work.

**Falsifiable microbenchmark**

- Enumerate all domain-three single-binary-operation models. Compare no
  symmetry, current static constraints, complete L7, online-only, and
  complete-plus-online. Every symmetry mode must return one representative per
  orbit under the same oracle used in L7.
- Record callback count, canonicality checks, clauses, rejected complete and
  partial models, and total time. **Reject** online pruning if it removes an
  orbit, leaves duplicates in its claimed scope, or merely duplicates complete
  static constraints at higher cost.

**Risks**

- A symmetry clause is satisfiability-preserving only relative to a proved
  automorphism and chosen representative order.
- Canonicality checking itself can dominate at each partial assignment; schedule
  only after meaningful table changes.

### L12. Positive-equality specialization for a syntactically proved fragment

**Priority:** P3. **State:** no explicit PEUF specialization.

**Mechanism and evidence**

- **[S]** Bryant, German, and Velev exploit positive equality and maximally
  diverse interpretations to simplify an eager equality encoding in their PEUF
  fragment (source 14).
- **[L]** The repository contains PEQ families, but a benchmark family name does
  not prove that every input satisfies the paper's polarity restrictions.

**Why this may have been missed or underimplemented**

- **[I]** A sound fragment recognizer and a differential model checker are more
  work than a filename-based route. The technique is unsafe as a generic QF_UF
  shortcut.

**Code mapping**

1. Normalize polarity through the Boolean DAG and prove the exact positive
   equality conditions for every candidate equality/function occurrence.
2. Apply the specialized encoding only when the recognizer emits a checkable
   witness; otherwise use the ordinary hybrid.

**Falsifiable microbenchmark**

- Generate paired formulas differing by one polarity flip. The positive member
  must be accepted by the recognizer and agree with the generic solver; the
  flipped member must be rejected by the recognizer.
- Audit every `PEQ/` input rather than assuming eligibility. **Reject** if the
  eligible subset is negligible or the specialized encoding fails to reduce
  its explicitly predicted variables/clauses.

**Risks**

- A polarity error is a soundness error. This stays P3 until L5 can check the
  transformation.

## Historically restricted, abandoned, or locally negative directions

These entries prevent an old idea from being rediscovered without the evidence
that caused it to be restricted. "Abandoned" here always means in the cited
implementation line or local experiment, not by the entire field.

| Direction | Evidence | Ledger decision | New discriminator required to revive |
| --- | --- | --- | --- |
| Lazy hyper-binary resolution, tree look-ahead, simple probing, and repeated HBR plus equivalent-literal substitution as the main equivalence engine | **[S]** The CCC paper describes these earlier Kissat equivalence attempts and motivates direct clausal congruence; repeated HBR/ELS may need many rounds. | **Archive as a primary mechanism.** | A pass-isolated ablation on formulas where direct CCC cannot extract the relevant equivalence. |
| Blocked-clause decomposition as the route to equivalences | **[S]** The CCC comparison notes limitations for inprocessing/proof support in that cited line. | **Archive for this proof-producing incremental path.** | A current proof-producing implementation compatible with external propagation, tested independently. |
| Internal SAT sweeping without a strict effort limit | **[S]** CCC and clausal sweeping discuss embedded SAT work and the need for bounded/preempted effort. | **Do not enable unbounded.** | Per-instance effort counters showing useful equivalences before the cap and no easy-head loss. |
| Hash-table acceleration of every gate-extraction candidate | **[S]** The CCC paper reports an attempted hash-table approach whose cost was comparable to marking in that implementation. | **Do not copy as an assumed optimization.** | Profiled evidence that this encoder's gate distribution changes the cost balance. |
| Full Ackermannization for every function | **[S]** Source 13 finds no absolute eager/lazy winner. **[L]** Local work promoted shape-gated dynamic completion, not unconditional full completion. | **Archive as a universal policy; retain as an A/B arm.** | Per-function cost/activity evidence from L3. |
| Exhaustive theory propagation at every opportunity | **[S]** Source 10 establishes the logical framework; it does not establish that every propagation schedule is fastest. **[S]** IPASIR-UP supports delayed reasons. | **Stage conflicts before propagations.** | M1/M2 data showing fewer complete models and acceptable reason/notification cost. |
| Root-only pigeonhole detection | **[L]** The local detector did not fire on its frozen target and added measurable overhead. | **Archive unchanged.** | L4's proved exhaustive domains plus an actual Hall witness and matching-state metrics. |
| Global pairwise-to-sequential AMO replacement | **[L]** All four selected finite targets still timed out. | **Archive unchanged.** | A constraint-specific activity signal or direct evidence that clause count, rather than cross-term Hall reasoning, is limiting. |
| Unconditional finite predicate-table channeling | **[L]** The guarded local implementation did not improve its recorded WMI experiment; direct finite equality channeling, by contrast, was accepted. | **Keep guarded; do not conflate with Boolean dynamic Ackermann.** | A predicate-heavy frozen target where generated channel clauses reduce invalid models or SAT calls. |
| Increasing the finite-domain cap with the same encoding | **[L]** Cap 8 to 11 did not solve the chosen tail. | **Archive unchanged.** | A changed proof system: L4 matching, L7 complete symmetry, or L10 adaptive encoding. |
| Direct CaDiCaL substitution on the finite tail | **[L]** The tested four-instance swap timed out throughout. | **Archive unchanged.** | Pass-isolated CaDiCaL 3 data or IPASIR-UP integration, not another whole-backend swap. |
| Generic Kissat release replacement | **[L]** The prior [frontier audit](2026-07-10-frontier-qf-uf.md) records that a broad Kissat 4 experiment was not promoted. **[S]** Kissat defaults and techniques have changed materially since the vendored 2021 snapshot. | **No wholesale promotion.** | L8/L9 single-pass attribution with pinned options, proofs, and full gates. |
| Immediate Alethe rewrite | **[S]** Alethe and cvc5 show viable modular SMT-proof designs. **[L]** The local immediate gap is independent base-CNF reconstruction. | **Defer.** | L5 complete, followed by a concrete interoperability consumer that justifies translation cost. |
| SAT decision override from theory | **[S]** IPASIR-UP exposes it and explicitly warns of performance risk. | **M3 only; off by default.** | M1/M2 traces that predict a decision and a separate fixed-seed A/B. |
| Treating Kissat `fastel` or factor/BVA defaults as universal advice | **[S]** Kissat 4.0.4 disables `fastel` by default and schedules factor/BVA conservatively; source 6 cautions against universal life-span claims. | **Ablate, do not infer.** | Version-pinned target-stratum evidence from L9. |

## Cross-entry implementation order

1. **Measurement first:** add closure, explanation, invalid-model, SAT-call,
   finite-domain, and proof-size counters without changing decisions.
2. **L1:** build and differentially test one rollback/proof-producing closure.
3. **L5 base layer:** independently reconstruct current ordinary EUF CNF and
   replay current theory clauses.
4. **L3:** test per-function static and online Ackermann policies using existing
   solver APIs.
5. **L2 M0/M1:** establish CaDiCaL 3/IPASIR-UP binding and partial-trail
   conflicts; do not begin with decisions.
6. **L4:** retain finite-domain structure and add complete-model, then
   partial-trail Hall reasoning with checked witnesses.
7. **L6 and L10:** optimize reason size and decide when active constraints should
   be encoded only after measurements identify those costs.
8. **L7:** add complete symmetry only in the proved single-table scope; keep the
   multi-table extension experimental.
9. **L8/L9:** evaluate front-end DAG sharing and modern SAT passes one mechanism
   at a time.
10. **L11/L12:** pursue only after the higher-priority gates preserve current
    correctness and corpus behavior.

## Promotion protocol

Every ledger experiment should produce one machine-readable row per solver run
with at least:

- repository revision, binary digest, backend release/commit, effective solver
  options, feature flags, seed, host, and timeout;
- input digest and benchmark stratum;
- result, independent oracle result where available, wall/user time, and peak
  RSS;
- CNF variables/clauses before and after preprocessing;
- theory merges, signature lookups, explanation requests/widths, invalid
  models, SAT calls, and learned theory clauses;
- for finite reasoning: candidate edges, matching repairs, Hall witnesses, and
  symmetry clauses/orbits;
- certificate digest, checker result, and proof-check time.

Promotion requires, in order:

1. differential semantic tests and adversarial mutation tests;
2. the candidate's stated microbenchmark discriminator;
3. a frozen targeted manifest chosen before seeing candidate timings;
4. the existing hot/easy regression gate;
5. the full 7,503-instance campaign with the accepted binary rerun as a control.

No paper result, solver release note, clause-count reduction, or selected
benchmark win substitutes for step 5. Conversely, one negative whole-backend
run does not refute a mechanism that was not isolated in that run.
