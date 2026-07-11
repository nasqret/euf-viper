# QF_UF / EUF Novelty Exclusion Map

Date: 2026-07-11

Status: primary-source exclusion map and experiment boundary. This is not a
claim that any proposed combination is patentable, unpublished, or absent from
private solvers.

## Scope

The target is one-shot, many-sorted, quantifier-free equality with
uninterpreted functions (`QF_UF`), including Boolean terms used as function
arguments or results. The performance target is the strongest public
implementations, especially Yices2 and Z3, with cvc5 as a third reference.

This note asks a narrow question: which ideas can still support a defensible
novelty claim after excluding established algorithms, published combinations,
and mechanisms visible in current public solver sources?

The search covered primary papers, artifacts, official solver repositories,
official release notes, and solver documentation available through
2026-07-11. It did not cover patents systematically, non-English literature
systematically, proprietary solver internals, unpublished industrial work, or
every branch and historical commit of every public solver. Consequently, "not
located" below means exactly that. It does not mean "does not exist."

## Classification Discipline

Every mechanism is assigned one of three labels.

- **ALREADY KNOWN**: a primary paper or public implementation establishes the
  central mechanism. A new implementation, faster implementation, Rust port,
  or modern benchmark result may still be valuable, but the algorithmic idea
  cannot be claimed as new.
- **KNOWN; DEPLOYMENT NOT LOCATED**: the algorithm is published, but this audit
  did not locate evidence that Z3 4.16.0, cvc5 1.3.3, or the audited Yices2
  source snapshot deploys it in the production `QF_UF` path. This is an
  implementation opportunity, not an algorithmic novelty claim.
- **PLAUSIBLY NOVEL COMBINATION**: all or most ingredients are known, but this
  bounded audit found no primary source implementing or evaluating the exact
  composition for `QF_UF`. The label is provisional and must be withdrawn if a
  matching paper, artifact, patent, or solver implementation is found.

No entry in this note is labelled "completely novel." Primary-source absence
cannot justify that wording.

## Audited Public Implementation Boundary

The following public snapshots anchor statements about current deployment.

| Solver | Audited public evidence | Relevant mechanisms visible in the evidence |
| --- | --- | --- |
| Z3 | [4.16.0 release](https://github.com/Z3Prover/z3/releases/tag/z3-4.16.0), [EUF solver source](https://github.com/Z3Prover/z3/blob/z3-4.16.0/src/sat/smt/euf_solver.cpp), [dynamic Ackermann source](https://github.com/Z3Prover/z3/blob/z3-4.16.0/src/sat/smt/euf_ackerman.cpp) | CDCL(T)-style EUF, e-graph reasoning, theory propagation/explanations, dynamic Ackermann lemmas |
| Yices2 | [Yices 2.2 architecture paper](https://yices.csl.sri.com/papers/cav2014.pdf), [public source snapshot](https://github.com/SRI-CSL/yices2/tree/b11db7c43ef72f9bd77d66a9c588d3eae80eaf93), [parameters](https://yices.csl.sri.com/doc/parameters.html), [QF_UF symmetry source](https://github.com/SRI-CSL/yices2/blob/b11db7c43ef72f9bd77d66a9c588d3eae80eaf93/src/context/symmetry_breaking.c) | dedicated e-graph, dynamic non-Boolean and Boolean Ackermann lemmas, equality learning, range/value symmetry, theory-clause caching |
| cvc5 | [1.3.3 release](https://github.com/cvc5/cvc5/releases/tag/cvc5-1.3.3), [UF options](https://cvc5.github.io/docs/latest/options.html), [cardinality extension](https://github.com/cvc5/cvc5/blob/cvc5-1.3.3/src/theory/uf/cardinality_extension.cpp), [1.1 release notes](https://github.com/cvc5/cvc5/releases/tag/cvc5-1.1.0) | equality engine, UF symmetry breaking, finite-cardinality reasoning, proof production, optional CaDiCaL through IPASIR-UP |
| CaDiCaL / Kissat | [CaDiCaL 2.0](https://doi.org/10.1007/978-3-031-65627-9_7), [Clausal Congruence Closure](https://doi.org/10.4230/LIPIcs.SAT.2024.6), [CCC artifact](https://doi.org/10.5281/zenodo.11652423) | external propagation, modern inprocessing and proof support, gate extraction, clausal structural hashing and congruence closure |

The source audit is evidence of presence. A text search that fails to find a
mechanism is not evidence of absence, so all negative deployment statements
remain explicitly bounded.

## Executive Exclusion Matrix

| Mechanism | Primary precedent | Current public implementation evidence | Classification | Novelty consequence |
| --- | --- | --- | --- | --- |
| Eager EUF-to-propositional reduction | [Bryant, German, and Velev](https://arxiv.org/abs/cs/9910014) | The method is the historical baseline for modern eager experiments | **ALREADY KNOWN** | "Eager EUF with a modern SAT solver" is not itself novel |
| Positive equality / maximally diverse interpretations | [Bryant, German, and Velev](https://arxiv.org/abs/cs/9910014) | Yices performs top-level equality learning; exact equivalence to the historical restricted method is not asserted here | **ALREADY KNOWN** | Positive-use specialization cannot be claimed as new |
| Full Ackermann expansion | [Bryant, German, and Velev](https://arxiv.org/abs/cs/9910014) and [Bruttomesso et al.](https://disi.unitn.it/rseba/papers/lpar06_ack.pdf) | Z3 and Yices contain dynamic variants | **ALREADY KNOWN** | Flattening applications and adding pairwise functional consistency is excluded |
| Partial/per-function Ackermannization | [Bruttomesso et al.](https://doi.org/10.1007/11916277_38) | [Z3 dynamic Ackermann](https://github.com/Z3Prover/z3/blob/z3-4.16.0/src/sat/smt/euf_ackerman.cpp), [Yices parameters](https://yices.csl.sri.com/doc/parameters.html) | **ALREADY KNOWN** | Static or activity-limited per-symbol selection is not a novelty claim |
| Reduced functional-consistency pairs | [Pnueli and Strichman](https://doi.org/10.1016/j.entcs.2005.12.006) | No claim is made that its exact signatures are deployed by current solvers | **ALREADY KNOWN** | Structural ordering or filtering of Ackermann pairs has prior art |
| Sparse transitivity constraints | [Bryant and Velev](https://arxiv.org/abs/cs/0008001) | Eager solvers can and do use sparse equality graphs | **ALREADY KNOWN** | Cycle-basis or sparse transitivity alone is excluded |
| Congruence closure for conjunctive EUF | [Nelson and Oppen](https://doi.org/10.1145/322186.322198), [Downey, Sethi, and Tarjan](https://doi.org/10.1145/322217.322228) | Core mechanism in Z3, Yices2, and cvc5 | **ALREADY KNOWN** | Union-find plus signature hashing is foundational, not novel |
| Incremental/backtrackable DPLL(T) EUF | [Ganzinger et al.](https://www.cs.upc.edu/~oliveras/dpllt.pdf), [Nieuwenhuis, Oliveras, and Tinelli](https://doi.org/10.1145/1217856.1217859) | Z3, Yices2, and cvc5 use integrated theory reasoning | **ALREADY KNOWN** | A rollback e-graph attached to CDCL is not by itself new |
| Model-constructing SMT | [de Moura and Jovanovic](https://doi.org/10.1007/978-3-642-35873-9_1), [Jovanovic, Barrett, and de Moura](https://theory.stanford.edu/~barrett/pubs/JBdM13.pdf), [modern Yices2-based account](https://arxiv.org/abs/2607.03777) | Yices2 implements MCSat; the 2026 account explicitly instantiates it for UF | **ALREADY KNOWN** | Maintaining a partial theory model during search is excluded |
| Proof-producing congruence closure | [Nieuwenhuis and Oliveras](https://www.cs.upc.edu/~oliveras/rta05.pdf) | Theory explanations are standard in SMT implementations | **ALREADY KNOWN** | Explanation forests and replayable congruence reasons are excluded |
| Small congruence explanations | [Flatt et al.](https://arxiv.org/abs/2209.03398) | No assertion is made that current solvers use this exact greedy objective | **ALREADY KNOWN** | Minimizing explanation trees is known; a new SAT-aware objective may remain open |
| Conditional/colored e-graphs | [Singher and Itzhaky](https://arxiv.org/abs/2305.19203) | No production `QF_UF` deployment was located in the audited solver snapshots | **KNOWN; DEPLOYMENT NOT LOCATED** | Sharing closure state across assumptions is published, but may be exploitable here |
| User-propagator bridge to CDCL | [IPASIR-UP](https://kfazekas.github.io/papers/FazekasNiemetzPreinerKirchwegerSzeiderBiere-JAIR24.pdf) | cvc5 has integrated CaDiCaL through IPASIR-UP | **ALREADY KNOWN** | External conflicts, propagation, reasons, decisions, and model checks are excluded as interface novelty |
| SMT constant/range symmetry breaking | [Deharbe et al.](https://members.loria.fr/PFontaine/Deharbe6b.pdf) | [Yices implementation](https://github.com/SRI-CSL/yices2/blob/b11db7c43ef72f9bd77d66a9c588d3eae80eaf93/src/context/symmetry_breaking.c), [cvc5 option](https://cvc5.github.io/docs/latest/options.html) | **ALREADY KNOWN** | Ordinary value precedence and range symmetry are excluded |
| MACE-style finite-domain SAT model finding | [Claessen and Sorensson](https://fitelson.org/paradox.pdf) | Paradox and later finite-model finders implement it | **ALREADY KNOWN** | Function tables, one-hot values, incremental domain size, and static symmetry are excluded |
| Finite-model finding integrated with SMT | [Reynolds et al.](https://cvc4.cs.stanford.edu/papers/CAV-2013/fmf_smt_reynolds_cav2013.pdf), [Reynolds, Tinelli, and Barrett](https://arxiv.org/abs/1706.00096) | [cvc5 cardinality extension](https://github.com/cvc5/cvc5/blob/cvc5-1.3.3/src/theory/uf/cardinality_extension.cpp) | **ALREADY KNOWN** | Cardinality-aware equality reasoning and clique detection are excluded |
| Matching-based `AllDifferent` | [Regin](https://cdn.aaai.org/AAAI/1994/AAAI94-055.pdf) | No Regin-style engine over automatically inferred `QF_UF` finite domains was located in the audited paths | **KNOWN; DEPLOYMENT NOT LOCATED** | Native Hall reasoning is an implementation opportunity, not an algorithmic novelty |
| Non-uniform adequate ranges | [Pnueli, Rodeh, and Strichman](https://doi.org/10.1007/3-540-45294-X_27), [Rodeh and Strichman](https://www.cs.bgu.ac.il/~mcodish/jsatornot/IC05.pdf) | No deployment evidence was located in the audited general-purpose `QF_UF` paths | **KNOWN; DEPLOYMENT NOT LOCATED** | Per-term finite ranges and graph-based range allocation are excluded as standalone ideas |
| Complete finite-model symmetry for one table | [Danco et al.](https://arxiv.org/abs/2502.10155) | No use as a production QF_UF preprocessing route was located | **KNOWN; DEPLOYMENT NOT LOCATED** | Complete canonization for a single magma is already published |
| SAT/SMT portfolio selection | [SATzilla](https://doi.org/10.1613/jair.2490), [SMT-RAT](https://doi.org/10.1007/978-3-319-24318-4_26), [MachSMT](https://cs.stanford.edu/~niemetz/publications/2021/ScottNiemetzPreinerNejatiGanesh-TACAS21.pdf) | Portfolios are standard and public | **ALREADY KNOWN** | Choosing a solver from syntactic features is excluded |
| Online per-instance strategy probing | [Wilson et al.](https://doi.org/10.34727/2025/isbn.978-3-85448-084-6_15), [Wu, Barrett, and Narodytska](https://doi.org/10.1609/aaai.v40i17.38451) | Published in 2025 and 2026 | **ALREADY KNOWN** | Micro-solving subproblems to select a strategy is excluded |
| SAT certificates | [DRAT](https://arxiv.org/abs/1610.06229), [native LRAT in CaDiCaL](https://doi.org/10.4230/LIPIcs.SAT.2023.21) | Modern SAT backends emit checkable proofs | **ALREADY KNOWN** | Adding DRAT/LRAT output is quality engineering, not solver-algorithm novelty |
| Modular SMT proof production | [Barbosa et al.](https://theory.stanford.edu/~barrett/pubs/BRK%2B22-abstract.html), [Alethe](https://arxiv.org/abs/2107.02354), [Carcara](https://doi.org/10.1007/978-3-031-30823-9_19) | cvc5 has broad proof support; veriT/cvc5 feed external proof ecosystems | **ALREADY KNOWN** | Composing Boolean and EUF proofs is established at the architecture level |
| Pseudo-Boolean proof logging | [Koops et al.](https://doi.org/10.4230/LIPIcs.CP.2025.21), [VeriPB](https://veripb.org/), [PBLean](https://arxiv.org/abs/2602.08692) | Practical and formally checked toolchains now exist | **ALREADY KNOWN** | Certifying Hall/cardinality reasoning through PB proofs is enabled, not conceptually new |

## 1. Classic Eager Reductions

### Established core

Bryant, German, and Velev reduce ground EUF to a propositional problem by
abstracting equality atoms and enforcing function consistency. Their work also
exploits positive equality and maximally diverse interpretations. Bryant and
Velev then study the transitivity bottleneck directly and construct smaller
constraint sets from sparse equality graphs.

Primary sources:

- [Processor Verification Using Efficient Reductions of the Logic of
  Uninterpreted Functions to Propositional Logic](https://arxiv.org/abs/cs/9910014)
- [Boolean Satisfiability with Transitivity Constraints](https://arxiv.org/abs/cs/0008001)
- [Building Small Equality Graphs for Deciding Equality Logic with
  Uninterpreted Functions](https://www.cs.bgu.ac.il/~mcodish/jsatornot/IC05.pdf)

These papers exclude novelty claims for:

- flattening ground UF applications to fresh symbols;
- pairwise functional-consistency implications;
- positive-equality specialization;
- sparse rather than complete transitivity constraints;
- finite value ranges justified by an equality graph;
- using SAT, BDDs, or another propositional engine after reduction.

### Known eager/lazy hybrids

Bruttomesso et al. show that neither complete Ackermannization nor theory
integration dominates universally and select function symbols for expansion.
Pnueli and Strichman use structural signatures to reduce functional-consistency
pairs and retain refinement when necessary.

Primary sources:

- [To Ackermann-ize or Not to Ackermann-ize?](https://disi.unitn.it/rseba/papers/lpar06_ack.pdf)
- [Reduced Functional Consistency of Uninterpreted
  Functions](https://doi.org/10.1016/j.entcs.2005.12.006)

Therefore, per-function eager/lazy selection, model-directed completion, and
structurally prioritized Ackermann pairs are **ALREADY KNOWN** at the mechanism
level. A new cost signal or a proof-preserving online migration protocol could
still be a new combination.

### Proof-complexity boundary

The eager route has a theoretical ceiling, not merely an implementation
problem. Robere, Kolokolova, and Ganesh compare lazy SMT proof systems with eager
reductions and establish lower-bound consequences for reductions from EUF to
SAT under the Exponential Time Hypothesis. Classical pigeonhole formulas also
have exponential resolution lower bounds.

Primary sources:

- [The Proof Complexity of SMT
  Solvers](https://doi.org/10.1007/978-3-319-96142-2_18)
- [Resolution Proofs of Generalized Pigeonhole
  Principles](https://doi.org/10.1016/0304-3975%2888%2990072-2)

This does not imply that eager solving cannot win on most practical instances.
It does imply that low-level SAT optimization alone cannot remove every hard
tail. A credible best-overall design needs either a stronger proof system or a
route that avoids presenting cardinality-shaped tails as plain resolution.

## 2. DPLL(T), MCSat, and Congruence Closure

### Established lazy architecture

Incremental, backtrackable congruence closure inside SAT search was already a
defining DPLL(T) example. The mature architecture includes theory conflicts,
theory propagation, learned theory lemmas, non-chronological backtracking, and
on-demand introduction of literals.

Primary sources:

- [DPLL(T): Fast Decision Procedures](https://www.cs.upc.edu/~oliveras/dpllt.pdf)
- [Solving SAT and SAT Modulo Theories](https://doi.org/10.1145/1217856.1217859)
- [Splitting on Demand in SAT Modulo
  Theories](https://www.cs.upc.edu/~oliveras/lpar06.pdf)

Consequently, the following are **ALREADY KNOWN**:

- complete-model theory checking followed by a blocking lemma;
- partial-trail theory conflicts;
- partial-trail theory propagation;
- delayed explanations supplied to conflict analysis;
- a rollback e-graph synchronized with SAT decisions;
- dynamic theory atoms and clauses.

IPASIR-UP makes these capabilities available through a generic modern SAT
interface and evaluates CaDiCaL as a CDCL(T) engine for cvc5. Recreating that
bridge is useful engineering but not novelty.

### MCSat is a separate exclusion

MCSat maintains a combined partial model and generalizes conflict-driven search
beyond a Boolean abstraction. The July 2026 formalization follows Yices2's
current implementation choices and includes an instantiation for uninterpreted
functions.

Primary sources:

- [A Model-Constructing Satisfiability
  Calculus](https://doi.org/10.1007/978-3-642-35873-9_1)
- [The Design and Implementation of the Model Constructing Satisfiability
  Calculus](https://theory.stanford.edu/~barrett/pubs/JBdM13.pdf)
- [A Modern View on MCSat](https://arxiv.org/abs/2607.03777)

Thus "build the model while solving" or "let theory values become decisions"
cannot support a novelty claim without a materially different mechanism.

### Congruence closure and explanations

The algorithmic line runs from the classic closure algorithms to incremental
proof-producing closure and recent proof-size optimization.

Primary sources:

- [Fast Decision Procedures Based on Congruence
  Closure](https://doi.org/10.1145/322186.322198)
- [Variations on the Common Subexpression
  Problem](https://doi.org/10.1145/322217.322228)
- [Proof-Producing Congruence Closure](https://www.cs.upc.edu/~oliveras/rta05.pdf)
- [Small Proofs from Congruence Closure](https://arxiv.org/abs/2209.03398)
- [Simplified and Verified: A Second Look at a Proof-Producing Union-Find
  Algorithm](https://arxiv.org/abs/2504.10246)

Proof forests, causal merge reasons, cached explanations, and greedy proof
minimization are known. A potentially open point is a joint objective that
chooses an explanation by predicted SAT impact, certificate cost, and future
reuse rather than proof size alone. This audit did not find such a deployed
`QF_UF` objective, but it also did not establish its absence.

### Conditional equality state

Colored e-graphs share a base e-graph across many assumption-specific
congruence relations and report large memory savings.

Primary source:

- [Colored E-Graph: Equality Reasoning with
  Conditions](https://arxiv.org/abs/2305.19203)

The data structure is **ALREADY KNOWN**. Using it as the theory core of a
production QF_UF solver is **KNOWN; DEPLOYMENT NOT LOCATED** in this audit.
Simply renaming colors as SAT branches would not be novel. A cross-layer
compiler that uses verified conditional congruences to share both EUF and
Boolean encodings is a narrower possible combination.

## 3. Ackermannization and Sparse Transitivity

The following novelty claims are excluded directly:

| Proposed claim | Exclusion evidence | Verdict |
| --- | --- | --- |
| Generate all congruence implications before SAT | Classic eager reduction | **ALREADY KNOWN** |
| Generate them only for selected functions | Partial Ackermannization | **ALREADY KNOWN** |
| Generate them after observing violated models | Lazy SMT and reduced functional consistency | **ALREADY KNOWN** |
| Limit generation using activity/conflict counters | Public Z3 and Yices dynamic Ackermann implementations | **ALREADY KNOWN** |
| Add only transitivity constraints induced by sparse graph structure | Bryant and Velev | **ALREADY KNOWN** |
| Order candidate pairs by a structural signature | Reduced functional consistency | **ALREADY KNOWN** |
| Switch the entire instance between eager and lazy modes | Partial Ackermannization plus solver portfolios | **ALREADY KNOWN** |

The less explored axis is not whether to Ackermannize, but whether a single
instance can use several proof systems concurrently at component granularity
and migrate a component without discarding reusable clauses or certificate
provenance. That exact composition was not located in this audit.

## 4. Symmetry Breaking

### SMT symmetry is established

Deharbe et al. formalize constant-permutation invariance and add symmetry
breaking predicates. Yices2 publicly implements QF_UF symmetry detection and
range/value constraints. cvc5 exposes the same paper's symmetry breaker as a
UF option.

Primary and implementation sources:

- [Exploiting Symmetry in SMT
  Problems](https://members.loria.fr/PFontaine/Deharbe6b.pdf)
- [Yices2 symmetry source](https://github.com/SRI-CSL/yices2/blob/b11db7c43ef72f9bd77d66a9c588d3eae80eaf93/src/context/symmetry_breaking.c)
- [cvc5 UF options](https://cvc5.github.io/docs/latest/options.html)

Value precedence, range constraints, transposition/cycle invariance checks,
and static lex-leader clauses are **ALREADY KNOWN**.

### Finite-model canonization is advancing rapidly

Danco et al. compute compact complete symmetry breaks for finite structures
with one binary operation. Akgun et al. trade completeness for smaller and
faster representation-specific symmetry constraints over abstract structures.

Recent primary sources:

- [Complete Symmetry Breaking for Finite
  Models](https://arxiv.org/abs/2502.10155)
- [Faster Symmetry Breaking Constraints for Abstract
  Structures](https://arxiv.org/abs/2511.11029)

Therefore:

- complete canonization of one finite operation table is **ALREADY KNOWN**;
- incomplete, representation-aware delayed symmetry application is
  **ALREADY KNOWN**;
- applying either method unchanged to QF_UF is an implementation transfer, not
  a new algorithm;
- a verified, compact, complete canonizer spanning multiple UF tables,
  predicates, sorts, distinguished constants, and partial SAT assignments was
  not located in this audit. This is a **PLAUSIBLY NOVEL COMBINATION**, not a
  confirmed novelty claim.

The proof obligation matters. An automorphism checker proves that a
permutation preserves the formula; it does not by itself prove that a chosen
set of symmetry constraints leaves at least one member of every orbit.

## 5. Finite Models, Cardinality, and Global Constraints

### Published finite-model machinery

MACE-style solvers flatten first-order formulas over a chosen finite domain,
encode function tables propositionally, reuse SAT state between domain sizes,
infer sorts, and add symmetry constraints. Modern SMT finite-model finding adds
cardinality constraints, clique discovery, and on-demand instantiation.

Primary sources:

- [New Techniques that Improve MACE-style Finite Model
  Finding](https://fitelson.org/paradox.pdf)
- [Finite Model Finding in
  SMT](https://cvc4.cs.stanford.edu/papers/CAV-2013/fmf_smt_reynolds_cav2013.pdf)
- [Constraint Solving for Finite Model Finding in SMT
  Solvers](https://arxiv.org/abs/1706.00096)
- [cvc5 cardinality extension](https://github.com/cvc5/cvc5/blob/cvc5-1.3.3/src/theory/uf/cardinality_extension.cpp)

One-hot table cells, binary table cells, domain constants, iterative domain
growth, clique conflicts, and finite-sort symmetry are all excluded as novelty
claims.

### Known but not located in production QF_UF paths

Three older or cross-domain techniques remain implementation opportunities.

1. **Non-uniform adequate ranges.** Pnueli, Rodeh, and Strichman assign
   different sufficient ranges to different equality-graph vertices. This is
   **KNOWN; DEPLOYMENT NOT LOCATED** in the audited current QF_UF paths.
2. **Matching-based `AllDifferent`.** Regin's matching algorithm enforces a
   strong consistency property and produces Hall-set consequences. The method
   is **ALREADY KNOWN**, while deployment over automatically proved QF_UF
   finite domains was not located.
3. **Modern compact cardinality encodings.** Krapivin, Przybocki, and
   Subercaseaux give new near-optimal encodings and grid compression in 2026.
   The encodings are **ALREADY KNOWN**; adoption in current QF_UF finite routes
   was not located.

Primary sources:

- [Range Allocation for Equivalence
  Logic](https://doi.org/10.1007/3-540-45294-X_27)
- [Filtering Algorithm for Constraints of Difference in
  CSPs](https://cdn.aaai.org/AAAI/1994/AAAI94-055.pdf)
- [Near-Optimal Encodings of Cardinality
  Constraints](https://arxiv.org/abs/2603.28954)

The 2025 EUF-plus-cardinality complexity note is a warning against assuming
that tiny domains make the combined problem easy: function symbols preserve
NP-hardness even at domain cardinality two.

- [A Few Exercises on the Complexity of Congruence Closure with Cardinality
  Constraints](https://ceur-ws.org/Vol-4008/SMT_paper24.pdf)

A new contribution must therefore be an empirically effective composition,
not a claim that finite QF_UF has become structurally trivial.

## 6. SAT and SMT Portfolios

### Offline and feature-based selection

SATzilla selects a solver per instance from empirical hardness models. SMT-RAT
provides configurable and parallel SMT strategies. MachSMT learns rankings of
SMT solvers from syntactic features.

Primary sources:

- [SATzilla](https://doi.org/10.1613/jair.2490)
- [SMT-RAT](https://doi.org/10.1007/978-3-319-24318-4_26)
- [MachSMT](https://cs.stanford.edu/~niemetz/publications/2021/ScottNiemetzPreinerNejatiGanesh-TACAS21.pdf)

A decision tree over counts such as terms, applications, equalities, lets, and
finite signatures is **ALREADY KNOWN** as a class of method. Novelty would need
to lie in the solver mechanisms selected or in a new online information source,
not in the existence of a structural router.

### Parallel partitioning and online tuning

OpenSMT2 implements portfolio and safe-partitioning modes. Wilson et al. study
distributed SMT partitioning, including QF_UF. Later work generates bounded
subproblems from one instance and uses their behavior to select a strategy.
Cubing for Tuning performs online tuning solely from the current instance.

Primary sources:

- [OpenSMT2 for Multi-Core and Cloud
  Computing](https://verify.inf.usi.ch/sites/default/files/main_submitted_SAT2016.pdf)
- [Partitioning Strategies for Distributed SMT
  Solving](https://arxiv.org/abs/2306.05854)
- [Per-Instance Subproblem Generation for Strategy Selection in
  SMT](https://doi.org/10.34727/2025/isbn.978-3-85448-084-6_15)
- [Cubing for Tuning](https://doi.org/10.1609/aaai.v40i17.38451)

The following are excluded as novelty claims:

- run Z3, Yices2, cvc5, and a specialized solver in parallel;
- train a static per-instance selector;
- probe generated subproblems and select a configuration online;
- cube a hard formula and distribute the cubes;
- use a portfolio to hide an eager solver's hard tail.

A portfolio can still be the best product design. It is not, by itself, the
substantially different solver algorithm sought here.

## 7. Proof Certificates

### Boolean proof layer

DRAT was designed to express modern SAT transformations. LRAT makes checking
more direct, and CaDiCaL can generate LRAT natively for its implemented
procedures.

Primary sources:

- [The DRAT Format and DRAT-trim Checker](https://arxiv.org/abs/1610.06229)
- [Faster LRAT Checking Than Solving with
  CaDiCaL](https://doi.org/10.4230/LIPIcs.SAT.2023.21)

### SMT and EUF proof layer

Proof-producing congruence closure records explanations for derived
equalities. cvc5's architecture builds proofs modularly and lazily. Alethe and
Carcara provide an external SMT proof interchange/checking path.

Primary sources:

- [Proof-Producing Congruence Closure](https://www.cs.upc.edu/~oliveras/rta05.pdf)
- [Flexible Proof Production in an Industrial-Strength SMT
  Solver](https://theory.stanford.edu/~barrett/pubs/BRK%2B22-abstract.html)
- [Alethe](https://arxiv.org/abs/2107.02354)
- [Carcara](https://doi.org/10.1007/978-3-031-30823-9_19)

### Cardinality and symmetry proof layer

Pseudo-Boolean proof logging now covers production-strength optimization and
constraint reasoning with a formally verified checking path. PBLean imports
the kernel rules into Lean.

Primary sources:

- [Practically Feasible Proof Logging for Pseudo-Boolean
  Optimization](https://doi.org/10.4230/LIPIcs.CP.2025.21)
- [VeriPB](https://veripb.org/)
- [PBLean](https://arxiv.org/abs/2602.08692)

Accordingly, "SAT proof plus EUF explanations" is **ALREADY KNOWN** as a
composition pattern. A project can contribute a smaller trusted checker, a
complete proof-producing implementation of new transformations, lower proof
overhead, or a useful proof interchange. It should not claim that certifying
SMT itself is new.

## 8. 2023-2026 Frontier and Its Exclusions

| Year | Primary result | What it establishes | Classification for this campaign |
| --- | --- | --- | --- |
| 2023 | [Colored E-Graphs](https://arxiv.org/abs/2305.19203) | Shared equality state across many conditions | **KNOWN; DEPLOYMENT NOT LOCATED** for production QF_UF |
| 2023 | [Partitioning Strategies for Distributed SMT](https://arxiv.org/abs/2306.05854) | SMT cubing and hybrid portfolios, including QF_UF evaluation | **ALREADY KNOWN** |
| 2023 | [Faster LRAT Checking](https://doi.org/10.4230/LIPIcs.SAT.2023.21) | Native LRAT generation in CaDiCaL | **ALREADY KNOWN** |
| 2023/2024 | [IPASIR-UP](https://kfazekas.github.io/papers/FazekasNiemetzPreinerKirchwegerSzeiderBiere-JAIR24.pdf) | Generic trail callbacks, external propagation/conflicts, delayed reasons, model checks | **ALREADY KNOWN** |
| 2024 | [Clausal Congruence Closure](https://doi.org/10.4230/LIPIcs.SAT.2024.6) | Gate extraction and congruence hashing during SAT pre/inprocessing | **ALREADY KNOWN** |
| 2024/2025 | [Input Normalization for SMT Stability](https://doi.org/10.34727/2025/isbn.978-3-85448-084-6_14) | Approximate semantic-preserving normalization reduces runtime instability | **ALREADY KNOWN** |
| 2025 | [Complete Symmetry Breaking for Finite Models](https://arxiv.org/abs/2502.10155) | Compact complete canonizing constraints for one binary operation | **KNOWN; DEPLOYMENT NOT LOCATED** in QF_UF |
| 2025 | [Verified Proof-Producing Union-Find](https://arxiv.org/abs/2504.10246) | Isabelle verification and imperative refinement of union-find with explain | **ALREADY KNOWN** |
| 2025 | [Per-Instance SMT Strategy Selection](https://doi.org/10.34727/2025/isbn.978-3-85448-084-6_15) | Online strategy evidence from bounded subproblems | **ALREADY KNOWN** |
| 2025 | [Practical PB Proof Logging](https://doi.org/10.4230/LIPIcs.CP.2025.21) | Practical, formally checked PB proof pipeline | **ALREADY KNOWN** |
| 2025 | [EUF plus Cardinality Complexity](https://ceur-ws.org/Vol-4008/SMT_paper24.pdf) | Hardness persists for very small finite domains with functions | Boundary result, not a solver mechanism |
| 2026 | [A Modern View on MCSat](https://arxiv.org/abs/2607.03777) | Current Yices2-inspired MCSat calculus, including UF | **ALREADY KNOWN** |
| 2026 | [Cubing for Tuning](https://doi.org/10.1609/aaai.v40i17.38451) | Online configuration tuning from the current instance | **ALREADY KNOWN** |
| 2026 | [Faster Symmetry Breaking for Abstract Structures](https://arxiv.org/abs/2511.11029) | Representation-specific delayed symmetry application | **ALREADY KNOWN** outside QF_UF; transfer opportunity |
| 2026 | [Near-Optimal Cardinality Encodings](https://arxiv.org/abs/2603.28954) | Smaller AMO and general cardinality encodings | **ALREADY KNOWN**; adoption opportunity |
| 2026 | [Compiler Optimization-Based SMT Simplifications](https://doi.org/10.1145/3795879) | Iterative and learned compiler-pass configurations improve SMT preprocessing | **ALREADY KNOWN** as preprocessing/selection strategy |
| 2026 | [PBLean](https://arxiv.org/abs/2602.08692) | VeriPB kernel checking reflected into Lean | **ALREADY KNOWN** proof route |

## 9. Claims Explicitly Excluded

The campaign must not describe any of the following as algorithmically novel.

1. Eager EUF reduction, even when paired with Kissat or CaDiCaL.
2. Full, partial, dynamic, or model-directed Ackermannization.
3. Sparse transitivity constraints or equality-graph completion.
4. Incremental, rollback, proof-producing congruence closure.
5. Complete-model refinement or partial-trail DPLL(T) propagation.
6. MCSat-style joint model construction.
7. Static value/range symmetry, lex leaders, or finite table symmetry.
8. One-hot, binary, or mixed finite-domain encodings.
9. Native Hall/`AllDifferent` propagation considered in isolation.
10. Boolean DAG hash-consing considered in isolation.
11. Gate extraction and clausal congruence closure considered in isolation.
12. Static feature routing, learned solver selection, online probing, cubing,
    or parallel portfolios considered in isolation.
13. DRAT, LRAT, Alethe, congruence explanations, or PB proof logging.
14. "Trust UNSAT, validate SAT, otherwise escalate" as a standalone novelty
    claim. Validation and proof-producing solver composition are established.
15. Low-level implementation choices such as Rust, arenas, bitsets, SIMD,
    cache-aware layouts, PGO, LTO, or custom allocators. These may produce an
    important performance result but not algorithmic novelty.

A defensible paper may still claim a new empirical result, a new combination,
a new cost model, a new proof-preserving integration, or a first implementation
in a precisely delimited scope. The claim must name that scope.

## 10. Novelty Claim Protocol

Before promoting any idea from "plausible combination" to a paper claim:

1. State the exact mechanism in pseudocode, including its proof obligation and
   fallback behavior.
2. Search by mechanism, not project terminology. Include SAT, SMT, theorem
   proving, finite model finding, CSP, CP, PB, e-graphs, and database
   congruence terminology.
3. Audit current Z3, Yices2, cvc5, veriT, OpenSMT, Vampire/Paradox, Kissat,
   CaDiCaL, and relevant PB/CP source paths at pinned revisions.
4. Search patents and dissertations before using "first" or "novel."
5. Cite the closest method and state the delta in one falsifiable sentence.
6. Run an ablation where every known ingredient is individually enabled. A
   combination claim fails if one known ingredient explains the full gain.
7. Use held-out families and CPU classes. A result discovered and evaluated on
   one benchmark family is a family specialization, not a general QF_UF result.
8. Require independent SAT-model validation and replayable UNSAT evidence.
   Performance cannot compensate for one wrong answer.

## 11. Five Precise Gaps Worth Experiments

These are the five highest-value gaps left by this bounded audit. Each is a
**PLAUSIBLY NOVEL COMBINATION**, not a confirmed novelty claim.

### Gap 1: Proof-carrying multi-table orbit quotienting

**Closest known work.** SMT range/value symmetry is established by Deharbe et
al. and deployed by Yices2/cvc5. Paradox uses static finite-model symmetry.
Danco et al. compute complete canonizing constraints for a single binary
operation. VeriPB can certify sophisticated combinatorial reasoning.

**Combination not located.** An automatic QF_UF route that:

1. proves a finite closed substructure from the input;
2. verifies the full formula automorphism group independently;
3. maintains a stabilizer chain spanning multiple function and predicate
   tables, multiple sorts, and distinguished constants;
4. rejects non-canonical partial tables during SAT search; and
5. emits a replayable orbit/canonicality witness for every pruning lemma.

**Hypothesis.** This removes the value-renaming search responsible for the
closed-table tail without imposing a generic one-hot pigeonhole proof on the
SAT backend.

**Falsifiable gate.** First restrict to exact one-table finite instances.

- Exhaustively enumerate all structures through domain size 5 and require
  exactly one surviving representative per isomorphism class.
- Check every accepted automorphism with an independent formula evaluator.
- On the frozen one-table target population, run three alternating 60-second
  repeats on both WMI CPU classes. Require zero wrong answers, zero new errors,
  zero baseline-only solves, at least one timeout conversion, and ratios above
  `1.05` for timeout-charged total, common-solve total, and geometric mean.
- Replay every symmetry lemma independently. Any unreplayable lemma rejects
  the mechanism regardless of speed.
- Only after that gate may the implementation broaden to several tables and
  sorts, followed by a 2x2 ablation against existing finite support clauses.

**Novelty falsifier.** A paper, patent, or public solver implementing complete
multi-table QF_UF canonicality with partial-search pruning and checkable orbit
witnesses removes the combination claim.

### Gap 2: Theory-conditioned quotient compilation of the Boolean DAG

**Closest known work.** Ordinary hash-consing is standard. Clausal congruence
closure recovers and merges equivalent gates from CNF. Colored e-graphs share
conditional equality relations. SMT input normalization canonicalizes many
semantics-preserving input variants.

**Combination not located.** A QF_UF compiler that preserves the source
Boolean DAG and shares a Tseitin literal not only for syntactically identical
nodes, but for nodes whose UF arguments are equal under a verified base or
conditional congruence. Conditional shares retain their assumptions and can be
invalidated or refined without rebuilding unrelated CNF. Every shared node
keeps source and proof provenance.

**Hypothesis.** Large generated table formulas contain enormous repeated
Boolean syntax over a small equality graph. Cross-layer quotienting can remove
that redundancy before SAT instead of asking the SAT backend to rediscover it.

**Falsifiable gate.** Begin in telemetry mode on the frozen large-DAG target.

- Record syntax occurrences, unique syntactic nodes, unique
  theory-conditioned nodes, projected CNF variables, and clauses.
- Require at least a 25% projected CNF reduction on at least 8 of the 10 hard
  closed-table timeout formulas before enabling solving behavior.
- Exhaustively compare original and quotient DAGs for all generated formulas
  up to six theory atoms and fuzz at least one million typed formulas,
  including Boolean-valued UF arguments.
- Reconstruct and check the original CNF semantics from provenance.
- Run three alternating 60-second repeats on the frozen large-DAG population.
  Require no loss, at least one timeout conversion, and all three timing ratios
  above `1.05`.
- Test alone, then in a 2x2 experiment with Gap 1. Reject the combination if
  orbit quotienting alone accounts for the gain.

**Novelty falsifier.** A prior QF_UF implementation that merges Boolean DAG
nodes modulo branch-conditional theory congruence, with proof-preserving
Tseitin reuse, removes the combination claim. Plain hash-consing, e-graphs, or
clausal congruence closure alone do not match it.

### Gap 3: Proof-complexity-triggered per-component representation migration

**Closest known work.** Partial Ackermannization chooses functions in advance.
DPLL(T), MCSat, and IPASIR-UP provide online theory interaction. Portfolios
switch whole configurations. PB and native cardinality solvers provide proof
systems stronger than plain resolution on pigeonhole-like constraints.

**Combination not located.** One SAT search in which each UF interference
component starts in the cheapest representation and can migrate independently:

- sparse eager transitivity/Ackermann clauses for low-fill components;
- rollback congruence propagation for equality-graph components;
- native Hall/PB reasoning for proved finite components.

Migration is triggered by online proof-complexity proxies such as conflict
rate, LBD/width growth, invalid-model recurrence, and useful-theory-cut yield.
Atoms have stable semantic identities, and learned information crosses a
migration only through checked bridge lemmas.

**Hypothesis.** The solver keeps eager fast-head performance while escaping a
resolution wall before spending the entire timeout in the wrong proof system.

**Falsifiable gate.** Implement in three milestones.

- `M0`: telemetry only. Replay existing runs and show that the predeclared
  trigger separates known eager wins from known proof-complexity tails on a
  held-out set. Reject if balanced accuracy is below 0.80 or trigger overhead
  exceeds 1%.
- `M1`: one-way eager-to-rollback migration with no theory propagation. If no
  migration occurs, SAT calls, clauses, models, and results must be byte-for-
  byte identical to baseline.
- `M2`: add finite Hall/PB migration only after `M1` passes.
- On the frozen large equality-graph target, require fewer complete invalid
  models on every multi-round case, at least `1.10x` target speedup, at least
  one timeout conversion, no baseline-only solve, and all aggregate ratios
  above one.
- Every bridge lemma must replay in an independent checker. Then require
  sample-40, hot-400, hard-tail, and full-corpus gates with nondecreasing
  coverage and zero wrong answers.

**Novelty falsifier.** A prior solver that migrates individual EUF components
between eager, rollback-closure, and PB/cardinality representations during one
search while preserving learned clauses and proof provenance removes the
combination claim.

### Gap 4: Adequate-range Hall reasoning with an end-to-end checked bridge

**Closest known work.** Non-uniform adequate ranges, Regin's matching
propagator, SMT finite-cardinality reasoning, and PB proof logging are all
published separately.

**Combination not located.** Compute a proved adequate value range for each
term or equality component, expose the resulting non-uniform bipartite domains
to a native incremental matching engine, derive Hall conflicts/propagations,
and translate every result into a checked PB proof plus EUF bridge premises.
Nested function applications are admitted only when their range proof is
reconstructable.

**Hypothesis.** This avoids both uniform-domain blowup and exponentially weak
plain-resolution proofs while preserving a small trusted base.

**Falsifiable gate.** Start with one-sort, function-free equality graphs.

- Exhaustively compare satisfiability and all propagated value removals for
  graphs through eight vertices against brute-force partitions.
- Require the adequate-range encoder to reduce allocated value cells by at
  least 30% on the selected sparse finite slice; otherwise reject before a
  solver campaign.
- Check every Hall reason in VeriPB/CakePB or an equivalently trusted checker.
  Proof generation plus checking must add no more than 25% to candidate solve
  time on solved target cases.
- On the frozen finite hard tail, require at least one timeout conversion, no
  loss, and all three timing ratios above `1.05` over three alternating
  60-second repeats.
- Add unary functions, then higher arities, only after separate exhaustive
  range-adequacy proofs and differential tests pass.

**Novelty falsifier.** Prior work combining per-term adequate ranges, native
incremental matching, and end-to-end checked EUF/PB explanations in a QF_UF
solver removes the combination claim. Any one ingredient alone does not.

### Gap 5: Pre-CNF EUF-consistent model scouts

**Closest known work.** Bryant et al. use maximally diverse interpretations for
positive equality. [Kissat tries cheap lucky
assignments](https://github.com/arminbiere/kissat/blob/rel-4.0.4/src/lucky.c#L307-L390),
and [Yices exposes model implicant operations](https://yices.csl.sri.com/release-notes.html).
This audit did not locate a production QF_UF path that tries a fixed suite of
complete EUF interpretations before allocating the general CNF.

**Combination not located.** A bit-parallel source-DAG evaluator tries a small,
fixed, deterministic suite of complete typed interpretations:

- the one-class quotient where allowed by explicit disequalities;
- a maximally diverse/free-term quotient;
- a greedy disequality-coloring quotient;
- collapsed and diverse interpretations crossed with false/true choices for
  unconstrained Boolean-valued functions.

A hit returns an explicit total SMT model. A miss discards all scout state and
enters the normal solver. The scouts never return UNSAT.

**Hypothesis.** A large fraction of satisfiable QF_UF instances have a simple
extreme quotient. Proving that by direct evaluation can beat all CDCL(T) and
eager-CNF startup costs on the fast head.

**Falsifiable gate.** Begin as a shadow evaluator over the full corpus.

- Independently validate every hit with a separate model checker and
  differential tests against Z3 and cvc5. Include generated many-sorted,
  Boolean-as-data, zero-arity, and nested-UF cases.
- Reject if unique correct hits cover less than 5% of satisfiable instances or
  if miss overhead exceeds 2% of baseline median time.
- For promotion, require at least `1.20x` speedup on hits, at least `1.05x`
  full-corpus median improvement, unchanged coverage, and timeout-charged,
  common-total, and geometric ratios all above one over two full paired runs.
- Fix the scout order before the held-out run. Per-instance online tuning of
  scout order is already covered by strategy-selection literature and cannot
  be folded into this novelty claim.

**Novelty falsifier.** A prior QF_UF solver or paper using a fixed pre-CNF suite
of complete EUF quotient interpretations with explicit model validation
removes the combination claim. SAT lucky assignments or ordinary post-search
model construction alone do not match the proposed scope.
