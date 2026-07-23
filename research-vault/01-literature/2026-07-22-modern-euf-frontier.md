# Modern EUF Frontier: Source Audit and Preregistered Tests

Date: 2026-07-22

Status: bounded primary-source and official-source audit. This note supports
experiment selection; it does **not** establish a first-in-history novelty
claim.

Tags: `QF_UF`, `EUF`, `Kissat`, `Yices2`, `congruence-closure`,
`finite-domain`, `symmetry`, `proof-logging`, `preregistration`

## Scope and claim discipline

This audit covers peer-reviewed or author-hosted primary papers and official
solver repositories/releases located by 2026-07-22. It is not an exhaustive
patent, dissertation, private-code, or unpublished-work search. Absence from
this audit means only **not located in this bounded search**.

The labels used below are deliberately strict:

- **Known prior art**: the mechanism is described in a primary publication.
- **Deployed control**: the mechanism is visible in a pinned official solver
  source or release.
- **Plausible combination**: all or most ingredients are known, but the exact
  composition was not located in this audit. This is a testable research
  hypothesis, not a novelty claim.
- **Locally rejected**: this repository tested a precise route and its
  preregistered gate failed. It does not mean the research community abandoned
  the mechanism.

Two terminology traps matter throughout:

1. Kissat's **clausal congruence closure** finds congruent Boolean gates
   extracted from CNF. It is not the ground-EUF congruence closure that reasons
   about source terms and uninterpreted functions.
2. A SAT proof checks the emitted propositional problem. It does not by itself
   justify EUF lemmas, finite-domain restrictions, symmetry restrictions, or
   the SMT-to-CNF translation.

## Reproducible current solver pins

"Modern solver" must mean a frozen release, options, compiler, and binary.
The latest official releases observed on 2026-07-22 were:

| Solver | Audited release and source pin | QF_UF relevance |
| --- | --- | --- |
| Yices2 | [2.7.0](https://github.com/SRI-CSL/yices2/releases/tag/yices-2.7.0), `85cf17e44eac76b5d14b297c09fc9bfecf47ef65` | Dedicated egraph, theory propagation, dynamic Ackermann lemmas, theory-clause cache, equality learning, and range-based symmetry |
| Kissat | [4.0.4](https://github.com/arminbiere/kissat/releases/tag/rel-4.0.4), `8af8e56f174b778aef3aa45af9f739b2a5f492c2` | High-performance non-incremental SAT control with modern preprocessing, inprocessing, and search |
| CaDiCaL | [3.0.1](https://github.com/arminbiere/cadical/releases/tag/rel-3.0.1), `c607304` | Incremental and proof-producing control carrying major Kissat techniques; 3.0.1 changed `factor` and light preprocessing defaults to off |
| Z3 | [4.16.0](https://github.com/Z3Prover/z3/releases/tag/z3-4.16.0), `ddb49568d3520e99799e364fb22f35fc67d887b1` | Current production EUF explanation and Ackermann control |
| cvc5 | [1.3.4](https://github.com/cvc5/cvc5/releases/tag/cvc5-1.3.4), `f3b21c4483d3b88dc63cb7cd3e5eb092eee5e341` | Current production equality-engine, proof, and UF-cardinality control |

The release pages are evidence only for these dated pins. A future campaign
must refresh the table and must not silently compare a new candidate against
these older binaries.

## Modern SAT and the Biere/Kissat control surface

### What is already occupied

Kissat 4.0.4 exposes, among other mechanisms, chronological backtracking;
focused/stable search; target phases, rephasing, restarts, and trail reuse;
probing; definition extraction with Kitten; bounded variable addition (`factor`);
lucky assignments before and after preprocessing; SAT sweeping; equivalent
literal substitution; transitive binary-clause reduction; and clause
vivification. Its congruence pass extracts AND, XOR, and ITE gates, and
`congruenceonce=0` permits more than an initial pass. These are explicit in the
pinned [Kissat options](https://github.com/arminbiere/kissat/blob/8af8e56f174b778aef3aa45af9f739b2a5f492c2/src/options.h#L21-L167).

The [4.0.4 release notes](https://github.com/arminbiere/kissat/blob/8af8e56f174b778aef3aa45af9f739b2a5f492c2/NEWS.md#L1-L51)
also matter experimentally: they report a fix for quadratic ITE extraction,
disable fast elimination by default, and delay BVA on larger formulas. Thus a
label such as "Kissat 4" is not a stable treatment unless the exact patch
release and options are frozen.

Biere, Fazekas, Fleury, and Froleyks' [Clausal Congruence Closure](https://doi.org/10.4230/LIPIcs.SAT.2024.6)
extracts gates from CNF, hashes structurally congruent gates, and runs in both
preprocessing and inprocessing. The paper also documents earlier unpublished
attempts. This occupies Boolean gate recovery and repeated Boolean congruence;
it does not occupy source-level EUF partition reasoning.

[CaDiCaL 3.0](https://doi.org/10.4230/LIPIcs.SAT.2026.40) ports clausal
congruence closure, clausal equivalence sweeping, and BVA from the
performance-oriented Kissat line into a full-featured incremental solver. It
also adds deterministic tick-based scheduling, direct consequences under
assumptions, and hinted linear proof production. The paper explicitly frames
Kissat's narrow interface as part of its performance tradeoff. A QF_UF
architecture needing incrementality, user propagation, or rich proofs should
therefore control against current CaDiCaL as well as Kissat.

[Factoring Learned Clauses](https://doi.org/10.4230/LIPIcs.SAT.2026.28)
revisits extended-resolution factoring of repeated learned-clause fragments
and adds global XOR/ITE factoring. Exact recurrence in learned clauses and
generic extension-variable factoring are therefore known SAT mechanisms.
Merely recognizing repeated explanation shapes is not a contribution.

[Simplify, Order, Break, Repeat (SORB)](https://doi.org/10.4230/LIPIcs.SAT.2026.4)
adds only unit and binary symmetry clauses, simplifies, and repeats because
new symmetries can emerge. Its reported CaDiCaL preprocessing improvements
make one-shot symmetry an inadequate modern control. SORB is still a CNF
symmetry control, not evidence that post-EUF semantic symmetries are already
handled.

[Dsat](https://doi.org/10.4230/LIPIcs.SAT.2026.31) implements CDCL directly
over fixed finite-domain variables rather than binarizing them. Native
set-valued literals, discrete propagation, reason construction, and clause
learning are consequently prior art. A changing domain of canonical EUF
classes would need a separate soundness argument; Dsat does not supply one.

[IPASIR-UP](https://doi.org/10.4230/LIPIcs.SAT.2023.8) and
[CaDiCaL 2.0](https://doi.org/10.1007/978-3-031-65627-9_7) already provide
user-propagator and external reasoning interfaces with trail, backtrack,
propagation, conflict, decision, and model interaction. Connecting an EUF
propagator to CDCL through such an interface is engineering prior art, not a
novel architecture by itself.

### Consequence for this repository

The current Linux control already vendors Kissat 4.0.4 at the exact pin above,
passes differential and certificate smoke tests, and has not yet begun its
frozen timing campaign: [[2026-07-13-modern-kissat-control]]. The same-binary
CaDiCaL clausal-congruence canary reduced conflicts and decisions on one target
but regressed the 20-pair ABBA median from 8.055 ms to 9.737 ms. This is direct
local evidence that lower SAT-internal counts are not promotion evidence.

**Known/deployed, not claimable:** a Kissat upgrade, clausal congruence,
sweeping, BVA, vivification, phase changes, restarts, trail reuse, a CaDiCaL
tail, or an IPASIR-UP attachment.

## Yices2 as the architectural control

The [Yices 2.2 architecture paper](https://yices.csl.sri.com/papers/cav2014.pdf)
describes hash-consed terms, simplification and internalization, a CDCL core,
theory solvers that can create literals and clauses during search, and a UF
solver based on an explanatory egraph with dynamic Ackermannization. This is
more than a SAT backend followed by model validation.

The current 2.7.0 source sharpens that control:

- The [egraph's dynamic Ackermann code](https://github.com/SRI-CSL/yices2/blob/85cf17e44eac76b5d14b297c09fc9bfecf47ef65/src/solvers/egraph/egraph.c#L3481-L3580)
  treats Boolean and non-Boolean applications separately, counts repeated hits
  on application pairs, obeys lemma caps, and stops when auxiliary-equality
  quotas are exhausted.
- The [context setup](https://github.com/SRI-CSL/yices2/blob/85cf17e44eac76b5d14b297c09fc9bfecf47ef65/src/context/context_solver.c#L480-L518)
  configures a bounded theory-clause cache and the Ackermann thresholds and
  quotas. The official [parameter documentation](https://yices.csl.sri.com/doc/parameters.html#generic-lemma-generation)
  documents `cache-tclauses`, `tclause-size`, `dyn-ack`, Boolean Ackermann
  variants, and auxiliary-equality limits.
- The [top-level equality learner](https://github.com/SRI-CSL/yices2/blob/85cf17e44eac76b5d14b297c09fc9bfecf47ef65/src/context/eq_learner.c#L149-L312)
  propagates equality information through Boolean equality, OR, and ITE
  structure before the main search.
- The [range recognizer and permutation check](https://github.com/SRI-CSL/yices2/blob/85cf17e44eac76b5d14b297c09fc9bfecf47ef65/src/context/symmetry_breaking.h#L39-L119)
  recognize finite range disjunctions and verify assertion invariance using
  generators of the constant-permutation group; the implementation then emits
  [symmetry clauses](https://github.com/SRI-CSL/yices2/blob/85cf17e44eac76b5d14b297c09fc9bfecf47ef65/src/context/symmetry_breaking.c#L1647-L1820).

Yices2 therefore occupies the combination of congruence closure,
explanations, selective theory-clause retention, dynamic Ackermann lemmas,
top-level equality discovery, and verified range symmetry. A candidate that
only adds one of these to a SAT encoding is a component ablation, not a new
solver architecture.

The [2.7.0 release notes](https://github.com/SRI-CSL/yices2/releases/tag/yices-2.7.0)
emphasize MCSat finite fields, caches, decisions, partial restarts, and a
portfolio script rather than claiming a new QF_UF algorithm. That observation
does not prove that an unadvertised or related mechanism is absent.

Local evidence remains bounded: the structural Yices portfolio has a
full-corpus hard-tail aggregate win but regresses geometric and median time and
depends on Yices for coverage, so it is not independent superiority:
[[2026-07-08-structural-yices-portfolio]].

## Congruence closure and explanations

### Established mechanisms

Classical congruence closure and DPLL(T) integration are foundational prior
art, beginning with the ground-equality procedures of
[Nelson and Oppen](https://doi.org/10.1145/322186.322198) and
[Downey, Sethi, and Tarjan](https://doi.org/10.1145/322217.322228). More
specifically, Nieuwenhuis and Oliveras'
[Proof-Producing Congruence Closure](https://www.cs.upc.edu/~oliveras/rta05.pdf)
maintains an incremental proof forest and recovers a `k`-step explanation in
time quasi-linear in `k` without increasing the overall `O(n log n)` closure
bound. Proof production and efficient `Explain` are not novel.

Producing the smallest useful explanation is a separate problem. Flatt et al.'s
[Small Proofs from Congruence Closure](https://arxiv.org/abs/2209.03398)
notes NP-completeness of minimum proof generation, gives an expensive optimal
algorithm for a relaxed tree-size metric, and gives a practical `O(n log n)`
greedy method. A solver should not promise minimum reasons.

Andreotti and Barbosa's
[Producing Shorter Congruence Closure Proofs in a State-of-the-Art SMT Solver](https://www.hanielbarbosa.com/papers/2026vmcai.pdf)
adapts greedy proof shortening to cvc5 while retaining redundant egraph edges.
Its aggregate result is a crucial negative control: Greedy reduced explanation
size by 7.91% and proof size by 3.33% but increased total runtime by 45.59%.
For the non-array/non-string group, which includes QF_UF, explanation size fell
21.27% while runtime rose 29.85%. At the same time, 5,347 of 162,228 instances
were at least twice as fast. Explanation quality is therefore a routing problem,
not an unconditional optimization.

Current production controls also expose rich explanation machinery:

- Z3 4.16.0 has source-level [EUF explanation collection](https://github.com/Z3Prover/z3/blob/ddb49568d3520e99799e364fb22f35fc67d887b1/src/sat/smt/euf_solver.cpp#L251-L417)
  and a separate [dynamic Ackermann component](https://github.com/Z3Prover/z3/blob/ddb49568d3520e99799e364fb22f35fc67d887b1/src/sat/smt/euf_ackerman.cpp#L23-L224).
- cvc5 1.3.4's [equality engine](https://github.com/cvc5/cvc5/blob/f3b21c4483d3b88dc63cb7cd3e5eb092eee5e341/src/theory/uf/equality_engine.h#L50-L236)
  is incremental, performs congruence closure, records reasons, and provides
  explanation operations; its [proof equality engine](https://github.com/cvc5/cvc5/blob/f3b21c4483d3b88dc63cb7cd3e5eb092eee5e341/src/theory/uf/proof_equality_engine.h#L90-L295)
  reconstructs proof-producing explanations.

**Known/deployed, not claimable:** proof forests, congruence explanations,
greedy shortening, retaining redundant edges to obtain alternative reasons,
fuel/budget limits, theory propagation, reason caching, and generic learned
clause factoring.

### Remaining plausible combination: exact EUF recurrence factoring

The bounded audit did not locate this exact composition:

1. preserve stable source-term and source-literal identities in every EUF
   explanation;
2. count exact recurring concrete antecedent sets, not alpha-isomorphic path
   shapes;
3. introduce a complete extension definition only when the exact formula
   recurs and generic CaDiCaL/Kissat factoring did not already recover it; and
4. expand or check the definition in the final proof.

This is candidate X1 in [[2026-07-22-viper-fabric-novelty-boundaries]]. It is
only a plausible unlocated combination. If the same savings appear under
generic learned-clause factoring, or if recurrence is only shape-level, the
EUF-specific hypothesis is falsified.

## Finite domains, all-different reasoning, and symmetry

### Established mechanisms

Ground EUF has finite models, but selecting a particular small domain for a
component still requires a sound source-level argument. Domain-size heuristics
or benchmark-family names are not such an argument.

Eager finite encodings are old and diverse:

- Bryant, German, and Velev's [positive-equality encoding](https://www.cs.cmu.edu/~bryant/pubdir/cav99a.pdf)
  uses maximally diverse interpretations and finite bit-vector encodings.
- Bryant and Velev's [sparse transitivity encoding](https://www.cs.cmu.edu/~bryant/pubdir/tocl-trans01.pdf)
  adds chordal fill and only the needed triangle constraints rather than a
  dense transitivity closure.
- Rodeh and Strichman's [Minimal-E](https://www.cs.bgu.ac.il/~mcodish/jsatornot/IC05.pdf)
  constructs smaller adequate equality graphs and range allocations.
- Bruttomesso et al.'s [To Ackermann-ize or Not to Ackermann-ize?](https://es-static.fbk.eu/people/griggio/papers/lpar06_ack.pdf)
  observes dramatic performance gaps in both directions and selects all or
  part of the function symbols by an offline cost estimate.

Finite-domain propagation and symmetry are equally occupied:

- Regin's [AllDifferent](https://cdn.aaai.org/AAAI/1994/AAAI94-055.pdf)
  gives matching-based generalized arc consistency. Hall-set propagation is
  not new, and [Justifying All Differences Using Pseudo-Boolean Reasoning](https://doi.org/10.1609/aaai.v34i02.5507)
  supplies a proof-oriented control.
- [Exploiting Symmetry in SMT Problems](https://members.loria.fr/SMerz/papers/cade2011symmetry.html)
  detects syntactic invariance under constant permutations and implements it
  in veriT for QF_UF. Yices2 deploys a related range-based pass as shown above.
- [SAT Modulo Symmetries](https://doi.org/10.4230/LIPIcs.CP.2021.34)
  integrates a partial-canonicality propagator into CDCL rather than emitting
  only a static break.
- [Symmetries for Cube-and-Conquer in Finite Model Finding](https://doi.org/10.4230/LIPIcs.CP.2023.8)
  discards isomorphic cubes while respecting the least-number heuristic.
- [Complete Symmetry Breaking for Finite Models](https://doi.org/10.1609/aaai.v39i11.33217)
  computes compact complete breaks for the studied one-binary-operation
  structures. Its scope does not establish a complete general multi-sort,
  multi-function QF_UF break.
- [Faster Symmetry Breaking Constraints for Abstract Structures](https://doi.org/10.1609/aaai.v40i17.38425)
  is a current 2026 control for incomplete symmetry breaking over abstract
  structures.
- Dsat occupies native CDCL over fixed finite-domain variables, while SORB
  occupies repeated generic CNF symmetry after simplification.
- cvc5's official [UF cardinality extension](https://github.com/cvc5/cvc5/blob/f3b21c4483d3b88dc63cb7cd3e5eb092eee5e341/src/theory/uf/cardinality_extension.cpp#L280-L494)
  builds clique and split lemmas for explicit UF cardinality reasoning. This is
  not the same as automatically recovering a small domain from ordinary QF_UF,
  but it is a necessary control for any cardinality claim.

### Local evidence and precise rejected routes

The repository has already shown that changing the representation without
matching the actual proof structure is insufficient:

- Raising the one-hot finite-domain cap from 8 to 11 left all four targets as
  timeouts: [[2026-07-08-finite-domain-cap-rejected]].
- Replacing pairwise at-most-one constraints with a sequential encoding left
  all four targets as timeouts: [[2026-07-08-finite-sequential-amo-rejected]].
- Routing the same finite clauses to CaDiCaL instead of Kissat left all four
  targets as timeouts: [[2026-07-08-finite-cadical-tail-rejected]].
- A root pigeonhole detector had zero mechanism incidence on four eligible
  profiles and measurable preprocessing cost:
  [[2026-07-08-finite-pigeonhole-detector-rejected]].
- Sound injection-to-permutation support produced strong targeted gains and a
  five-solve full-corpus coverage gain, but missed the full geometric gate; a
  narrower successor then lost hot-set coverage:
  [[2026-07-10-finite-permutation-support]].

These results reject those exact policies, not one-hot encodings, support
clauses, Hall reasoning, or finite-domain solving in general.

### Remaining plausible combinations

**F1: source-certified Hall/PB recovery.** Recognize a finite domain only from
checked range/exhaustiveness evidence, maintain a native matching/Hall
propagator over application-result domains, emit source-replayable reasons, and
log the cardinality reasoning in a PB-capable proof. Every ingredient is known;
the exact guarded QF_UF composition was not located here.

**F2: post-quotient repeated semantic symmetry.** Recompute typed source-level
automorphisms after congruence rewriting or finite-domain propagation exposes
new equivalences, then emit only cuts with an orbit or
substitution-redundancy witness. The controls are Yices/veriT one-shot range
symmetry, SORB on the emitted CNF, and dynamic SAT Modulo Symmetries. This is X2
in [[2026-07-22-viper-fabric-novelty-boundaries]], not a novelty claim.

**F3: dynamic quotient-domain CDCL.** Adapt Dsat-style set-valued literals and
first-UIP learning to a domain whose values are canonical EUF classes that
merge and roll back. Learned objects may mention only stable source terms or
checked relabel-invariant partition predicates. This is E2 in
[[2026-07-22-viper-fabric-novelty-boundaries]]. Dsat's fixed domains, ordinary
DPLL(T), and abstract CDCL remain the closest controls.

## Proof logging is part of the algorithm

SAT certification has a mature ladder:

- DRAT is easy for solvers to emit, while LRAT supplies explicit hints for
  efficient checking. [Faster LRAT Checking Than Solving with CaDiCaL](https://doi.org/10.4230/LIPIcs.SAT.2023.21)
  implements native LRAT across CaDiCaL procedures.
- [FRAT](https://doi.org/10.46298/lmcs-18(2:3)2022) separates convenient solver
  output from elaborated checking hints.
- [CaDiCaL 3.0](https://doi.org/10.4230/LIPIcs.SAT.2026.40) extends the current
  control to hinted linear proofs for its imported Kissat-style passes.
- [Certifying Incremental SAT Solving](https://doi.org/10.29007/PDCC) covers
  assumptions, incremental calls, and user-propagator interactions through
  LIDRUP/IDRUP-style records.

SMT and stronger reasoning need more than a SAT trace:

- [Flexible Proof Production in cvc5](https://doi.org/10.1007/978-3-031-10769-6_3)
  and [Alethe](https://doi.org/10.4204/EPTCS.336.6) are controls for modular SMT
  proof reconstruction and exchange.
- [Certified Symmetry and Dominance Breaking](https://doi.org/10.1613/JAIR.1.14296)
  demonstrates checkable without-loss-of-generality reasoning using stronger
  redundancy arguments.
- [Practically Feasible Proof Logging for Pseudo-Boolean Optimization](https://doi.org/10.4230/LIPIcs.CP.2025.21)
  provides a current VeriPB/CakePB control if Hall or cardinality reasoning is
  expressed natively rather than expanded into CNF.

A QF_UF certificate pipeline must account for five boundaries separately:

1. source parsing, typing, rewriting, and flattening;
2. every EUF propagation/conflict or Ackermann lemma;
3. every finite-domain or symmetry restriction, including its
   equisatisfiability witness when it is not a logical consequence;
4. the SAT/PB derivation over the final emitted constraints; and
5. SAT model decoding followed by complete source-level EUF validation.

A DRAT/LRAT proof for layer 4 cannot be cited as a proof of layers 1-3. A
symmetry cut in particular may preserve satisfiability without being entailed,
so an ordinary EUF implication check is insufficient.

## Eager encodings: prior art versus abandoned experiments

Full Ackermannization, per-function partial Ackermannization, positive
equality, range allocation, sparse transitivity, chordal completion, and eager
finite-domain encodings are all prior art. They should not be described as
abandoned by the field.

The repository's evidence is narrower:

- Dynamic Ackermannization plus bounded chordal completion passed one exact
  full-corpus gate and remains an active local mechanism:
  [[2026-07-09-dynamic-ackermann-chordal]].
- Automatic quotient activation later failed its broad default gate, and a
  budgeted full-Ackermann leaf route lost coverage despite large
  common-solved gains: [[2026-07-12-flat-clause-and-budgeted-ackermann-gates]].
- Full completion generated more than ten million Ackermann clauses and more
  than three hundred thousand fill edges on one recorded profile before
  termination. Allocation-independent preflight caps are therefore mandatory.

Kissat's own history also cautions against loose "abandoned technique"
language: some passes were removed or disabled in competition variants and
later reintroduced or retuned. Only a release-specific option ablation is
defensible.

The correct conclusion is: **eager encodings remain a selective portfolio
arm, while the tested unconditional or weakly guarded policies are rejected.**

## Occupied-territory matrix

| Mechanism | Status | Required control before any contribution claim |
| --- | --- | --- |
| Incremental/rollback congruence closure with explanations | Known and deployed | Yices2, Z3, cvc5; proof-producing CC |
| Dynamic, full, or per-symbol partial Ackermannization | Known and deployed | Yices2/Z3 dynamic modes; literature cost selector; current local dynamic route |
| Boolean gate congruence and repeated inprocessing | Known and deployed | Kissat 4.0.4 and CaDiCaL 3.0.1 |
| Sweeping, BVA/factoring, probing, vivification, phase/restart tuning | Known and deployed | One-at-a-time Kissat/CaDiCaL option ablations |
| Short/greedy congruence explanations | Known; experimental production evaluation exists | Vanilla and cvc5-style Greedy, including total cost |
| Exact learned-clause factoring/extended resolution | Known | Generic CaDiCaL factoring/FX control |
| Native fixed finite-domain CDCL | Known | Dsat and Boolean binarization controls |
| AllDifferent/Hall propagation | Known | Regin-style matching and PB-justified all-different |
| QF_UF constant/range symmetry | Known and deployed | veriT/Yices one-shot symmetry |
| Repeated generic CNF symmetry | Known | SORB on exactly the emitted CNF |
| Dynamic partial-canonicality propagation | Known in other finite structures | SAT Modulo Symmetries |
| SAT, incremental SAT, SMT, PB, and symmetry proof logging | Known families | LRAT/FRAT/LIDRUP, Alethe/cvc5, VeriPB/CakePB, SR-style witness |
| SAT backend replacement or structural portfolio | Engineering control | Frozen modern Kissat and current Yices/Z3/cvc5 comparisons |

## Candidate combinations that survive this bounded audit

None of the following is asserted novel.

| ID | Plausible exact combination not located here | Cheapest decisive falsifier |
| --- | --- | --- |
| C1 / E2 | Relabel-invariant CDCL over a changing quotient domain, with stable source-term reasons | Exhaust all typed states through four terms and every class relabeling; one unstable reason kills it |
| C2 / X1 | Exact concrete EUF explanation recurrence factored into checked extension definitions only when generic factoring misses | Observation-only recurrence trace; reject shape-only recurrence or savings reproduced by generic FX |
| C3 / X2 | Repeated typed semantic symmetry after EUF rewriting, with orbit/SR witnesses | Produce a verified second-round cut absent from one-shot typed symmetry and SORB |
| C4 / F1 | Source-certified finite-table recovery plus native Hall propagation and PB-checkable reasons | Census certified finite components and Hall events; reject if mechanism incidence is negligible or reasons do not replay |

The orthogonal E3 source-complete quotient-frontier cache remains documented in
[[2026-07-22-viper-fabric-novelty-boundaries]]. It should not be mixed into the
first behavioral experiments above.

## Preregistered census protocol

The numeric thresholds below are proposed decision rules, not reported
results. Freeze this section, source commits, and manifests before collecting
behavioral timings.

### P0: common freeze and evidence rules

1. Hash the exact source, compiler, dependencies, solver binaries, benchmark
   bytes, expected statuses, environment, and command lines.
2. Treat the already repeatedly measured 7,503-instance SMT-LIB 2025 QF_UF
   corpus as development evidence, not a fresh held-out set. Confirmation of a
   general claim needs a previously unmeasured release or a generator and seed
   committed before candidate results are viewed.
3. Run paired arms on the same node. Use randomized ABBA order, three repeats
   for broad screening, and 31 repeats for any timeout or millisecond boundary
   used in a decision.
4. Charge timeouts in all-instance totals. Report coverage, common-correct
   total, geometric ratio, median, paired wins, peak RSS, and 95% paired
   bootstrap intervals. Common-solved speed alone cannot promote a route.
5. Require zero wrong answers, crashes, malformed results, proof failures, and
   model-validation failures. Any candidate-only answer must be independently
   checked.
6. A behavioral arm advances only with no coverage loss, a lower 95% bound
   above parity for its preregistered target metric, and no anti-target p95
   slowdown above 1%. These are project gates, not literature claims.

### P1: modern SAT attribution census

Run identical SMT parsing, CNF, finite axioms, EUF clauses, fallback, and model
validation with these arms:

| Arm | Treatment |
| --- | --- |
| `S0` | Frozen Kissat SC2021 control |
| `S1` | Kissat 4.0.4 defaults |
| `S2` | `S1` without clausal congruence |
| `S3` | `S1` without sweeping |
| `S4` | `S1` without `factor`/BVA |
| `S5` | `S1` without vivification |
| `S6` | `S1` without probing/definitions |
| `S7` | `S1` without lucky phases and trail reuse |
| `S8` | CaDiCaL 3.0.1 with explicit `factor=0` |
| `S9` | CaDiCaL 3.0.1 with explicit `factor=1` and declared extension variables |

Record conflicts, decisions, propagations, ticks, learned/deleted clauses,
peak memory, proof bytes, proof-generation time, proof-check time, and complete
end-to-end time. A pass is considered explanatory only if its on/off effect is
reproduced on at least 20 eligible instances representing at least 5% of
timeout-charged corpus time. This census can attribute an engineering gain; it
cannot support a novelty claim.

### P2: explanation and exact-recurrence census

Run the current solver without changing any decisions. For every theory
propagation and conflict, log:

- stable source literal IDs and source term IDs;
- Vanilla explanation length, decision-level count, projected LBD, and
  backjump level;
- a hash of the exact concrete antecedent set and a separate hash of the typed
  alpha-shape;
- recurrence count, clause lifetime, and conflict weight;
- projected literals and clauses for a complete extension definition;
- whether generic CaDiCaL learned-clause factoring finds the same definition;
- estimated greedy-search work and proof-expansion work.

Advance X1 to a shadow implementation only if exact concrete recurrence covers
at least 25% of target conflict weight, the complete definitions project at
least 20% net literal reduction, and at least half of that projected saving is
absent from the generic factoring control. Shape recurrence alone is a no-go.

If the census passes, use a factorial ablation:

| Arm | Explanation policy | Factoring policy |
| --- | --- | --- |
| `E0` | Vanilla | Off |
| `E1` | Greedy always | Off |
| `E2` | Fuel-bounded structural router | Off |
| `E3` | Vanilla | Generic SAT factoring |
| `E4` | Vanilla | Exact concrete EUF recurrence only |
| `E5` | Fuel-bounded router | Generic plus exact EUF recurrence |

Reject unconditional Greedy unless it beats Vanilla end to end; shorter
reasons are a secondary metric. Reject any extension whose definition cannot
be expanded and checked without cycles.

### P3: certified finite-structure and Hall census

Before adding a propagator, scan every input and emit a machine-readable record
for each sort/component containing:

- the exact source clauses proving range exhaustiveness and distinct domain
  constants;
- term and application counts, sort, function arity, and observed table-row
  coverage;
- disequality graph degree/core/clique data;
- current one-hot variables, clauses, literal slots, and projected pairwise,
  sequential, and order encodings;
- maximum matching size after each root propagation round;
- every Hall set found, values removed, conflict depth, and a replayable source
  reason;
- injection-to-permutation opportunities and current support-clause coverage;
- typed value and table automorphism generators, orbit sizes, and witness cost;
- projected PB proof size and checking cost.

Advance native Hall propagation only if at least 20 independently certified
components, accounting for at least 5% of timeout-charged corpus time, exhibit
either a Hall conflict or at least 10% domain-value pruning beyond ordinary
unit propagation. Family names and expected finite sizes are forbidden as
eligibility features.

The first behavioral ablation is:

| Arm | Added mechanism |
| --- | --- |
| `F0` | Current finite encoding only |
| `F1` | Source-certified Hall propagation |
| `F2` | Existing full-injection support clauses |
| `F3` | One-shot verified range/value symmetry |
| `F4` | Repeated post-propagation semantic symmetry |
| `F5` | Hall plus one-shot symmetry |
| `F6` | Hall plus repeated semantic symmetry |

Each Hall event must replay from source facts and each non-entailed symmetry
cut needs a WLOG witness. Compare CNF-expanded Hall reasoning with a native PB
trace; do not assume the native form is faster.

### P4: dynamic quotient-domain census and bounded oracle

No performance implementation is permitted before an exhaustive reference
oracle enumerates:

1. every typed ground formula in the bounded generator;
2. every partition state through four source terms;
3. every legal class merge, rollback, and relabeling;
4. every watched set-valued literal, propagation reason, conflict, learned
   object, and first-UIP step; and
5. replay before and after backjump under every class relabeling.

One unstable reason or learned object rejects the representation. If sound,
the observation census records quotient size/churn, equality atoms avoided,
watch moves, source-normalization cost, learned-object size, and explored
states versus ordinary DPLL(T) and fixed-domain Dsat-style search.

Advance only if the learned language does not collapse to ordinary pair-equality
clauses and the bounded oracle shows at least 10% fewer explored states on at
least 25% of eligible generated formulas. Those thresholds authorize a larger
prototype, not a novelty statement.

### P5: repeated semantic-symmetry census

At every root-level simplification fixpoint, compute but do not apply:

- one-shot typed source symmetries;
- SORB symmetries on exactly the emitted CNF; and
- typed semantic automorphisms after current EUF rewriting.

Canonicalize every mapped cut back to stable source IDs. Record discovery and
verification time, rounds, orbit sizes, unit/binary cuts, cuts already produced
by controls, and orbit/SR witness size.

Advance X2 only if at least 20 instances and 5% of target timeout-charged time
contain a verified second-round semantic cut absent from both one-shot typed
symmetry and SORB. Identical mapped cuts falsify the distinct-mechanism claim
even if timings differ. Assignment-dependent symmetries must be guarded.

The behavioral arms are `one-shot`, `SORB`, `semantic-once`,
`semantic-repeat`, and `SORB+semantic-repeat`; all use the same SAT backend and
proof policy.

### P6: eager-encoding opportunity census

For each function symbol and connected component, log:

- application count and argument/result sorts;
- all candidate application pairs and projected Ackermann clauses/literal
  slots;
- required new equality atoms and Yices-style pair hit counts;
- chordal fill edges, triangles, and peak temporary allocation;
- invalid-model frequency before each completion round;
- observed work avoided after each generated lemma; and
- exact preflight rejection reason.

Replay four fixed policies offline: lazy DPLL(T), Yices-style thresholded
dynamic Ackermannization, per-symbol partial Ackermannization, and full
completion under allocation-independent caps. The behavioral ablation may
start only after the census freezes the selector. It must include the accepted
local dynamic route and the rejected leaf-budget route as controls.

Mandatory preflight caps cover base terms, variables, clauses, literal slots,
applications, arity, argument slots, pair examinations, projected Ackermann
literals, chordal fill, and the selected SAT backend. A common-solved speedup
with one lost instance is a rejection.

### P7: certificate census and mutant gate

For every arm above, record proof bytes and generation/checking time by layer.
Before timing promotion, require mutants that independently corrupt:

- one parser/flattening map;
- one EUF antecedent and one congruence edge;
- one Ackermann application pair;
- one finite-domain exhaustiveness fact;
- one Hall reason;
- one symmetry witness;
- one SAT/PB proof step; and
- one decoded SAT model value.

Each mutant must be rejected by the intended checker, not merely by a later
solver disagreement. A checked theory-empty contradiction is terminal without
a fictitious SAT proof; a SAT answer remains provisional until source-level
model validation passes.

## Decision order

1. Finish P1 to determine how much of the current gap is simply the SAT
   control surface.
2. Run P2, P3, P5, and P6 as observation-only censuses in parallel; they do
   not change solver behavior.
3. Implement only the cheapest candidate whose mechanism incidence passes its
   frozen threshold.
4. Run the component ablation before any combined arm.
5. Add proof generation and independent checking before broad timing.
6. Use the full reused corpus only as a regression gate; reserve a previously
   unmeasured corpus for confirmatory claims.

## Claim boundary

The literature and official sources support a demanding baseline: modern
QF_UF work must beat an explanatory egraph with selective lemmas and symmetry,
not merely an old SAT encoding; and it must control for current Kissat/CaDiCaL
preprocessing, inprocessing, search, and proof machinery.

The four surviving combinations are worth censusing because their exact
cross-layer forms were not located in this bounded audit. They remain
**hypotheses** until source-complete implementation searches, checked proofs,
component ablations, frozen current-solver comparisons, and fresh held-out
evidence all pass. No statement in this note supports "novel", "first", or
"better than Z3/Yices/cvc5" without those later gates.
