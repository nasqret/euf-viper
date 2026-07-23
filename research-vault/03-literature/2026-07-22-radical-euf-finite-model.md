# Radical EUF and finite-model tail research

**Date:** 2026-07-22

**Scope:** concrete, currently unimplemented optimization hypotheses for the qg7 and Goel tails
**Claim discipline:** this is a design and falsification memo, not a performance or superiority claim

## Executive decision

The two tails should not be forced through one optimization:

| Tail | Observed shape | Most defensible next experiment | Main reason |
|---|---|---|---|
| Goel | A large Boolean shell around comparatively sparse UF structure; the sole 1200 s tail inspected locally has 35,744 Boolean assertions, 8,682 terms, 138 applications, and 8,542 constants | Slice the externally observed theory boundary and defer explanation construction until CaDiCaL requests a reason | The current adapter observes every source atom and constructs reasons before the bridge requests them; whole-instance propagation helped targets but incurred unacceptable anti-target overhead |
| qg7 | Large finite binary-operation searches with strong permutation symmetry; a local probe found 5,040 complete forbidden tables in one simultaneous-conjugation orbit | First build a source-complete finite-table projection, then compare canonical augmentation, generic SAT symmetry controls, and an orbit-quotiented forbidden-table automaton | Existing finite-table, Hall, and orbit components are bounded and isolated; the current abstraction omits source obligations, so search improvements cannot yet establish source-level correctness |

Two exact compositions look potentially new enough to investigate, but **neither is established as novel**:

1. **Goel composition candidate:** lazy IPASIR-UP reason tokens combined with recurrence-triggered, proof-expandable auxiliary equality atoms.
2. **qg7 composition candidate:** a source-complete, proof-carrying finite-table propagator that combines canonical augmentation, incremental Hall witnesses, and an orbit-quotiented forbidden-table state.

Every constituent of both candidates has close prior art. The possible contribution is the exact composition, source contract, and certificate discipline. A broader literature and code search would be required before any novelty statement.

## Evidence boundary

The local evidence used to shape the experiments is deliberately narrower than a benchmark claim:

- The frozen 60 s deficit contains 22 instances: 12 qg7 UNSAT instances, 9 Goel instances of which 6 are SAT and 3 are UNSAT, and 1 PEQ UNSAT instance outside this note's scope.
- The inspected 1200 s Goel tail, `QF_UF/2018-Goel-hwbench/QF_UF_sokoban.2.prop1_ab_br_max.smt2` (SHA-256 `cfe0e5e611139004e7f8a06461c4cbf3066bb604786377db1a94d40e797f3112`), is Boolean-heavy and application-sparse. It has no top-level equality or disequality facts.
- Whole-instance rollback propagation improved target coverage from 15 to 23, but anti-target p95 overhead ranged from 11.17x to 32.75x against a 1.10 cap. This rejects unconditional routing, not external propagation itself.
- Full Ackermann-style completion produced one run with 10,136,258 Ackermann clauses and exhausted memory. A separate transitivity-heavy experiment added 1,517,715 clauses. These reject unbounded completion.
- The closed-atom Ackermann probe saw 3,686 candidate clauses over 138 applications but emitted zero closed clauses because the required result-equality atoms did not exist. This is evidence for a bounded latent-atom experiment, not for eager atom completion.
- A prior shortest/SAT-impact reason experiment did not encounter enough alternative-reason opportunities and its local pass timed out. Generic explanation minimization should therefore begin with an opportunity census.
- Removing the 5,040 direct qg7 forbidden roots reduced encoding work but did not prove or solve the target set. Orbit compression by itself is insufficient.
- The current RTXC qg7 abstraction omits source obligations, including right-translation order, diagonal, fixed-point, absorption, involution, implication, and Skolem constraints. It cannot serve as a source-complete decision procedure.
- No current qg7 target has a locally proved finite range under the generic finite-range route. The finite carrier must be derived from source semantics or the specialized path must abstain.
- The representative qg7 source is `QF_UF/QG-classification/qg7/iso_icl_nogen001.smt2`, 6,013,419 bytes, UNSAT, SHA-256 `6e9ea0786a672c467f853bf8964283bbdc53c2b51c41e0b0e6fc1fbd8ba34be0`.

These observations come from the frozen local campaign artifacts and implementation, while the external links below are primary papers or official project sources.

### Local implementation map

| Local hook | Current boundary | Experiment it enables |
|---|---|---|
| [`src/fabric/cadical_up.rs`](../../src/fabric/cadical_up.rs) | Default-isolated CaDiCaL/IPASIR-UP adapter; observes all source atoms, uses rollback congruence, and builds propagation reasons eagerly | G1 observation slicing and deferred reasons; G2 activation policy; G3 bounded latent equalities; G5 decision callback |
| [`vendor/rustsat-cadical-up/src/external_propagator.rs`](../../vendor/rustsat-cadical-up/src/external_propagator.rs) | Rust user-propagator bridge stores a complete reason before CaDiCaL consumes it | G1 stable reason-token protocol and rollback invalidation |
| [`src/fabric/finite_hall.rs`](../../src/fabric/finite_hall.rs) | Bounded rollback domains and checked Hall witnesses, not source-integrated | Q1 incremental matching/Hall ablation |
| [`src/fabric/latin_exact_cover.rs`](../../src/fabric/latin_exact_cover.rs) | Bounded one-operation Latin-table search and certificates, not routed from Fabric | Q0 source-complete projection target and Q1 baseline |
| [`src/finite_table_source.rs`](../../src/finite_table_source.rs) | Test-only, fail-closed source evaluator | Q0 differential oracle |
| [`src/stabilizer_order.rs`](../../src/stabilizer_order.rs) and [`src/forbidden_orbit_probe.rs`](../../src/forbidden_orbit_probe.rs) | Bounded stabilizer/orbit machinery | Q2 canonical augmentation and checked orbit witnesses |
| [`src/forbidden_table_mdd.rs`](../../src/forbidden_table_mdd.rs) and [`src/forbidden_table_mvdd.rs`](../../src/forbidden_table_mvdd.rs) | Isolated forbidden-table decision-diagram components | Q3 quotient-automaton product |

These hooks are implementation opportunities, not evidence that the proposed integrations are correct or effective.

## Classification labels

| Label | Meaning |
|---|---|
| **K** | Known technique or directly documented deployment |
| **L** | Already proposed or partially implemented in this worktree, but not integrated for this tail |
| **U** | Exact composition not located in this bounded audit; a novelty candidate only |
| **R** | Rejected locally in a broader or less controlled form; only a materially bounded variant remains open |

`U` does not mean genuinely new. It means that the exact composition was not found in the sources checked here.

## 1. Modern EUF solving and explanations

### What is established

Modern ground EUF engines use congruence closure or explanatory e-graphs, maintain rollback-compatible equality state, and return antecedents for conflicts or theory propagations. The important optimization question is not merely whether explanations exist, but when they are built, how much of the equality graph they retain, and which explanation is selected.

- Nieuwenhuis and Oliveras, **“Proof-Producing Congruence Closure” (2005)**, gives proof-producing congruence closure with efficient explanation generation: [DOI](https://doi.org/10.1007/978-3-540-32033-3_33).
- Flatt, Coward, Willsey, Tatlock, and Panchekha, **“Small Proofs from Congruence Closure” (2022)**, proves that exact minimum explanations are NP-complete and develops polynomial-time `TreeOpt` and near-linear `Greedy` alternatives: [DOI](https://doi.org/10.34727/2022/isbn.978-3-85448-053-2_13), [arXiv](https://arxiv.org/abs/2209.03398).
- Andreotti and Barbosa, **“Producing Shorter Congruence Closure Proofs in a State-of-the-Art SMT Solver” (2026)**, adapts greedy proof reduction to cvc5 with rollback and implicit-dependency handling: [DOI](https://doi.org/10.1007/978-3-032-15700-3_1), [author PDF](https://www.hanielbarbosa.com/papers/2026vmcai.pdf). Its evaluation reports shorter explanations but aggregate runtime overhead, so shorter reasons cannot be assumed to reduce solve time.
- Dutertre, **“Yices 2.2” (2014)**, describes the explanatory e-graph and theory-clause interaction in Yices: [official PDF](https://yices.csl.sri.com/papers/cav2014.pdf). Yices exposes size-bounded theory-clause caching and dynamic Ackermann controls in its [official parameter reference](https://yices.csl.sri.com/doc/parameters.html#generic-lemma-generation).
- Z3's pinned official implementation provides concrete references for [EUF explanation construction](https://github.com/Z3Prover/z3/blob/ddb49568d3520e99799e364fb22f35fc67d887b1/src/sat/smt/euf_solver.cpp#L251-L417) and [dynamic Ackermann reduction](https://github.com/Z3Prover/z3/blob/ddb49568d3520e99799e364fb22f35fc67d887b1/src/sat/smt/euf_ackerman.cpp#L23-L224).

The implication for this worktree is conservative: explanation minimization, theory-clause caching, and dynamic Ackermannization are known ideas. A useful result would have to come from a tail-specific policy, an implementation improvement in the bridge, or a stronger source/proof contract.

### Goel candidate G1: observed-atom slicing plus truly lazy reasons

**Labels:** K for lazy explanations and external propagation; U for the exact bridge-and-slice composition.

**Current gap.** The local CaDiCaL adapter observes all source atoms. Native CNF auxiliaries remain hidden, which is already useful, but source atoms outside the active UF boundary still generate callback traffic. The adapter also constructs and stores a complete propagation reason before the CaDiCaL bridge asks for that reason. The vendored Rust bridge then replays the stored literals through the reason callback.

**Implementation hypothesis.** Introduce two independent changes so their effects are measurable:

1. Compute a conservative closure of theory-relevant source atoms. Seed it with equality atoms, Boolean-valued UF atoms, application-result atoms, and atoms reachable through explanation dependencies. Observe only this closure. Complete source-model validation remains mandatory outside the callback path.
2. Change the Rust bridge contract from `propagated literal + complete reason` to `propagated literal + stable reason token`. Materialize and replay the antecedents only if CaDiCaL requests the reason. Tokens must be invalidated or versioned on backtrack.

The closure must be fail-closed. If an unobserved assignment can become a theory antecedent, a theory conclusion, or alter a source-level model check, the slicer must include it or disable propagation for the component.

**Why it may fit Goel.** A sparse UF core inside a large Boolean shell creates a plausible callback-volume problem. Lazy construction can only help if CaDiCaL does not request most candidate reasons, so this is an empirical question.

**Falsification experiment.** Run a 2x2 factorial on the frozen Goel target and anti-target sets:

| Arm | Observation set | Reason construction |
|---|---|---|
| A | all source atoms | eager |
| B | sliced closure | eager |
| C | all source atoms | deferred |
| D | sliced closure | deferred |

Before timing, run a shadow mode that executes all four policies without changing the returned consequences. Require identical source-level results, complete model validation, and successful replay of every requested reason. Record assignments notified, components activated, propagation candidates, reasons requested, reasons materialized, reason literals, callback ticks, and rollback invalidations.

**Fast rejection conditions.** Reject or narrow the candidate if the slice is nearly the full source set, if most candidates immediately request reasons, if reason construction is a negligible fraction of callback work, if deferred tokens retain comparable memory, or if any model/reason differential appears.

**Novelty risk.** High. Gent, Miguel, and Moore's **“Lazy Explanations for Constraint Propagators” (2010)** explicitly argues for retrospective explanation construction: [DOI](https://doi.org/10.1007/978-3-642-11503-5_19). Flexible lazy proof construction is also established in cvc5. The potentially unlocated part is the exact source-atom slicing and token lifetime discipline in this IPASIR-UP/Rust bridge.

### Goel candidate G2: conflict-first adaptive theory activation

**Label:** K.

**Implementation hypothesis.** Start a component with source-model validation and theory conflicts only. Enable proactive theory propagation after a bounded signal such as repeated congruence-invalid candidate models, repeated equality-path reconstruction, or a rollback-adjusted closure-work threshold. Activation is component-local and monotone for the current solve.

**Falsification experiment.** Compare conflict-only, always-propagate, and adaptive policies with the same observations and explanation implementation. Log the exact activation cause, invalid-model count, propagations avoided, conflicts delayed, and CDCL decisions after activation.

**Fast rejection conditions.** Reject if SAT Goel cases repeatedly rediscover the same invalid models before activation, if the selected signal does not separate target from anti-target instances, or if activation merely shifts the existing overhead later in the run.

**Novelty risk.** Very high. Delayed theory combination, conflict-only checks, and adaptive propagator scheduling are established policy choices. This is routing work, not a novel algorithm. It must also respect the local prohibition on unvalidated cross-engine migration.

### Goel candidate G3: bounded dynamic latent equality atoms

**Labels:** K for dynamic Ackermannization; R for unbounded completion; U for recurrence-triggered proof expansion in the local bridge.

**Current gap.** The closed-atom probe found useful-looking application pairs but could not emit their clauses because result-equality atoms were absent. Creating all missing equality atoms is not viable: prior broad experiments generated millions of clauses.

**Implementation hypothesis.** Maintain saturating counters for application pairs that repeatedly appear in invalid source models, requested explanations, or congruence conflicts. Create an auxiliary result-equality atom only when all of the following hold:

- the applications have the same function symbol and arity;
- the pair crosses a recurrence threshold;
- per-function, per-component, and global atom/clause budgets remain available;
- the atom has a proof expansion into source-stable term identities and argument equalities;
- generic CaDiCaL factoring or existing source atoms do not already express the relation.

Use separate enter and stop thresholds, plus a quota relative to source equality atoms. This follows the bounded style of Yices' dynamic Ackermann parameters rather than eager completion.

**Falsification experiment.** First run a no-effect census that reports pair recurrence, missing result equalities, projected atom and clause counts, overlap with generic Boolean factoring, and source-level explanation reuse. Only instantiate atoms for frozen pairs that pass the census. Compare no atoms, source-closed atoms only, and recurrence-triggered latent atoms under identical clause caps.

**Fast rejection conditions.** Reject if hot pairs do not recur, if they require a large fraction of the projected 3,686 pair clauses, if atom definitions dominate learned clauses, if SAT model validation becomes more expensive, or if proof expansion cannot eliminate every auxiliary atom.

**Novelty risk.** High. Dynamic Ackermann reduction is implemented by Z3 and parameterized by Yices. A claim could only concern the exact recurrence source, lazy reason-token interaction, and proof expansion, and even that requires a broader solver-code survey.

### Goel candidate G4: bounded theory-clause retention

**Label:** K.

**Implementation hypothesis.** Keep only short, repeatedly reused theory clauses, with separate limits for clause width, retained literal count, component lifetime, and backtrack age. Count a hit only when retaining the clause avoids rebuilding an explanation or causes Boolean propagation.

**Falsification experiment.** Run cache-off, size-only, and size-plus-reuse policies. Measure rebuilds avoided, Boolean propagations caused, retained bytes, and stale clauses scanned.

**Fast rejection conditions.** Reject if the reuse distribution has no heavy head, retained clauses rarely propagate, or cache lookup and invalidation cost match saved explanation work.

**Novelty risk.** Very high. Yices documents small theory-clause caching. This is an implementation policy.

### Goel candidate G5: external decision steering

**Label:** K.

**Implementation hypothesis.** Implement the currently unused external `decide()` callback with a strictly bounded selector over existing source equality atoms. Rank by recent congruence impact, unresolved application pairs, and activity; never create atoms from this path.

**Falsification experiment.** Compare no steering, one decision per component activation, and unrestricted callback use. Record accepted suggestions, overridden decisions, propagation depth, conflicts, and branch entropy.

**Fast rejection conditions.** Reject if CaDiCaL routinely overrides the suggestions, if steering increases restarts or conflicts without reducing invalid models, or if gains disappear when the same initial variable order is supplied statically.

**Novelty risk.** Very high. Theory-aware branching and the IPASIR-UP decision callback are known.

### Goel candidate G6: opportunity-gated explanation choice

**Labels:** K and R.

**Implementation hypothesis.** Before constructing alternative congruence explanations, count whether the equality graph actually contains competing paths at the current level. Invoke a bounded Greedy-style selector only when alternatives can change reason width, backjump level, or estimated LBD. Retain redundant equalities only under a small fuel budget.

**Falsification experiment.** An observation-only pass must first report alternative-path frequency and the distribution of achievable width/backjump improvements. Then compare first-found and selected reasons on precisely those events.

**Fast rejection conditions.** Do not implement the selector if alternatives are rare, as in the previous local attempt. Reject it if graph maintenance costs more ticks than it saves or if shorter reasons do not improve end-to-end search.

**Novelty risk.** Very high. Both explanation optimization and retaining redundant equality edges are current research topics, and the 2026 cvc5 study demonstrates the runtime-risk directly.

## 2. CaDiCaL, IPASIR-UP, and Armin Biere's relevant work

The following sources define the external-propagation and proof-engineering baseline:

- Fazekas, Niemetz, Preiner, Kirchweger, Szeider, and Biere, **“IPASIR-UP: User Propagators for CDCL” (2023)**: [DOI](https://doi.org/10.4230/LIPIcs.SAT.2023.8). The interface supports assignment, decision-level, backtrack, propagation, reason, clause, model-check, and decision interactions.
- Fazekas, Niemetz, Preiner, Kirchweger, Szeider, and Biere, **“Satisfiability Modulo User Propagators” (2024)**: [DOI](https://doi.org/10.1613/JAIR.1.16163), [author PDF](https://kfazekas.github.io/papers/FazekasNiemetzPreinerKirchwegerSzeiderBiere-JAIR24.pdf), [artifact](https://doi.org/10.5281/zenodo.13710465). This is the main evaluation of the abstraction, including CaDiCaL-based use cases and cvc5 integration.
- Biere, Faller, Fazekas, Fleury, Froleyks, and Pollitt, **“CaDiCaL 2.0” (2024)**: [DOI](https://doi.org/10.1007/978-3-031-65627-9_7).
- Pollitt, Fleury, Fazekas, Froleyks, Schidler, Schreiber, and Biere, **“CaDiCaL 3.0” (2026)**: [DOI](https://doi.org/10.4230/LIPIcs.SAT.2026.40), [official release](https://github.com/arminbiere/cadical/releases/tag/rel-3.0.1). Its new Boolean mechanisms and deterministic scheduling are relevant controls, but do not replace a UF solver.
- Biere, Fazekas, Fleury, and Froleyks, **“Clausal Congruence Closure” (2024)**: [DOI](https://doi.org/10.4230/LIPIcs.SAT.2024.6). Despite the name, this detects congruent **Boolean gates** in clauses. It is not congruence closure for uninterpreted functions. It should be measured as a Boolean-shell control on Goel, not cited as EUF propagation.
- Pollitt, Fleury, and Biere, **“Faster LRAT Checking Than Solving with CaDiCaL” (2023)**: [DOI](https://doi.org/10.4230/LIPIcs.SAT.2023.21). This supplies the SAT-proof baseline and reinforces that certificate checking cost must be measured, not assumed.
- Fazekas, Pollitt, Fleury, and Biere, **“Certifying Incremental SAT Solving” (2024)**: [DOI](https://doi.org/10.29007/pdcc), [author PDF](https://kfazekas.github.io/papers/FazekasPollittFleuryBiere-LPAR24.pdf). Its incremental proof format and checker design are relevant when assumptions, external clauses, or staged solves enter the path.

CaDiCaL 3.0's clausal congruence closure, equivalence sweeping, bounded variable addition, and simplification should be run as exact-CNF controls before attributing a Goel change to the theory layer. Release notes also matter because propagator-compatible preprocessing defaults can change across versions. Any experiment must pin the CaDiCaL commit, options, and bridge commit.

## 3. Finite model finding, quasigroups, and Latin squares

### Source-completeness before search

The finite-model literature does not justify inferring a 7-element carrier from a benchmark directory name.

- Reynolds, Tinelli, Goel, and Krstić, **“Finite Model Finding in SMT” (2013)**: [DOI](https://doi.org/10.1007/978-3-642-39799-8_42), [author PDF](https://homepage.cs.uiowa.edu/~tinelli/papers/ReyEtAl-CAV-13.pdf).
- Reynolds, Tinelli, Goel, Krstić, Deters, and Barrett, **“Quantifier Instantiation Techniques for Finite Model Finding in SMT” (2013)**: [DOI](https://doi.org/10.1007/978-3-642-38574-2_26), [author page](https://theory.stanford.edu/~barrett/pubs/RTG%2B13-abstract.html).
- Reynolds, Tinelli, and Barrett, **“Constraint Solving for Finite Model Finding in SMT Solvers” (2017)**: [DOI](https://doi.org/10.1017/S1471068417000175), [author page](https://theory.stanford.edu/~barrett/pubs/RTB17-abstract.html).

These works combine cardinality constraints with on-demand instantiation for quantified finite model finding. qg7 is ground QF_UF, so the transferable lesson is explicit finite-cardinality reasoning and source-preserving model construction, not direct reuse of the quantifier algorithm.

Torlak and Jackson, **“Kodkod: A Relational Model Finder” (2007)**, is also relevant for bounds, sparse relational representations, partial solutions, and symmetry-aware Boolean translation: [DOI](https://doi.org/10.1007/978-3-540-71209-1_49), [author PDF](https://groups.csail.mit.edu/sdg/pubs/2007/tacas07-torlak-jackson.pdf).

### qg7 prerequisite Q0: a source-complete finite-table projection

**Labels:** K for finite relational compilation; L for the existing bounded evaluator and table components.

**Implementation hypothesis.** Define a fail-closed extractor whose output consists of:

- a source-derived carrier bound and proof of every term's range;
- one table cell for every reachable binary-operation application;
- a translation for every source assertion, implication, equality, disequality, and Skolem term;
- explicit residual clauses for supported source constructs not absorbed into the table CSP;
- an inverse map from a table assignment to a complete source interpretation.

Do not activate the specialization if any source node, range obligation, or interpretation mapping is unsupported. The existing test-only source evaluator can act as a differential oracle, but not as the proof of correctness.

**Falsification experiment.** Exhaustively enumerate small carriers for generated formulas at orders 1 through 4. Compare source evaluation, projected table satisfaction, and reconstructed source models in both directions. Add mutation tests for each currently omitted qg7 obligation. On the real instances, report a source-node coverage ledger and abstain unless it reaches 100%.

**Fast rejection conditions.** Block all qg7 performance claims if the extractor relies on path names, if one direction of model reconstruction is missing, if Skolem interpretations are partial, or if any source construct is silently dropped.

**Novelty risk.** Low as a research claim. It is necessary solver engineering and a precondition for evaluating later ideas.

### qg7 candidate Q1: incremental matching and Hall propagation

**Labels:** K and L.

**Implementation hypothesis.** Wire the bounded Latin exact-cover engine and rollback Hall component into the source-complete path. Use incremental bipartite matching for each changed row and column. Emit a propagation only when the matching support or a Hall set proves it; retain a compact witness sufficient for independent replay.

Régin, **“A Filtering Algorithm for Constraints of Difference in CSPs” (1994)**, is the matching-based generalized-arc-consistency baseline: [AAAI page](https://m.aaai.org/Library/AAAI/1994/aaai94-055.php), [PDF](https://cdn.aaai.org/AAAI/1994/AAAI94-055.pdf). Elffers, Gocht, McCreesh, and Nordström, **“Justifying All Differences Using Pseudo-Boolean Reasoning” (2020)**, provides a proof-logging baseline: [DOI](https://doi.org/10.1609/aaai.v34i02.5507).

**Falsification experiment.** Compare singleton-only Latin propagation, full matching support, and bounded Hall-set propagation under the same branching order. Count non-singleton Hall events, removed values, search nodes, matching repairs, explanation widths, and checker time.

**Fast rejection conditions.** Reject full matching if non-singleton pruning is rare or matching repair dominates search. Root-level absence of Hall events is not enough to reject it; the measurement must include branch-induced domains.

**Novelty risk.** Very high. Matching-based `AllDifferent`, exact cover, rollback search, and Hall explanations are known. Knuth's **“Dancing Links” (2000)** is the classic reversible exact-cover reference: [arXiv](https://arxiv.org/abs/cs/0011047).

### qg7 candidate Q2: canonical augmentation under verified conjugation

**Labels:** K and L.

**Implementation hypothesis.** First prove mechanically that every translated source constraint is invariant under simultaneous carrier relabeling. Then maintain a stabilizer chain for the assigned table prefix and branch only along a canonical construction path. Every rejected child records a concrete permutation mapping it to an accepted representative.

McKay, **“Isomorph-Free Exhaustive Generation” (1998)**, establishes canonical construction paths and applies orderly generation to structures including Latin rectangles: [DOI](https://doi.org/10.1006/jagm.1997.0898), [author PDF](https://users.cecs.anu.edu.au/~bdm/papers/orderly.pdf). McKay, Meynert, and Myrvold, **“Small Latin Squares, Quasigroups, and Loops” (2007)**, gives the relevant classification setting: [DOI](https://doi.org/10.1002/jcd.20105), [author PDF](https://users.cecs.anu.edu.au/~bdm/papers/ls_final.pdf).

Dančo, Janota, Codish, and Araújo, **“Complete Symmetry Breaking for Finite Models” (2025)**, is especially close prior art: it gives compact complete symmetry breaking for finite models with one binary operation, including magmas: [DOI](https://doi.org/10.1609/aaai.v39i11.33217). Any qg7 novelty claim must distinguish itself from this construction experimentally and formally.

**Falsification experiment.** Exhaustively compare the accepted prefix set against brute-force orbit representatives for orders at most 5. On qg7, compare four exact-CNF/search controls: no symmetry handling, static structure-based breaking, complete magma breaking, and native canonical augmentation. Check that every complete model orbit has exactly one accepted representative.

**Fast rejection conditions.** Reject immediately on an invariant violation, a missing orbit, multiple terminal representatives, or canonical-test cost comparable to the removed subtree cost.

**Novelty risk.** Very high. Canonical augmentation and complete symmetry breaking for a single binary operation are known. Applying them to this verified source translation may be valuable engineering, but is not itself a defensible novelty claim.

### qg7 candidate Q3: orbit-quotiented forbidden-table automaton

**Labels:** L and U.

**Current gap.** The local 5,040 forbidden complete tables form one observed simultaneous-conjugation orbit. Removing their direct root clauses reduced encoding but did not solve the instances. The missing ingredient is propagation from the forbidden family during partial assignment, not merely a smaller root encoding.

**Implementation hypothesis.** Compile the forbidden family into a reduced MDD/MVDD or equivalent automaton over table cells. Quotient each automaton state by the same stabilizer used for canonical augmentation. Search state becomes the product of:

- the partial Latin table;
- row and column matching state;
- the current stabilizer/canonical-prefix state;
- the live forbidden-family automaton state.

The automaton may prune only when all completions of the current state are forbidden. Each prune must replay to either a source clause or a checked orbit witness plus terminal forbidden-table certificate.

**Falsification experiment.** On small orders, compare the accepted complete tables and every pruning event against explicit enumeration of all forbidden roots. On qg7, use an ablation matrix: raw roots, unquotiented automaton, canonical augmentation alone, and their product. Report states, transitions, quotient collisions, branch nodes, memory, and certificate bytes.

**Fast rejection conditions.** Reject if automaton states grow near the raw root trie, if quotient canonicalization costs dominate transitions, if the product gives no pruning beyond canonical augmentation, or if a prune lacks a replayable source-level witness.

**Novelty risk.** Medium to high. MDDs, forbidden-tuple constraints, canonical augmentation, and symmetry quotienting are known, and this combination is already proposed locally. The exact proof-carrying product may be unlocated, but that is not evidence of novelty.

### qg7 candidate Q4: partial row-cycle canonicality

**Label:** U.

Gill, Mammoliti, and Wanless, **“Canonical Labeling of Latin Squares in Average-Case Polynomial Time” (2025)**, uses row-cycle structure for complete Latin squares: [DOI](https://doi.org/10.1002/rsa.70015), [arXiv](https://arxiv.org/abs/2402.06205). Extending a complete-square canonical label to safe partial-prefix pruning is nontrivial.

**Implementation hypothesis.** Derive only prefix invariants that are monotone under completion, and use them to refine the stabilizer partition before a full canonical test. Never prune from a complete-square invariant whose value can change under extension.

**Falsification experiment.** Exhaustively enumerate all partial Latin tables at each depth for orders at most 5. Verify that the filter leaves at least one prefix for every completable orbit and agrees with full canonical labeling at terminal depth.

**Fast rejection conditions.** One lost completable orbit rejects the filter. Also reject it if partition refinement does not reduce canonical-test work after accounting for its own cost.

**Novelty risk.** High in both directions: the exact partial-prefix method was not located here, but there may be unpublished or differently named canonical augmentation work, and the 2025 result does not itself establish sound partial pruning.

### qg7 candidate Q5: isomorph-free cube generation

**Label:** K.

Araújo, Chow, and Janota, **“Symmetries for Cube-And-Conquer in Finite Model Finding” (2023)**, discards isomorphic cubes in finite model finding: [DOI](https://doi.org/10.4230/LIPIcs.CP.2023.8). Use this only after a source-complete projection and only if parallel cube execution is needed.

**Implementation hypothesis.** Generate cubes at a fixed source-complete table-prefix depth, canonicalize each cube under the verified residual group, and retain one representative plus explicit permutation witnesses for discarded cubes. Estimate remaining search mass before dispatch so orbit reduction does not create a few disproportionately hard cubes.

**Falsification experiment.** Compare ordinary cubes and orbit-representative cubes at equal estimated subproblem mass. Check cube coverage, pairwise orbit duplication, solving skew, and certificate aggregation.

**Fast rejection conditions.** Reject if canonicalization merely moves work into the cube phase, if representative cubes are badly imbalanced, or if source-level cover checking is unavailable.

**Novelty risk.** Very high. This is directly known.

### qg7 candidate Q6: dynamic symmetry propagation through IPASIR-UP

**Label:** K.

Kirchweger and Szeider, **“SAT Modulo Symmetries for Graph Generation” (2021)**, implements dynamic partial canonicality through a SAT user propagator: [DOI](https://doi.org/10.4230/LIPIcs.CP.2021.34). Adapting this style to simultaneous row-column-symbol conjugation is plausible, but complete binary-operation symmetry breaking is already available as a close static baseline.

**Implementation hypothesis.** Observe only table-cell literals and maintain the canonical-prefix predicate incrementally under assignment and rollback. Return a blocking clause over the first lexicographically decisive cells, with an explicit permutation witness that an independent checker can replay.

**Falsification experiment.** Compare native finite-table canonical augmentation, static emitted clauses, and an IPASIR-UP symmetry propagator over the same canonical predicate. Separate callback cost, reason construction, learned clauses, and nodes removed.

**Fast rejection conditions.** Reject if the propagator reproduces the static clauses at higher cost, if reasons are too large, or if canonical checking does not exploit partial assignments beyond the static baseline.

**Novelty risk.** Very high. SAT modulo symmetries is known; the application may be new only in a narrow engineering sense.

## 4. Symmetry controls that must be included

qg7 experiments need modern generic controls; comparison only with raw clauses would overstate a specialized method.

- Anders, Brenner, and Rattan, **“Satsuma: Structure-Based Symmetry Breaking in SAT” (2024)**: [DOI](https://doi.org/10.4230/LIPIcs.SAT.2024.4). Relevant structures include row interchangeability, row-column symmetry, and Johnson actions.
- Anders, Schweitzer, and Soos, **“Algorithms Transcending the SAT-Symmetry Interface” (2023)**: [DOI](https://doi.org/10.4230/LIPIcs.SAT.2023.1). This is a baseline for exploiting natural actions, orbits, and decompositions rather than treating the CNF graph alone.
- Anders, Codel, and Heule, **“Simplify, Order, Break, Repeat” (2026)**: [DOI](https://doi.org/10.4230/LIPIcs.SAT.2026.4). Its iterative unit/binary symmetry clauses and simplification are an exact-CNF control.
- Anders, Codel, and Heule, **“Orbitopal Fixing in SAT” (2026)**: [DOI](https://doi.org/10.1007/978-3-032-22752-2_5), [arXiv](https://arxiv.org/abs/2601.16855). Its fixing clauses and substitution-redundancy proofs are another required control when a matrix action is available.

Simultaneous conjugation of a binary operation is not automatically identical to independent row or column permutation. The comparison must use the exact group action and report whether each control preserves and exploits that action.

## 5. Proof logging for theory and finite-model propagation

An LRAT proof of the emitted Boolean formula is not, by itself, a proof that a source-level qg7 projection, symmetry prune, or auxiliary equality is valid. The certificate needs layers.

### Proposed certificate stack

| Layer | Obligation | Candidate evidence |
|---|---|---|
| Source translation | Projected constraints and reconstructed models are equivalent to the supported source formula | Checked translation ledger, source-node coverage, bidirectional small-model differential tests |
| EUF propagation | Each propagated equality/conflict follows from assigned source equalities and congruence | Replayable equality paths and congruence steps; auxiliary equality expansion |
| Latin/Hall | Each value deletion or conflict follows from matching/Hall structure | Hall witness or pseudo-Boolean derivation |
| Symmetry | A pruned branch has a source-preserving permutation to a retained branch | Explicit permutation, canonical comparison trace, and a checked invariant declaration |
| Forbidden family | Every rejected completion belongs to the exact forbidden set; partial pruning excludes only states with no allowed completion | Automaton transition trace and terminal table certificate |
| SAT search | Learned clauses and final contradiction are propositionally valid | LRAT/FRAT or the pinned CaDiCaL proof path |

Relevant primary work:

- Schurr, Fleury, Barbosa, and Fontaine, **“Alethe: Towards a Generic SMT Proof Format” (2021)**: [DOI](https://doi.org/10.4204/EPTCS.336.6).
- Barbosa, Reynolds, El Ouraoui, Lachnitt, and Tinelli, **“Flexible Proof Production in an Industrial-Strength SMT Solver” (2022)**: [DOI](https://doi.org/10.1007/978-3-031-10769-6_3). The modular and lazy proof architecture is directly relevant to deferred external reasons.
- Baek, Carneiro, and Heule, **“A Flexible Proof Format for SAT Solver-Elaborator Communication” (2022)**: [DOI](https://doi.org/10.46298/LMCS-18(2:3)2022). FRAT is relevant when solver-side proof hints need elaboration.
- Bogaerts, Gocht, McCreesh, and Nordström, **“Certified Dominance and Symmetry Breaking for Combinatorial Optimisation” (2023)**: [DOI](https://doi.org/10.1613/JAIR.1.14296). Dominance reasoning supplies a proof framework for without-loss-of-generality steps.
- Anders, Bogaerts, Bogø, Gontier, Koops, McCreesh, Myreen, Nordström, Oertel, Rebola-Pardo, and Tan, **“Faster Certified Symmetry Breaking Using Orders with Auxiliary Variables” (2026)**: [DOI](https://doi.org/10.1609/aaai.v40i17.38426). Auxiliary order variables and VeriPB checking are relevant to compact canonical-order certificates.

### Required negative tests

Every new proof rule should ship with mutants that the checker must reject:

- remove one antecedent from a congruence reason;
- reuse a reason token after its rollback generation;
- map an auxiliary equality to the wrong source-term pair;
- omit one member of a Hall set;
- use a non-bijective or non-invariant symmetry map;
- alter one forbidden-table automaton transition;
- drop one source assertion from the projection ledger.

Checker time, peak memory, and certificate size are benchmark outputs. A fast solver path with an uncheckable or disproportionately expensive certificate does not pass the gate.

## 6. Novelty ledger

| Candidate | Closest known work | Status after this audit | What would have to be new | Main novelty risk |
|---|---|---|---|---|
| G1 observed slicing + lazy reason tokens | IPASIR-UP; Lazy Explanations; cvc5 flexible proofs | U, not established novel | A sound source-boundary closure and rollback token protocol with measured avoided work | Lazy explanations are old; another bridge may already expose deferred reasons |
| G2 adaptive propagation activation | DPLL(T) policies; user-propagator scheduling | K | Nothing claimed | Policy tuning is not algorithmic novelty |
| G3 recurrence-triggered latent equalities | Z3 dynamic Ackermann; Yices Ackermann thresholds | U only for exact trigger/proof composition | Recurrence derived from requested source explanations plus bounded proof expansion | Dynamic Ackermannization is established and close |
| G4 theory-clause retention | Yices theory-clause cache | K | Nothing claimed | Direct prior deployment |
| G5 external decision steering | IPASIR-UP decision callback; theory-aware branching | K | Nothing claimed | Direct interface feature |
| G6 opportunity-gated short reasons | Small Proofs; 2026 cvc5 adaptation | K/R | Nothing claimed without a materially different objective | Very recent close prior art; local opportunity may be absent |
| Q0 source-complete table projection | finite model finding; Kodkod | K/L | Nothing claimed | Required correctness engineering |
| Q1 dynamic Hall propagation | Régin; PB AllDifferent proofs | K/L | Nothing claimed | Standard global-constraint propagation |
| Q2 canonical augmentation | McKay; complete finite-model symmetry breaking | K/L | Nothing claimed | 2025 complete magma breaking is extremely close |
| Q3 quotient automaton product | MDD/forbidden tuples; canonical augmentation; local proposal | L/U | A compact checked product construction with useful partial propagation | Combination may exist under constraint-automata or symmetry-reduced search terminology |
| Q4 partial row-cycle refinement | 2025 Latin-square canonical labeling | U, high risk | A monotone, sound partial-table invariant that reduces canonical tests | Complete-square method may not extend; related orderly-generation work may cover it |
| Q5 isomorph-free cubes | 2023 finite-model cube symmetry | K | Nothing claimed | Direct prior work |
| Q6 dynamic symmetry propagator | SAT Modulo Symmetries | K | Nothing claimed without a new proof/source composition | Direct prior mechanism |

No entry in this table supports a statement of genuine novelty. G1, G3, Q3, and Q4 justify a deeper novelty search only after their falsification gates show that the mechanisms matter.

## 7. Preregistered experiment order

1. **G-OBS:** add observation-only counters for callback volume, reason requests, reason construction, hot application pairs, and generic Boolean-factor overlap. No search behavior changes.
2. **G1:** run the 2x2 observation-slice/deferred-reason factorial, first in shadow replay and then under frozen target and anti-target gates.
3. **G3:** admit latent equalities only if G-OBS finds a small recurrent pair set that survives strict projected atom/clause budgets.
4. **Q0:** complete and differentially validate the source-to-table projection. Do not time a specialized qg7 engine before this passes.
5. **Q1:** integrate the Latin baseline, then measure incremental matching and Hall propagation as separate ablations.
6. **Q2:** compare canonical augmentation against complete magma breaking, Satsuma, SORB, and orbitopal-fixing controls under the exact verified action.
7. **Q3:** add the forbidden-table automaton only after Q2, so its incremental pruning is separable from symmetry reduction.
8. **Certificates:** run all proof mutants and measure checker cost before broad timing.

For every timed stage, pin the corpus DOI, instance hashes, solver and bridge commits, CaDiCaL version/options, hardware class, timeout, seeds, and target/anti-target manifests. Report solved counts and distributions without extrapolating beyond the frozen sets.

## 8. Recommended implementation boundary

The shared substrate should remain small:

- stable source term and atom identifiers;
- rollback generation counters;
- reason tokens and certificate event transport;
- deterministic counters and trace serialization;
- independent source-model validation.

The Goel EUF path and qg7 finite-table path should keep separate propagation state, activation gates, and proof rules. Runtime migration between them is not required by any candidate above and would confound the first experiments.

The relevant local hooks are the isolated CaDiCaL adapter, finite Hall propagator, Latin exact-cover search, source evaluator, stabilizer/orbit probes, and forbidden-table MDD/MVDD components. Their current existence lowers implementation cost but does not count as an integrated result.

## 9. Stable corpus and context links

- The benchmark snapshot used by the local campaign is archived at [Zenodo DOI 10.5281/zenodo.16740866](https://doi.org/10.5281/zenodo.16740866).
- The official SMT-LIB logic definition for QF_UF is available from the [SMT-LIB logic catalogue](https://smt-lib.org/logics.shtml).
- For hardware-derived Goel context, Lee and Sakallah, **“Unbounded Scalable Verification Based on Approximate Property-Directed Reachability and Datapath Abstraction” (2014)**, describes datapath abstraction in unbounded verification: [DOI](https://doi.org/10.1007/978-3-319-08867-9_56). It is context, not evidence that every Goel benchmark has the same recoverable structure.
- Ansótegui, del Val, Dotú, Fernández, and Manyà, **“Modeling Choices in Quasigroup Completion: SAT vs. CSP” (2004)**, demonstrates that quasigroup encoding and propagation choices materially affect search: [AAAI PDF](https://cdn.aaai.org/AAAI/2004/AAAI04-022.pdf). It does not by itself supply the qg7 source proof or symmetry method.

## Bottom line

The lowest-risk Goel experiment is not a new EUF algorithm. It is removing avoidable external-propagator work, while measuring whether callbacks and eager reasons are actually the cost center. The only bounded semantic expansion worth testing next is recurrence-triggered auxiliary equalities, because unrestricted completion already failed locally and production solvers establish strict prior art.

The lowest-risk qg7 step is correctness infrastructure: a source-complete finite-table projection. Once that exists, canonical augmentation and dynamic Hall propagation are strong known baselines. The orbit-quotiented forbidden-table automaton is the most specific local combination to test, but it must show a distinct incremental effect relative to those controls and pass source-level certificate checks before it warrants a broader claim.
