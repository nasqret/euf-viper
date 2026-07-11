# Proof-Complexity Countermeasures for Eager QF_UF

Date: 2026-07-11

Status: primary-source exclusion audit and executable experiment campaign.
This is not a claim that any candidate below is unpublished, patentable, or
absent from private solver implementations.

## Research Question

The narrow target is the hard tail of an eager, one-shot `QF_UF` solver:
ground equality and uninterpreted functions are reduced to a propositional
problem, but finite-domain, injection, operation-table, and classification
instances expose cardinality- and pigeonhole-shaped subproblems on which plain
CDCL inherits the limitations of resolution.

The campaign asks a more precise question than "which SAT trick is fast?":

> Which 2018-2026 SAT/SMT mechanisms can be recombined with typed EUF
> structure so that the eager fast head is preserved, the resolution-hard tail
> is routed to a stronger representation or proof system, and every additional
> inference remains independently checkable?

The relevant comparison boundary is Z3, Yices2, and cvc5 as complete SMT
solvers, plus Kissat as a modern propositional backend. A technique already
published or visible in one of these systems is excluded as a standalone
novelty claim. The remaining opportunity is an EUF-specific recognizer,
representation, schedule, proof interface, or combination.

## Evidence Discipline

This audit used papers, author-hosted preprints, official proceedings,
artifacts, official solver documentation, and version-pinned public source.
The main publication window is 2018-2026. Older work is mentioned only where it
defines a baseline that a recent paper extends.

Labels used below:

- **EVIDENCED**: the linked primary source or pinned implementation directly
  supports the statement.
- **INFERENCE**: a proposed consequence of the evidence, not a statement made
  by the source.
- **NOT LOCATED**: this bounded audit did not find the exact mechanism in the
  cited papers or audited public paths. This is not evidence of absence.
- **EXCLUDED**: established prior art; implementation may still be useful, but
  the central mechanism cannot support a novelty claim.
- **CANDIDATE COMBINATION**: the ingredients are known, but the exact typed
  `QF_UF` composition was not located in this audit.

The audit did not systematically search patents, every historical branch,
non-English literature, proprietary solvers, or unpublished work. Any paper
claim must repeat and broaden that search.

## Executive Finding

1. **A newer SAT backend does not remove the proof-system wall.** Robere,
   Kolokolova, and Ganesh model SMT proof complexity and prove an
   information-theoretic lower-bound consequence for eager EUF-to-SAT
   reductions. Modern CDCL engineering can move constants dramatically, but a
   plain eager encoding still asks a resolution engine to count.

2. **The strongest direct countermeasure is selective proof-system escalation.**
   Native pseudo-Boolean cutting planes, matching/Hall propagation, and
   BDD/MDD reasoning can have short proofs on families that are hard for
   resolution. The practical requirement is to recover the high-level
   constraint before it is erased by generic CNF.

3. **Generic BVA is necessary but not sufficient.** Structured BVA is effective
   in practice, but 2026 graph-theoretic results prove that idealized BVA cannot
   construct the asymptotically smaller product encoding for at-most-one. The
   EUF solver should therefore introduce semantic extension variables directly
   for rows, neighborhoods, or stabilizer states instead of waiting for blind
   CNF BVA to rediscover them.

4. **Two 2026 mechanisms materially change the experiment order.** Iterating
   simplification with unit/binary symmetry cuts can outperform conventional
   lex leaders, and factoring learned clauses can make extended-resolution
   definitions useful after search has exposed structure. Both invite typed
   EUF variants, but neither justifies calling those variants novel yet.

5. **The defensible design is a structure-retaining compiler, not another
   monolithic DPLL(T) implementation.** Keep term, function-table, finite-range,
   orbit, and Hall metadata beside every emitted atom. Use that metadata to
   choose literal order, extension variables, propagation, cubing, and proof
   witnesses. Leave ordinary instances on the current low-overhead eager path.

## Audited Public Solver Boundary

Statements in this table are intentionally narrow. A blank or "not located"
cell does not assert that a solver lacks the technique.

| Mechanism | Z3 4.16.0 | Yices2 audited snapshot | cvc5 1.3.3 | Kissat 4.0.4 | Consequence for this campaign |
| --- | --- | --- | --- | --- | --- |
| Ground EUF and dynamic theory lemmas | **EVIDENCED:** [EUF e-graph, propagation, and explanations](https://github.com/Z3Prover/z3/blob/z3-4.16.0/src/sat/smt/euf_solver.cpp); [dynamic Ackermannization](https://github.com/Z3Prover/z3/blob/z3-4.16.0/src/sat/smt/euf_ackerman.cpp) | **EVIDENCED:** dedicated [e-graph implementation](https://github.com/SRI-CSL/yices2/tree/b11db7c43ef72f9bd77d66a9c588d3eae80eaf93/src/solvers/egraph) and [documented dynamic Ackermann parameters](https://yices.csl.sri.com/doc/parameters.html) | **EVIDENCED:** equality-engine/UF implementation in the [official source tree](https://github.com/cvc5/cvc5/tree/cvc5-1.3.3/src/theory/uf) | Not an SMT solver | Rollback congruence closure, theory propagation, explanations, and dynamic Ackermann lemmas are **EXCLUDED** as standalone novelty. |
| Native cardinality or PB machinery | **EVIDENCED:** SAT-level [cardinality/PB extension](https://github.com/Z3Prover/z3/blob/z3-4.16.0/src/sat/smt/pb_solver.cpp). Automatic recovery of Hall structure from arbitrary `QF_UF` was **NOT LOCATED**. | Positive evidence for an analogous general PB engine was **NOT LOCATED** in the audited source paths. | **EVIDENCED:** UF [cardinality extension](https://github.com/cvc5/cvc5/blob/cvc5-1.3.3/src/theory/uf/cardinality_extension.cpp), including regions, disequalities, and clique tests. | Native PB/cardinality support was **NOT LOCATED** in the audited release options. | Native counting is occupied. A typed recognizer that selectively reconstructs Hall/PB constraints remains a **CANDIDATE COMBINATION**. |
| UF value/range symmetry | No positive deployment evidence was located in the audited `sat/smt/euf_*` paths. | **EVIDENCED:** [QF_UF symmetry source](https://github.com/SRI-CSL/yices2/blob/b11db7c43ef72f9bd77d66a9c588d3eae80eaf93/src/context/symmetry_breaking.c) checks assertion invariance and emits range/value clauses. | **EVIDENCED:** [UF symmetry breaker](https://github.com/cvc5/cvc5/blob/cvc5-1.3.3/src/theory/uf/symmetry_breaker.cpp) implements the Deharbe-Fontaine-Merz-Paleo algorithm. | Generic SAT symmetry machinery was **NOT LOCATED** in the audited release. | Constant interchangeability, value precedence, and ordinary range symmetry are **EXCLUDED**. Complete orbit/stabilizer compilation needs a narrower claim. |
| BCE/BVE/subsumption | **EVIDENCED:** [SAT simplifier](https://github.com/Z3Prover/z3/blob/z3-4.16.0/src/sat/sat_simplifier.cpp) contains blocked/covered clause elimination, variable elimination, and subsumption. | A comparable broad inprocessing inventory was not audited deeply enough for a claim. | Optional SAT backends and internal preprocessing exist, but no claim is made here about the exact `QF_UF` schedule. | **EVIDENCED:** release [options](https://github.com/arminbiere/kissat/blob/rel-4.0.4/src/options.h) enable BVE and multiple preprocessing passes. | Generic elimination is **EXCLUDED**. Projection-aware elimination of EUF-generated auxiliaries is an implementation question with model-reconstruction obligations. |
| BVA/factorization | No positive evidence of the 2023/2026 structured variants was located in the audited Z3 paths. | **NOT LOCATED**. | CaDiCaL can be integrated through IPASIR-UP, but that does not establish use of BVA in the default `QF_UF` route. | **EVIDENCED:** `factor` is described as bounded variable addition; `factorstructural` and effort controls are visible in [options.h](https://github.com/arminbiere/kissat/blob/rel-4.0.4/src/options.h). | Generic and structured BVA are **EXCLUDED**. EUF-semantic factor selection and learned-clause factorization are candidate combinations. |
| Vivification and SAT sweeping | No claim from this bounded audit. | No claim from this bounded audit. | No claim from this bounded audit. | **EVIDENCED:** `vivify`, `sweep`, budgets, and scheduling controls are enabled in [options.h](https://github.com/arminbiere/kissat/blob/rel-4.0.4/src/options.h). | Boolean vivification/sweeping are **EXCLUDED**. A rollback-EUF oracle inside vivification was **NOT LOCATED**. |
| Clausal congruence closure | Z3 has theory congruence closure, which is not the same mechanism as gate extraction from arbitrary CNF. | Same distinction applies to the Yices e-graph. | No claim from this bounded audit. | **EVIDENCED:** [gate extraction and congruence closure](https://github.com/arminbiere/kissat/blob/rel-4.0.4/src/congruence.c) for AND/XOR/ITE structures, enabled by default in [options.h](https://github.com/arminbiere/kissat/blob/rel-4.0.4/src/options.h). | Boolean clausal congruence closure is **EXCLUDED**. A typed dual closure spanning source EUF nodes and emitted Boolean gates is a candidate combination. |
| Local-search/CDCL exchange | No claim from this bounded audit. | No claim from this bounded audit. | No claim from this bounded audit. | **EVIDENCED:** local search, target phases, rephasing, and phase import are described in the 2022 paper and visible through `walk`/`rephase` controls in [options.h](https://github.com/arminbiere/kissat/blob/rel-4.0.4/src/options.h). | Generic local-search guidance is **EXCLUDED**. Searching only valid finite EUF interpretations and importing their source-level phases was **NOT LOCATED**. |
| Proof production | Z3 has internal proof construction/checking in the EUF source, but this audit does not equate it with an external FRAT/LRAT plus EUF certificate. | External proof production was **NOT LOCATED** in the audited boundary. | **EVIDENCED:** [proof documentation and Alethe output](https://cvc5.github.io/docs/latest/proofs/proofs.html); broad proof sources are in the tagged tree. | **EVIDENCED:** proof-chain support in [proof.c](https://github.com/arminbiere/kissat/blob/rel-4.0.4/src/proof.c). | DRAT/FRAT/LRAT, Alethe, and congruence explanations are **EXCLUDED** as novelty. The exact composite certificate still has to be engineered and checked. |

## Primary-Source Mechanism Map, 2018-2026

### Proof Complexity, Cardinality, and Pseudo-Boolean Reasoning

| Year | Primary source | Direct evidence | Exclusion or opening |
| --- | --- | --- | --- |
| 2018 | Robere, Kolokolova, Ganesh, [The Proof Complexity of SMT Solvers](https://doi.org/10.1007/978-3-319-96142-2_18) | Introduces `Res(T)`/`Res*(T)` models and proves, under ETH, a worst-case size consequence for EUF-to-SAT reductions. | **EXCLUDES** the claim that low-level eager encoding alone removes the theoretical tail. It does not predict practical crossover points. |
| 2018 | Vinyals, Elffers, Giráldez-Cru, Gocht, Nordström, [In Between Resolution and Cutting Planes](https://jakobnordstrom.se/docs/publications/ProofSystemsPBsolving_SAT.pdf) | Relates practical PB conflict-analysis rules to proof systems between resolution and cutting planes. | **EXCLUDES** "PB conflict analysis" as novelty; motivates measuring which rule strength is actually needed. |
| 2018 | Elffers and Nordström, [Divide and Conquer: Towards Faster Pseudo-Boolean Solving](https://gitlab.com/MIAOresearch/software/roundingsat) | RoundingSat performs native cutting-planes conflict analysis; the official repository identifies the IJCAI 2018 origin and current implementation. | **EXCLUDES** a generic PB fallback as novelty. Selective extraction from typed EUF is still an engineering and combination question. |
| 2020 | Elffers, Gocht, McCreesh, Nordström, [Justifying All Differences Using Pseudo-Boolean Reasoning](https://ojs.aaai.org/index.php/AAAI/article/view/5507) | Gives efficient PB justifications for matching-based `AllDifferent` propagation. | **EXCLUDES** Hall/matching propagation and PB explanations as standalone ideas. Automatic sound recovery from `QF_UF` remains open in this audit. |
| 2021 | Bryant and Heule, [Generating Extended Resolution Proofs with a BDD-Based SAT Solver](https://arxiv.org/abs/2105.00885) | A BDD solver emits extended-resolution proofs and scales on pigeonhole, parity, Urquhart, and mutilated-chessboard families. | **EXCLUDES** BDD-based strong reasoning plus ER proof output. A typed MDD over operation-table cells is a narrower candidate. |
| 2022 | Grosof, Zhang, Heule, [Towards the Shortest DRAT Proof of the Pigeonhole Principle](https://arxiv.org/abs/2207.11284) | Auxiliary variables and recursive decomposition yield manually constructed `O(n^3)` DRAT proofs while ordinary solvers exhibit exponential behavior. | Shows that a short standard proof can exist without a generic CDCL heuristic finding it. Semantic extension-variable discovery is central. |
| 2024 | Reeves, Heule, Bryant, [From Clauses to Klauses](https://www.cs.cmu.edu/~mheule/publications/knf.pdf) | Proposes native cardinality constraints (`KNF`) rather than erasing them into clauses. | **EXCLUDES** native cardinality input/propagation. Recovering EUF cardinality and preserving its identity across the compiler is the candidate. |
| 2024 | Nieuwenhuis, Oliveras, Rodríguez-Carbonell, Zhao, [Speeding up Pseudo-Boolean Propagation](https://drops.dagstuhl.de/entities/document/10.4230/LIPIcs.SAT.2024.22) | Counter and watched propagation win on different constraint shapes; a carefully implemented hybrid is faster overall in RoundingSat. | **EXCLUDES** either propagation scheme and the generic hybrid. It supplies a concrete implementation template for an EUF Hall/PB sidecar. |
| 2025 | Reeves, Filipe, Hsu, Martins, Heule, [The Impact of Literal Sorting on Cardinality Constraint Encodings](https://ojs.aaai.org/index.php/AAAI/article/view/33232) | Related literals placed nearby can give auxiliary variables better semantic meaning; ordering can matter more than encoding family. | **EXCLUDES** literal-order optimization. Ordering by typed congruence/application/orbit structure was **NOT LOCATED**. |
| 2025 | Koops et al., [Practically Feasible Proof Logging for Pseudo-Boolean Optimization](https://drops.dagstuhl.de/entities/document/10.4230/LIPIcs.CP.2025.21) | VeriPB plus CakePB covers advanced RoundingSat/Sat4j techniques with practically feasible formally verified checking. | Removes "PB cannot be certified practically" as an excuse. Proof generation and checking must be timed separately. |
| 2026 | Przybocki, Subercaseaux, Heule, [Automated Reencoding Meets Graph Theory](https://www.cs.cmu.edu/~mheule/publications/BVA-SAT26.pdf) | Characterizes idealized BVA on 2-CNF and proves an at-most-one lower bound of `3n-6`; BVA cannot discover the `2n+o(n)` product encoding. | **EXCLUDES** BVA as a universal cardinality repair. Direct semantic encodings can occupy a space that blind BVA provably cannot reach. |

### BVA, BCE, Vivification, and Congruence-Based Inprocessing

| Year | Primary source | Direct evidence | Exclusion or opening |
| --- | --- | --- | --- |
| 2018 | Li, Xiao, Luo, Manyà, Lü, Li, [Clause Vivification by Unit Propagation in CDCL SAT Solvers](https://arxiv.org/abs/1807.11061) | Uses scheduled unit propagation to remove literals from selected original and learned clauses; selection and literal order matter. | **EXCLUDES** Boolean vivification. An EUF explanation oracle can strengthen the implication test without changing the basic method. |
| 2019 | Fazekas, Biere, Scholl, [Incremental Inprocessing in SAT Solving](https://doi.org/10.1007/978-3-030-24258-9_9) | Formalizes and implements conditions for sound inprocessing in incremental use. | **EXCLUDES** incremental elimination as novelty and warns that assumptions/frozen variables constrain transformations. |
| 2023 | Haberlandt, Green, Heule, [Effective Auxiliary Variables via Structured Reencoding](https://drops.dagstuhl.de/entities/document/10.4230/LIPIcs.SAT.2023.11) | Structured BVA makes tie-breaking robust and shows that auxiliary-variable meaning matters beyond formula size. | **EXCLUDES** AST-like tie-breaking in generic BVA. Typed EUF neighborhoods can provide a stronger semantic score, but this exact use was **NOT LOCATED**. |
| 2024 | Biere, Fazekas, Fleury, Froleyks, [Clausal Congruence Closure](https://drops.dagstuhl.de/entities/document/10.4230/LIPIcs.SAT.2024.6) | Extracts AND/XOR/ITE gates from CNF and runs congruence closure to eliminate isomorphic subcircuits, including during inprocessing. | **EXCLUDES** gate extraction plus congruence closure. Sharing identities across source EUF and Boolean gates is a candidate boundary. |
| 2024 | Lagniez, Marquis, Biere, [Dynamic Blocked Clause Elimination for Projected Model Counting](https://drops.dagstuhl.de/entities/document/10.4230/LIPIcs.SAT.2024.21) | Restricting blocked-clause search to projected variables preserves projected counts and improves `d4`. | **EXCLUDES** projection-aware BCE. It suggests treating Tseitin/Ackermann auxiliaries differently from source equality atoms, with explicit model reconstruction. |
| 2025 | Pollitt et al., [Revisiting Clause Vivification](https://cca.informatik.uni-freiburg.de/papers/PollittFleuryBiereSakallahHeuleChenFisseha-POS25.pdf) | Details current Kissat/CaDiCaL scheduling and shows that a subtle clause-retention choice caused a large performance regression. | Reinforces that a theory-aware pass must be budgeted and ablated; literal removal counts alone are not evidence of speed. |
| 2025 | Fazekas, Pollitt, Fleury, Biere, [Incremental Inprocessing Rules beyond Resolution](https://cca.informatik.uni-freiburg.de/papers/FazekasPollittFleuryBiere-POS25.pdf) | Gives sufficient conditions for incremental BVA and selected blocked-clause additions beyond resolution. | **EXCLUDES** incremental BVA/BCA architecture. Every extension-variable experiment needs a scoped lifetime and reconstruction proof. |
| 2025 | Gstrein, Pollitt, Schidler, Fleury, Biere, [Learn to Unlearn](https://cca.informatik.uni-freiburg.de/papers/GstreinPollittSchidlerFleuryBiere-SAT25.pdf) | Re-evaluates learned-clause deletion in Kissat; recent use is important, and SAT/UNSAT behavior differs. | A new clause producer must include database-retention interaction in its factorial experiment. Keeping all new theory/factor clauses is not a neutral baseline. |
| 2026 | Pollitt et al., [Factoring Learned Clauses](https://www.cs.cmu.edu/~mheule/publications/ER-SAT26.pdf) | CaDiCaL-FX applies BVA-like AND/XOR/ITE factorization to original and learned clauses and reports hard-family gains with little general overhead. | **EXCLUDES** learned-clause factoring and ER definitions. EUF-signature-driven factor candidates were **NOT LOCATED** in this source. |

### Symmetry, Cubing, Enumeration, and Search Hybrids

| Year | Primary source | Direct evidence | Exclusion or opening |
| --- | --- | --- | --- |
| 2022 | Bogaerts et al., [Certified Symmetry and Dominance Breaking](https://ojs.aaai.org/index.php/AAAI/article/view/20283) | Certifies general symmetry, dominance, parity, and cardinality reasoning with PB proofs. | **EXCLUDES** proof-logged generic symmetry. Typed formula automorphisms and a cheaper special certificate remain implementation choices. |
| 2022 | Cai, Zhang, Fleury, Biere, [Better Decision Heuristics in CDCL through Local Search and Target Phases](https://cca.informatik.uni-freiburg.de/papers/CaiZhangFleuryBiere-JAIR22.pdf) | Exchanges complete assignments, phases, and variable activity between local search and CDCL; implemented in Kissat and other solvers. | **EXCLUDES** generic local-search/CDCL cooperation. A local-search state space containing only valid finite EUF interpretations is a candidate combination. |
| 2023 | Araújo, Chow, Janota, [Symmetries for Cube-And-Conquer in Finite Model Finding](https://drops.dagstuhl.de/entities/document/10.4230/LIPIcs.CP.2023.8) | Discards isomorphic cubes while remaining compatible with the Least Number Heuristic in Mace4. | **EXCLUDES** symmetry-reduced finite-model cubing. Typed equality-partition cubes and proof-prefix scoring are still a specific composition to test. |
| 2023 | Fazekas et al., [IPASIR-UP: User Propagators for CDCL](https://drops.dagstuhl.de/entities/document/10.4230/LIPIcs.SAT.2023.8) | Exposes external propagation, conflicts, reasons, decisions, and model checks; evaluated with cvc5 and CaDiCaL. | **EXCLUDES** the SAT/theory callback interface. It is the cleanest implementation boundary for Hall and EUF-aware vivification experiments. |
| 2024 | Anders, Brenner, Rattan, [Satsuma: Structure-Based Symmetry Breaking in SAT](https://drops.dagstuhl.de/entities/document/10.4230/LIPIcs.SAT.2024.4) | Detects row, row-column, Johnson, and combined structures faster than prior generic graph-based approaches on relevant families. | **EXCLUDES** those static structure detectors. Source-level operation-table actions can bypass generic CNF graph discovery, but are not automatically novel. |
| 2025 | Dančo, Janota, Codish, Araújo, [Complete Symmetry Breaking for Finite Models](https://ojs.aaai.org/index.php/AAAI/article/view/33217) | Computes compact complete symmetry breaks for finite models focused on one binary operation (magmas). | **EXCLUDES** complete canonization for a single closed binary table. Multi-symbol, partial-table, or base-formula integration needs a precise scope and prior-art search. |
| 2025 | Battleman, Reeves, Heule, [Problem Partitioning via Proof Prefixes](https://drops.dagstuhl.de/entities/document/10.4230/LIPIcs.SAT.2025.3) | Uses early proof-variable frequencies and a cardinality-aware partitioner to find effective static splits. | **EXCLUDES** proof-prefix cubing and cardinality-aware partitioning. Using EUF explanation/proof-prefix statistics to select a stronger proof system was **NOT LOCATED**. |
| 2025 | Spallitta, Sebastiani, Biere, [Disjoint Projected Enumeration for SAT and SMT without Blocking Clauses](https://cca.informatik.uni-freiburg.de/papers/SpallittaSebastianiBiere-AIJ25.pdf) | Combines CDCL, chronological backtracking, theory reasoning, and implicant shrinking to enumerate disjoint projected partial models without blocking clauses. | **EXCLUDES** non-blocking projected AllSAT/AllSMT. Enumerating disjoint partial operation tables as a bounded model-search tier is a candidate composition. |
| 2025 | Schreiber, Rigi-Luperti, Biere, [Streamlining Distributed SAT Solver Design](https://drops.dagstuhl.de/entities/document/10.4230/LIPIcs.SAT.2025.27) | Centralizes preprocessing and runs lightweight uniform clause-sharing workers; redundant per-worker inprocessing can be harmful. | **EXCLUDES** centralized preprocessing plus uniform distributed CDCL. Any WMI design should avoid rebuilding the same semantic EUF indexes in every worker. |
| 2026 | Anders, Codel, Heule, [Orbitopal Fixing in SAT](https://doi.org/10.1007/978-3-032-22752-2_5) | Adds proof-logged unit symmetry fixes with negligible general regressions and gains on symmetry-rich inputs. | **EXCLUDES** orbitopal fixing and unit-only certified symmetry. Typed operation-table orbit fixing is a specialization, not automatically a new mechanism. |
| 2026 | Anders et al., [Faster Certified Symmetry Breaking Using Orders with Auxiliary Variables](https://ojs.aaai.org/index.php/AAAI/article/view/38426) | Auxiliary-variable order encodings reduce proof logging/checking cost by orders of magnitude in Satsuma/VeriPB experiments. | **EXCLUDES** auxiliary order variables for symmetry proofs. It is the preferred proof representation if typed lex orders are tested. |
| 2026 | Anders, Codel, Heule, [Simplify, Order, Break, Repeat](https://www.cs.cmu.edu/~mheule/publications/Symbreak-SAT26.pdf) | Alternates simplification with unit/binary symmetry cuts, uses connectivity/cliques to order cuts, and reports 22% PAR-2 improvement over CaDiCaL on SAT Competition 2025. | **EXCLUDES** the generic iteration. Recomputing typed UF stabilizers after EUF simplification is a **CANDIDATE COMBINATION**. |

### Proof-Certificate Infrastructure

| Year | Primary source | What it establishes | Required use here |
| --- | --- | --- | --- |
| 2021/2022 | Baek, Carneiro, Heule, [FRAT](https://arxiv.org/abs/2109.09665) | Solver hints, clause IDs, and final-clause information reduce LRAT elaboration cost while keeping solver overhead low. | Use FRAT/LRAT for the propositional spine and extension definitions; do not invent an opaque SAT trace. |
| 2021 | Schurr, Fleury, Barbosa, Fontaine, [Alethe](https://arxiv.org/abs/2107.02354) | A pragmatic generic SMT proof format designed for solver/checker interoperability. | Reuse its architectural separation or export compatible equality steps; format adoption itself is not novelty. |
| 2023 | Pollitt, Fleury, Biere, [Faster LRAT Checking Than Solving with CaDiCaL](https://drops.dagstuhl.de/entities/document/10.4230/LIPIcs.SAT.2023.21) | Native proof-chain generation can make LRAT checking practical. | Record antecedents when generated rather than reconstructing every chain after the run. |
| 2024 | Schreiber, [Trusted Scalable SAT Solving with On-The-Fly LRAT Checking](https://drops.dagstuhl.de/entities/document/10.4230/LIPIcs.SAT.2024.25) | Distributed LRAT reasoning can be checked online with much lower overhead than a monolithic post-hoc artifact. | For WMI cubes, check leaf clauses/proofs as they arrive and separately certify cube coverage. |
| 2025 | Koops et al., [Practically Feasible PB Proof Logging](https://drops.dagstuhl.de/entities/document/10.4230/LIPIcs.CP.2025.21) | VeriPB elaboration plus formally verified CakePB checking covers modern PB search. | Hall, cardinality, and symmetry steps should use PB witnesses rather than being mislabeled as EUF lemmas. |

## Exclusion and Candidate-Combination Matrix

The "not located" column reports only this audit. It is a hypothesis generator,
not a publication claim.

### A. Proof-System and Cardinality Countermeasures

| ID | Known implemented technique and exact source | Solver-presence evidence | Exact combination not located in this audit | Falsifiable benchmark prediction | Soundness and proof burden |
| --- | --- | --- | --- | --- | --- |
| A1 | Plain eager EUF reduction plus modern CDCL; proof-complexity boundary in [CAV 2018](https://doi.org/10.1007/978-3-319-96142-2_18) | Z3 and Yices use dynamic rather than purely eager theory lemmas; Kissat 4.0.4 is a strong CDCL backend. | No new combination: this is the baseline and is **EXCLUDED**. | Backend-only swaps may improve constants but will retain exponential-looking conflict/proof growth on scaled EUF pigeonholes. Test `n=6..16` and fit conflicts/proof bytes, not just timeout. | Ordinary CNF mapping plus FRAT/LRAT is sufficient, but a short proof is not guaranteed. |
| A2 | Matching/Hall propagation with PB justifications, [AAAI 2020](https://ojs.aaai.org/index.php/AAAI/article/view/5507); hybrid PB watchers, [SAT 2024](https://drops.dagstuhl.de/entities/document/10.4230/LIPIcs.SAT.2024.22) | Z3 has a PB extension; cvc5 has UF cardinality regions/clique tests; no automatic `QF_UF` Hall recovery was located in the audited paths. | **CANDIDATE:** prove a finite value set from typed EUF constraints, build a reversible matching, and send only Hall conflicts/propagations to a PB-capable sidecar. | On generated EUF-PHP, matching repairs and PB steps should grow polynomially through at least `n=32`; on the frozen corpus, easy-instance p95 must regress by less than 1%, while at least one current cardinality timeout stratum gains solves. | Certify finite-domain exhaustiveness, every variable-domain edge, the Hall neighborhood/matching witness, and the derived PB inequality. SAT still requires full source-model validation. |
| A3 | Native cardinality/KNF, [CAV 2024](https://www.cs.cmu.edu/~mheule/publications/knf.pdf); structure-aware literal ordering, [AAAI 2025](https://ojs.aaai.org/index.php/AAAI/article/view/33232) | Generic cardinality engines exist; no evidence was located that any audited QF_UF path orders recovered value literals by UF application or orbit structure. | **CANDIDATE:** order each totalizer/cardinality network by `(function symbol, argument congruence class, stabilizer orbit, disequality-neighborhood overlap)` rather than source or variable ID. | Holding encoding family and size fixed, the typed order should reduce decisions, propagations, and learned-clause LBD by at least 20% on recognized finite-table/Hall cases and yield at least 1.25x geometric speedup. | Ordering is semantic-preserving. The checker must reconstruct the same data-literal set and verify the definitional CNF independent of the heuristic order. |
| A4 | BDD reasoning with ER proofs, [2021](https://arxiv.org/abs/2105.00885); short DRAT PHP decomposition, [2022](https://arxiv.org/abs/2207.11284) | No general QF_UF solver deployment of a table-cell MDD/BDD proof tier was located. | **CANDIDATE:** compile recognized forbidden operation-table suffixes and Hall deficits into a reduced multi-valued decision diagram, with a strict state cap and SAT fallback. | On orbit-heavy `iso*`/`nogen*` inputs, state count should be below 25% of raw forbidden-literal count and parser-inclusive solve time at least 2x faster; otherwise the compiler abstains. | Exhaustively check the MDD truth relation on small carriers. Emit definitional ER/FRAT steps or a separately checked MDD proof, plus an exact atom-to-source map. |
| A5 | Proof-prefix partitioning, [SAT 2025](https://drops.dagstuhl.de/entities/document/10.4230/LIPIcs.SAT.2025.3), and stronger PB/BDD proof systems above | Proof prefixes are used for cubing; no source was located that uses an EUF proof-prefix fingerprint to switch proof systems within a single solver. | **CANDIDATE:** run a bounded deterministic eager probe, classify the emerging proof as congruence-, Hall-, orbit-, or Boolean-dominated, then activate exactly one stronger tier. | A probe capped at min(`5,000` conflicts, 0.5% of timeout) should preserve at least 99.5% of baseline easy solves and recover more timeout-charged total time than it spends. Classification must beat a static AST-only selector on a held-out family split. | The selector is heuristic and outside soundness. Every selected route needs its own checked proof; timeout/abstention returns `unknown`, never `unsat`. |

### B. Representation and Inprocessing Countermeasures

| ID | Known implemented technique and exact source | Solver-presence evidence | Exact combination not located in this audit | Falsifiable benchmark prediction | Soundness and proof burden |
| --- | --- | --- | --- | --- | --- |
| B1 | Structured BVA, [SAT 2023](https://drops.dagstuhl.de/entities/document/10.4230/LIPIcs.SAT.2023.11); BVA limits, [SAT 2026](https://www.cs.cmu.edu/~mheule/publications/BVA-SAT26.pdf) | Kissat 4.0.4 exposes BVA/factorization and structural controls. | **CANDIDATE:** introduce extension variables directly for repeated UF rows, argument-equality rectangles, Hall neighborhoods, and orbit-prefix states; score by predicted watch traffic and explanation reuse. | Semantic factoring should reduce watched literals by at least 30% and improve targeted total time even against Kissat BVA enabled. If generic BVA reaches the same representation and speed, reject the special pass. | BVA is equisatisfiability-preserving, not generally model-preserving. Log each definition, maintain source-model reconstruction, and emit ER/FRAT or SR-valid additions. |
| B2 | Learned-clause factoring, [SAT 2026](https://www.cs.cmu.edu/~mheule/publications/ER-SAT26.pdf) | CaDiCaL-FX is the direct implementation evidence; Kissat has generic factorization, but exact learned-clause behavior is not inferred from the option name. | **CANDIDATE:** canonicalize equality literals by typed UF application signatures and factor repeated learned tails only when the new variable has a source-level row/neighborhood meaning. | On clauses learned from repeated Ackermann/table conflicts, require at least 25% fewer clause bytes and 15% fewer propagations after amortizing detection; no more than 0.5% overhead when no factor is emitted. | Every introduced variable needs a total definition and proof step. Deletion policy must be tested factorially so definitions outlive every clause that uses them. |
| B3 | Projection-aware BCE, [SAT 2024](https://drops.dagstuhl.de/entities/document/10.4230/LIPIcs.SAT.2024.21); Z3 blocked/covered elimination source | Z3 has BCE/CCE; dynamic projected BCE is evidenced in `d4`, not in the audited QF_UF routes. | **CANDIDATE:** run blocked/covered elimination preferentially on Tseitin, Ackermann, MDD, and symmetry-order auxiliaries while treating source equality atoms as projected variables to preserve model observability. | Remove at least 20% of auxiliary clauses on high-duplication eager CNFs, lower peak watch bytes, and preserve or improve SAT model-reconstruction time. Reject if source validation failures or total time increase. | Record the elimination stack and reconstruct all eliminated auxiliaries before source-model checking. UNSAT proof logging must justify additions/deletions in the chosen proof format. |
| B4 | Boolean clause vivification, [2018](https://arxiv.org/abs/1807.11061) and [2025](https://cca.informatik.uni-freiburg.de/papers/PollittFleuryBiereSakallahHeuleChenFisseha-POS25.pdf) | Kissat 4.0.4 enables vivification. No rollback-EUF-enhanced variant was located. | **CANDIDATE:** while vivifying a selected clause prefix, run watched propagation and rollback congruence closure together; cache short EUF explanations as binary or ternary clauses. | On long equality-path clauses, remove at least twice as many literals as Boolean-only vivification and reduce downstream propagations by 15%; total vivification budget stays below 2% of baseline runtime. | A removed literal requires a replayable Boolean or EUF explanation from the negated retained prefix. Never accept a closure answer lacking typed antecedents. |
| B5 | Clausal congruence closure, [SAT 2024](https://drops.dagstuhl.de/entities/document/10.4230/LIPIcs.SAT.2024.6) | Kissat 4.0.4 contains AND/XOR/ITE gate CCC; Z3/Yices/cvc5 already have theory e-graphs. | **CANDIDATE:** maintain a cross-layer identity table linking source Boolean DAG nodes, typed equality atoms, Ackermann guards, and extracted CNF gates; merge only identities proved either structurally or by unconditional EUF congruence. | On high Boolean-occurrence-duplication inputs, eliminate at least 10% more literals than source DAG hash-consing plus Kissat CCC independently, with construction below 1% of solve time. | Structural identities use definitional equivalence proofs. EUF identities need unconditional congruence proofs; conditional equalities must remain guarded and cannot be substituted globally. |
| B6 | Iterated symmetry simplification, [SAT 2026](https://www.cs.cmu.edu/~mheule/publications/Symbreak-SAT26.pdf) | Generic implementation is in Satsuma/CaDiCaL; Yices and cvc5 have ordinary UF range symmetry. | **CANDIDATE:** add only typed unit/binary stabilizer cuts, simplify the term/CNF graph, recompute the residual automorphism group, and repeat before large lex or orbit constraints are considered. | On recognized finite-table families, each round must expose new fixes or shrink the active group; targeted PAR-2 improves by at least 20%, and non-symmetric misses cost below 1 ms. | Verify sort-preserving whole-formula automorphisms, base invariance after every rewrite, and each SR/PB symmetry step. Stop if the checker cannot replay the changed group. |

### C. Search, Enumeration, and Parallel Countermeasures

| ID | Known implemented technique and exact source | Solver-presence evidence | Exact combination not located in this audit | Falsifiable benchmark prediction | Soundness and proof burden |
| --- | --- | --- | --- | --- | --- |
| C1 | Local-search/CDCL phase exchange, [JAIR 2022](https://cca.informatik.uni-freiburg.de/papers/CaiZhangFleuryBiere-JAIR22.pdf) | Implemented in Kissat and other CDCL solvers. | **CANDIDATE:** local search moves over finite equivalence partitions and function-table cells, so every state is a valid EUF interpretation; import only source-atom phases and conflict frequencies. | On SAT finite-model strata, reach a validated model at least 2x faster on median; on UNSAT strata, bounded local search adds less than 1% p95 overhead. Compare against ordinary bit-level WalkSAT phases. | Local search may only produce a SAT candidate. Re-evaluate the complete source formula independently; failed candidates are hints, never conflicts or UNSAT evidence. |
| C2 | Symmetry-aware finite-model cubing, [CP 2023](https://drops.dagstuhl.de/entities/document/10.4230/LIPIcs.CP.2023.8); proof-prefix splitting, [SAT 2025](https://drops.dagstuhl.de/entities/document/10.4230/LIPIcs.SAT.2025.3) | Implemented in Mace4/Proofix-style tools, not located as a QF_UF eager tier in the audited solvers. | **CANDIDATE:** cube on canonical equality partitions, Hall-critical assignments, and stabilizer-minimal table prefixes, scored by short EUF/SAT proof prefixes. | On WMI with 8 and 32 workers, obtain at least 4x and 12x wall speedup respectively while total CPU stays below 2.25x and 3x the sequential candidate. Raw-Boolean cubes are the control. | Certify that cubes are disjoint or at least cover the root, record every symmetry witness used to remove a cube, and check every UNSAT leaf proof. |
| C3 | Disjoint projected AllSMT without blocking clauses, [AIJ 2025](https://cca.informatik.uni-freiburg.de/papers/SpallittaSebastianiBiere-AIJ25.pdf) | TabularAllSMT is direct implementation evidence. | **CANDIDATE:** enumerate disjoint partial assignments only to operation-table/equality variables, shrink each to a source implicant, and stop immediately on a fully validated finite model. | On SAT classification instances with many Boolean auxiliaries, generate at least 5x fewer projected decisions than blocking-clause enumeration and reduce memory while preserving model-finding time. | A SAT answer needs one complete source model. Turning exhaustive enumeration into UNSAT additionally requires a checked disjoint cover and proofs that every partial cube is impossible. |
| C4 | Central preprocessing plus uniform distributed clause sharing, [SAT 2025](https://drops.dagstuhl.de/entities/document/10.4230/LIPIcs.SAT.2025.27) | Demonstrated in MallobSat; no QF_UF-specific semantic preprocessor claim is made. | **CANDIDATE:** construct typed term/orbit/Hall indexes once, distribute an immutable compiled core plus certificate digest, and let workers share only source-mapped or independently checked clauses. | Compared with per-worker compilation, startup CPU and memory should fall approximately with worker count; search wall time must not regress after excluding compilation. | Every worker verifies the input/CNF/index digest. Imported clauses need proof chains or online validation; model reconstruction remains centralized and independent. |
| C5 | Complete single-magma symmetry breaking, [AAAI 2025](https://ojs.aaai.org/index.php/AAAI/article/view/33217), plus certified order encodings, [AAAI 2026](https://ojs.aaai.org/index.php/AAAI/article/view/38426) | Published tools cover the stated generic scopes; no production QF_UF route was located. | **CANDIDATE:** prove the surrounding typed formula invariant, quotient a recognized forbidden-table family by the carrier action, and encode only the stabilizer automaton of canonical prefixes. | For an exact free orbit of size `d!`, compile one representative plus a polynomial-size prefix automaton rather than `d!` table clauses; require at least 20x literal reduction and 2x end-to-end speed at `d=6..8`. | Check typed extraction, group action, base invariance, orbit coverage, stabilizer transitions, and decoded models. A table-only symmetry is unsound if the surrounding formula fixes names asymmetrically. |

## What Is Definitely Not a Novelty Claim

The following descriptions should not appear in a paper title, abstract, or
claim of contribution without a materially narrower qualifier:

- eager Ackermannization with a modern SAT backend;
- partial or dynamic Ackermannization;
- rollback congruence closure, EUF explanations, or theory propagation;
- native cardinality/PB solving or cutting-planes conflict analysis;
- matching-based `AllDifferent`/Hall propagation with PB proofs;
- BVA, structured BVA, BCE/BVE, vivification, or clausal congruence closure;
- ordinary finite-domain encoding, value precedence, range symmetry, lex
  leaders, Satsuma structures, or complete canonization of a single magma;
- local-search phase import, proof-prefix cubing, symmetry-aware finite-model
  cubing, or projected AllSMT without blocking clauses;
- DRAT, FRAT, LRAT, Alethe, VeriPB, or composite SAT/SMT proof architecture by
  itself.

The potentially defensible object is the exact typed composition, for example:
recovering a proved finite value graph from arbitrary ground EUF; choosing a
cardinality literal order from congruence and stabilizer structure; escalating
only the detected component to Hall/PB/MDD reasoning; and composing its proof
with the eager CNF and source-model checker. Even this wording remains
provisional until a broader prior-art and implementation audit is complete.

## Campaign Design

### Corpus Stratification Before Implementation

Freeze manifests before viewing candidate timings:

1. **Fast head:** instances solved by the accepted eager binary in less than
   10 ms, stratified by parser size and SAT/UNSAT result.
2. **Congruence tail:** long equality paths and repeated applications without
   a proved finite carrier.
3. **Hall/cardinality tail:** proved finite ranges, dense disequality graphs,
   injections, exact-one rows, and synthetic scaled EUF pigeonholes.
4. **Orbit/table tail:** complete or near-complete function tables,
   `iso*`/`nogen*`-style constraints, and exact automorphism witnesses.
5. **Boolean-duplication tail:** high repeated-DAG occurrence ratios but weak
   additional EUF quotienting.
6. **Negative controls:** structurally similar formulas with one missing range
   edge, broken automorphism, polarity inversion, or conditional rather than
   unconditional congruence.

Family grouping is mandatory in train/tune/test splits. Siblings from the same
generator must not be divided across selector training and final evaluation.

### Factorial Experiment Rule

Each mechanism is tested alone before combinations. A valid row records:

- source revision, candidate revision, binary digest, compiler, target CPU,
  backend version/commit, feature flags, seed, host, and timeout;
- input digest, family, structural stratum, oracle result, candidate result,
  wall/user time, peak RSS, and proof/check time;
- source terms, equality atoms, Boolean DAG nodes, CNF variables/clauses,
  watched literals, propagations, decisions, conflicts, learned-clause bytes,
  and LBD distribution;
- mechanism-specific counters: Hall matching repairs and witnesses; PB
  propagations; MDD states; factor candidates/definitions; vivified literals
  and EUF explanation widths; group size, stabilizer size, symmetry cuts, and
  removed cubes;
- SAT model-validation result and UNSAT certificate-validation result.

For interacting passes use a full small factorial, not a stack with no
attribution. Examples: `BVA x learned-factor x deletion-policy`, `symmetry x
simplification-order`, and `Boolean-vivification x EUF-vivification`.

### Promotion Funnel

1. Exhaustive truth/model equivalence on generated carriers through the largest
   feasible small size; mutation tests must corrupt every certificate field.
2. Deterministic microbenchmarks that isolate the mechanism's predicted shape.
3. Frozen targeted WMI A/B with the same binary and one feature flag changed.
4. Fast-head gate: no result changes, no new unknowns, and no statistically
   significant parser-inclusive regression beyond the experiment's stated cap.
5. Full four-solver corpus campaign against the accepted euf-viper control,
   Z3, Yices2, and cvc5 at short and long timeouts.
6. Rerun the accepted control binary in the same allocation; compare paired
   rows, timeout-charged total, PAR-2, solved count, geometric speed on common
   solves, and bootstrap confidence intervals.
7. Promote only if every SAT model and every UNSAT proof checks. Report proof
   generation and checking costs both separately and end to end.

Clause count, conflict count, a selected-family win, or a lower median is not a
promotion result. The governing metric is coverage-adjusted end-to-end time
with the easy head protected.

## Expert Watchlist

The highest-value active lines to monitor before each campaign revision are:

- **Armin Biere, Mathias Fleury, Katalin Fazekas, Florian Pollitt, Nils
  Froleyks:** [official publication list](https://cca.informatik.uni-freiburg.de/papers/),
  especially clausal congruence closure, IPASIR-UP, vivification, learned-clause
  retention/factoring, local-search/DDFW integration, and distributed proof
  checking. The 2026 DDFW paper is listed officially, but this audit did not use
  inaccessible technical details from it.
- **Marijn Heule, Joseph Reeves, Zachary Battleman, Cayden Codel, Markus Anders,
  Bernardo Subercaseaux:** semantic auxiliary variables, cardinality literal
  ordering, proof-prefix partitioning, learned-clause factoring, verified
  encodings, and iterative certified symmetry.
- **Jakob Nordström, Stephan Gocht, Wietze Koops, Ciaran McCreesh, Magnus
  Myreen:** proof complexity, cutting planes, Hall explanations, VeriPB, CakePB,
  and certified symmetry/dominance.
- **Robert Nieuwenhuis, Albert Oliveras, Enric Rodriguez-Carbonell, Rui Zhao:**
  low-level PB propagation, directly relevant to whether a strong tail tier can
  be fast enough to preserve coverage-adjusted performance.
- **Robert Robere, Antonina Kolokolova, Vijay Ganesh:** SMT proof-complexity
  boundaries that prevent an empirical backend win from being overstated as a
  universal eager-solver result.

## Ranked Executable Experiments

The ranking estimates expected **coverage-adjusted** speed: probability of
recognition times value of converted timeouts, minus preprocessing and proof
cost over the whole corpus. It is not a novelty ranking.

### 1. Congruence-Ordered Hall/KNF Hybrid

**Composition.** Recover only proved finite-domain components from typed EUF;
maintain a reversible matching; encode or propagate Hall constraints with the
2024 hybrid PB watcher; order cardinality literals by shared UF symbol,
argument congruence class, stabilizer orbit, and neighborhood overlap.

**Why unconventional.** It combines constraint recovery, proof-complexity
escalation, and encoding-order semantics. The goal is not fewer clauses but
auxiliary variables that summarize the same EUF neighborhoods likely to recur
in conflicts.

**First executable slice.** Generate scaled injective-function and table-row
EUF-PHP instances. Compare pairwise CNF, totalizer-natural, totalizer-random,
totalizer-congruence-order, native PB, and matching-plus-PB under one parser and
one SAT backend.

**Prediction.** The matching/PB arms avoid exponential-looking conflict growth
through `n=32`; congruence ordering beats natural ordering by at least 1.25x on
recognized official instances; miss overhead is below 1% p95.

**Kill condition.** Reject if domain exhaustiveness is rarely provable, if PB
handoff costs more timeout-charged time than it recovers, or if a generic
cardinality encoding with random/natural order matches the typed arm.

**Proof burden.** Typed range certificate, edge extraction, Hall witness,
VeriPB/CakePB derivation, definitional CNF reconstruction, and independent SAT
model validation.

### 2. Typed Simplify-Order-Break-Repeat

**Composition.** Compute a sort-preserving automorphism group over carrier
constants and table cells; choose high-connectivity orbit representatives; add
only unit/binary stabilizer cuts; simplify both term and CNF graphs; recompute
the residual group; repeat until no certified progress.

**Why unconventional.** It treats symmetry cuts as an iterative simplifier of
the EUF compiler rather than a static pile of lex leaders. The recomputed object
is a typed term/table action, not only a variable-clause graph.

**First executable slice.** Use exhaustive carriers through size five and
frozen `iso*`/`nogen*` targets. Compare no symmetry, existing range symmetry,
one-shot lex, one-shot complete table canonization, generic Satsuma, and the
typed iterative loop.

**Prediction.** Collapse every certified free table orbit to one canonical
prefix, reduce emitted literals by at least 20x on the exact-orbit target, and
obtain at least 2x parser-inclusive targeted speed with sub-millisecond misses.

**Kill condition.** Reject if group recomputation dominates, no new fixes
appear after the first round, or generic 2026 Satsuma preprocessing matches the
typed result and runtime.

**Proof burden.** Whole-formula base invariance, typed automorphism generators,
stabilizer transitions, SR/PB symmetry steps, orbit coverage, and source-model
decoding.

### 3. EUF-Semantic Factoring of Learned Clauses

**Composition.** Observe original and learned clauses, canonicalize equality
literals by UF application signature, and introduce an extension variable only
for a repeated row/neighborhood/tail whose predicted saved watch traffic
exceeds definition and lifetime cost. Couple activation to the learned-clause
deletion policy.

**Why unconventional.** CaDiCaL-FX factors Boolean gate patterns. This arm asks
whether CDCL has exposed a repeated *theory reason* that should become a named
extended-resolution object even though the backend never sees the source term
graph.

**First executable slice.** Replay traces from repeated Ackermann and finite
table conflicts. Run a `factor-source x factor-learned x deletion-policy`
factorial with generic Kissat/CaDiCaL factoring as controls.

**Prediction.** At least 25% fewer learned-clause bytes and 15% fewer
propagations on the target stratum, less than 0.5% corpus-wide detection
overhead, and a positive timeout-charged full-corpus total.

**Kill condition.** Reject if generic factorization finds the same definitions,
definitions die before reuse, proof output dominates, or clause reduction does
not translate to wall time.

**Proof burden.** Total ER definitions, stable source IDs, FRAT/LRAT chains,
definition lifetime checks, and SAT model reconstruction.

### 4. Rollback-EUF Vivification and Theory HBR

**Composition.** Select long/high-use clauses under the current Kissat-style
budget. Propagate the negated prefix simultaneously through watched clauses and
rollback congruence closure. Shrink on a checked conflict; cache only very short
EUF consequences as binary/ternary clauses.

**Why unconventional.** It applies a mature Boolean inprocessing operation
through a theory oracle without turning the solver into a full-time lazy
CDCL(T) engine.

**First executable slice.** Build clauses with redundant equality paths and
congruence diamonds. Compare no vivification, Boolean-only, EUF-only, combined,
and combined-with-short-clause-cache at fixed propagation/tick budgets.

**Prediction.** At least twice the literal removals of Boolean-only
vivification on the target, 15% fewer later propagations, and total pass cost
below 2% of baseline runtime.

**Kill condition.** Reject if explanation construction erases propagation
savings, if most candidate clauses produce no shrink, or if full-corpus total
regresses despite local literal reduction.

**Proof burden.** Replay every removed literal from the retained prefix using a
typed EUF explanation or Boolean RUP chain; log every cached short clause.

### 5. Proof-Prefix-Triggered Proof-System Switching and Canonical Cubing

**Composition.** Run a tiny deterministic eager probe and classify early
conflicts/explanations by Hall deficit, orbit repetition, congruence depth, and
Boolean gate recurrence. Stay eager for ordinary cases; otherwise switch one
component to PB/MDD or choose stabilizer-minimal theory cubes for WMI workers.

**Why unconventional.** Published proof-prefix work chooses split variables.
Here the prefix chooses both the proof system and typed split object while the
accepted eager binary remains the zero-overhead default route.

**First executable slice.** Freeze a family-disjoint training set and compare
AST-only routing, proof-prefix-only routing, combined routing, and an oracle
selector. For cubing compare raw Boolean variables with equality partitions,
Hall-critical edges, and table prefixes at 1/8/32 workers.

**Prediction.** At least 99.5% of easy baseline solves survive; selected tail
coverage improves; 8 and 32 workers achieve at least 4x and 12x wall speedup
without exceeding 2.25x and 3x sequential CPU respectively.

**Kill condition.** Reject if routing accuracy fails on held-out families, the
probe consumes more timeout-charged time than it recovers, or theory cubes are
less balanced than raw Boolean cubes.

**Proof burden.** Route-local certificates, a checked cube tree/cover,
automorphism witnesses for removed cubes, online FRAT/LRAT checking, and an
immutable compiler/certificate digest shared by all workers.

### 6. Orbit-Disjoint EUF Model Search with Local-Search Phases

**Composition.** Search over concrete finite equivalence partitions and
function-table cells so congruence is true by construction. Use DDFW-style
weights on falsified source constraints, shrink successful interpretations to
disjoint projected table/equality cubes without blocking clauses, and import
the best validated source-atom phases into CDCL.

**Why unconventional.** Generic SAT local search flips arbitrary Tseitin bits.
This search never enters a semantically impossible EUF state and can exchange
partial source models, orbit representatives, and conflict frequencies rather
than opaque Boolean assignments.

**First executable slice.** Restrict to independently proved carriers of size
at most eight. Compare ordinary WalkSAT/Kissat phases, finite-interpretation
local search, projected chronological enumeration, and the combined model
hunter on SAT/UNSAT-balanced frozen strata.

**Prediction.** At least 2x median speedup on recognized SAT finite-model
instances, 5x fewer projected decisions than blocking enumeration, and less
than 1% p95 overhead on UNSAT or ineligible inputs.

**Kill condition.** Reject if maintaining valid interpretations makes moves too
expensive, source-level phases do not improve CDCL, or gains disappear after
full model validation and parser time are included.

**Proof burden.** Local search is never trusted for UNSAT. A SAT result requires
a complete independently evaluated typed source model. Exhaustive UNSAT via
enumeration additionally requires a checked disjoint cover and a proof for
every rejected projected cube.
