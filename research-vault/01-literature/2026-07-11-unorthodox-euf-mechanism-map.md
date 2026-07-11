# Unorthodox QF_UF Mechanism Map

Date: 2026-07-11

Status: active hypothesis ledger. This note is a literature-screening and
experiment document, not an absolute novelty claim.

## Boundary

Ackermannization, CDCL(T), congruence closure, generic symmetry breaking,
bounded variable addition, blocked-clause elimination, native cardinality and
pseudo-Boolean solving, finite-model ladders, cube-and-conquer, and proof
logging are established. A defensible contribution must therefore lie in an
EUF-specific representation, recognizer, proof interface, routing rule, or
combination that survives source archaeology and ablation.

The measured project facts that constrain the search are:

- Yices2 is approximately `4.27x` faster in the accepted 1,200-second
  opportunity checkpoint;
- the domain-seven `iso_icl_nogen001` input contains exactly `7! = 5,040`
  complete forbidden tables in one conjugacy orbit;
- that input has 497,474 Boolean occurrences but only 11,370 syntactically
  distinct nodes, a 97.7144% occurrence-duplication ratio;
- unconditional EUF quotienting removes only another 42 nodes there, so
  syntactic polarity compilation and table structure dominate theory-DAG
  quotienting on this family;
- the hard coverage tail contains pigeonhole-shaped finite constraints for
  which ordinary resolution can be exponentially weak.

## Ranked Mechanisms

### M1: Canonical forbidden-operation-table quotient

Recognize complete operation tables before CNF and use the carrier action

`(pi . f)(x, y) = pi(f(pi^-1(x), pi^-1(y)))`.

After proving that every surrounding constraint is invariant under that same
action, retain one canonical forbidden representative per orbit and search
only canonical tables. This targets `iso_*` and `nogen*` classification
families without reproducing a generic e-graph or DPLL(T) loop.

Falsification gate:

1. exhaustive equivalence through carrier size five;
2. exact witness replay for every removed table;
3. at least `20x` fewer emitted literals on degree 6-8 targets;
4. at least `2x` paired parser-inclusive speedup;
5. zero effect when base invariance cannot be proved.

Closest work:

- [Complete Symmetry Breaking for Finite Models](https://ojs.aaai.org/index.php/AAAI/article/view/33217)
- [Satsuma](https://drops.dagstuhl.de/entities/document/10.4230/LIPIcs.SAT.2024.4)
- [Proof-logged orbitopal fixing](https://crcodel.com/research/orbitopal_fixing.pdf)

### M2: Stabilizer-aware forbidden-table MDD/ZDD

Order function-table cells, hash-cons equal forbidden suffix states, and carry
the stabilizer of the fixed prefix. Either propagate directly on the decision
diagram or emit a bounded Tseitin encoding. Unlike ordinary Boolean DAG
sharing, the states summarize families of complete forbidden interpretations.

Falsification gate:

1. compare raw clauses, trie, reduced ordered BDD, and stabilizer MDD;
2. construction time below 5% of baseline solve time;
3. state count below 25% of raw forbidden literal count;
4. exhaustive truth-table equivalence on small instances;
5. reject the mechanism for any variable order that expands the target.

Closest work:

- [ROBDD encodings with generalized arc consistency](https://arxiv.org/abs/1401.5860)
- [Multi-Valued Decision Diagrams](https://www2.eecs.berkeley.edu/Pubs/TechRpts/1990/1671.html)

### M3: EUF-structured bounded variable addition

Run BVA on semantic units before generic CNF: repeated operation-table rows,
argument-equality rectangles, shared negative conjunctions, and repeated
Ackermann products. Score candidates by projected watched-literal and
propagation traffic, not only `variables + clauses`.

Falsification gate:

1. compare blind CNF, generic BVA, and AST-guided BVA;
2. require at least 30% fewer literals;
3. require a statistically significant paired speedup;
4. reject if timeout count, model validation, or proof reconstruction worsens.

Closest work:

- [Automated Reencoding of Boolean Formulas](https://fmv.jku.at/papers/MantheyHeuleBiere-HVC12.pdf)
- [Structured Reencoding](https://arxiv.org/abs/2307.01904)

### M4: Certifying Hall-set propagation

Detect finite term collections whose mandatory disequality graph proves an
all-different constraint. Maintain a reversible maximum matching and derive
conflicts or value removals from Hall sets, with PB-checkable explanations.
This attacks the known proof-complexity wall directly rather than asking CDCL
to rediscover cardinality reasoning from pairwise clauses.

Falsification gate:

1. exact agreement with brute finite search on small carriers;
2. polynomial scaling on synthetic EUF pigeonholes;
3. checked PB explanations for every pruning step;
4. positive complete-corpus total after detector overhead.

Closest work:

- [Regin's matching filter](https://s.aaai.org/Papers/AAAI/1994/AAAI94-055.pdf)
- [Justifying All Differences Using PB Reasoning](https://ojs.aaai.org/index.php/AAAI/article/view/5507)

### M5: Selective cutting-planes escalation

Preserve recognized cardinality inequalities from the SMT AST and move only a
proved pigeonhole or subset-cardinality component to a division-capable
cutting-planes backend. Sending an already flattened generic CNF to a PB solver
does not test this hypothesis.

Falsification gate:

1. compare pairwise CNF, native cardinality, and RoundingSat-style PB search;
2. freeze the structural selector before timing;
3. require both tail coverage and timeout-charged total improvement;
4. reject if generic-instance handoff cost exceeds the converted tail value.

Closest work:

- [Proof systems for pseudo-Boolean solving](https://jakobnordstrom.se/docs/publications/ProofSystemsPBsolving_SAT.pdf)
- [RoundingSat](https://gitlab.com/MIAOresearch/software/roundingsat)
- [From Clauses to Klauses](https://www.cs.cmu.edu/~mheule/publications/knf.pdf)

### M6: Blocked-decomposition theory mining

Use blocked-clause decomposition to isolate a large easy Boolean component,
sample it under a strict budget, group equality atoms by identical signatures,
and validate every candidate backbone or equivalence with congruence closure.
Covered-clause elimination may expose additional gates.

Falsification gate:

1. fixed analysis budget below 2% of baseline time;
2. count only independently validated substitutions;
3. require parser-inclusive paired improvement;
4. include model reconstruction and certificate cost.

Closest work:

- [Blocked Clause Decomposition](https://fmv.jku.at/papers/HeuleBiere-LPAR19.pdf)
- [Covered Clause Elimination](https://fmv.jku.at/papers/HeuleJarvisaloBiere-LPAR10-short.pdf)

### M7: Theory-aware vivification and hyper-binary probing

During clause vivification, propagate an assumed prefix through both watched
clauses and rollback congruence closure. Remove a literal only when the EUF
explanation proves the prefix inconsistent, and cache short implications as
binary clauses. This is intended for long clauses containing repeated
equality paths and conditional congruence diamonds.

Falsification gate:

1. sweep fixed budgets selected by clause length, LBD, and activity;
2. measure removed literals, explanation length, learned LBD, and decisions;
3. include rollback-closure cost;
4. reject unless wall time improves on a frozen target and full corpus.

Closest work:

- [Clause Vivification](https://home.mis.u-picardie.fr/~cli/clauseVivificationPublishedVersion.pdf)
- [Biere preprocessing and inprocessing survey](https://cca.informatik.uni-freiburg.de/biere/talks/Biere-WorKer11-talk.pdf)
- [Fast Congruence Closure](https://www.cs.upc.edu/~roberto/papers/IC06.pdf)

### M8: Validated small-model ladder

Infer independent sort bounds, try canonical domain sizes incrementally, reuse
safe constraints between sizes, and validate every total typed model with an
independent source evaluator. This is a SAT-only front tier and cannot infer
UNSAT from a missed size.

Falsification gate:

1. stratify SAT inputs by independently established minimum model size;
2. solve at least 30% of size-at-most-eight targets;
3. add less than 3% p95 overhead on misses;
4. mutation-test the source model checker.

Closest work:

- [Paradox finite-model techniques](https://fitelson.org/paradox.pdf)
- [Finite Model Finding in SMT](https://cvc4.github.io/papers/cav2013-fmf)

### M9: Sparse Ackermannization plus an activation propagator

Emit only high-value congruence implications eagerly. Handle omitted pairs in
a sparse term-activation propagator when both applications become relevant.
The mechanism is useful only if an interior eager budget dominates both full
Ackermannization and a fully lazy endpoint; otherwise it merely recreates a
mature CDCL(T) design.

Falsification gate:

1. sweep 0%, 25%, 50%, 75%, and 100% eager-pair budgets;
2. report coverage, total clauses, propagator calls, and total time;
3. reject unless one interior point dominates both endpoints;
4. audit against cvc5 and Yices2 source before any novelty claim.

Closest work:

- [IPASIR-UP](https://drops.dagstuhl.de/entities/document/10.4230/LIPIcs.SAT.2023.8)

### M10: Search-aware congruence explanations

Maintain alternative equality explanation paths and choose a learned theory
clause by a weighted objective over length, projected LBD, propagation depth,
and atom activity. The target is a redundant equality graph where the first
union-find explanation is valid but poor for CDCL.

Falsification gate:

1. compare first-path, proof-size-greedy, and LBD-aware explanations;
2. measure maintenance cost and median explanation LBD;
3. require paired runtime improvement, not only shorter clauses;
4. preserve replayable proof provenance.

Closest work:

- [Fast Congruence Closure and Extensions](https://www.cs.upc.edu/~roberto/papers/IC06.pdf)
- [Small Proofs from Congruence Closure](https://ztatlock.net/pubs/2022-fmcad-smallproofs/2022-fmcad-smallproofs.pdf)

### M11: Symmetry-reduced equality cube-and-conquer

Split on canonical equality partitions, disequalities, and operation-table
prefixes rather than raw Boolean literals. Remove isomorphic cubes with a
stabilizer certificate and distribute survivors over WMI.

Falsification gate:

1. compare 1, 8, and 32 workers;
2. report wall time and total CPU time;
3. require at least `4x` wall speedup at no more than `1.5x` CPU;
4. require proof merging or independent checked cube coverage.

Closest work:

- [Cube and Conquer](https://cca.informatik.uni-freiburg.de/papers/HeuleKullmannWieringaBiere-HVC11.pdf)
- [Symmetries for Cube-and-Conquer in Finite Model Finding](https://drops.dagstuhl.de/entities/document/10.4230/LIPIcs.CP.2023.8)

### M12: Composite certificates

Validate SAT with a total typed source-model checker. For UNSAT, compose
symmetry witnesses, VeriPB Hall/cutting-plane steps, FRAT-to-LRAT SAT proofs,
and a small checked SMT translation boundary. Aggressive transformations do
not enter the trusted base merely because they are fast.

Falsification gate:

1. 100% certificate acceptance on every promoted answer;
2. mutation-test rejection of damaged witnesses;
3. median generation overhead below 10%;
4. checking faster than solving on the target corpus.

Closest work:

- [FRAT](https://www.cs.cmu.edu/~mheule/publications/FRAT-TACAS.pdf)
- [Verified LRAT checking](https://www.cs.utexas.edu/~kaufmann/papers/lrat-preprint/paper.pdf)
- [VeriPB](https://veripb.org/)
- [Alethe output in cvc5](https://cvc5.github.io/docs-ci/docs-main/proofs/output_alethe.html)

## Execution Order

The current order is `M1 -> M3 -> M4/M5 -> M7 -> M10`, with `M12` developed
alongside every UNSAT-capable mechanism. `M2` is being tested in parallel
because the raw orbit corpus already supplies a precise construction target.
`M8` remains SAT-only until its source certificate includes expanded
definitions. `M9` is lower novelty and is pursued only if the quotient routes
leave a broad Ackermann tail.

Every behavioral mechanism is default-off and receives a same-binary paired
gate. No combination is timed until its constituent mechanisms individually
pass correctness, target speed, full-corpus total, and coverage gates.

## 2024-2026 Expert Watchlist

This section records newer work by Armin Biere and collaborators that changes
the control experiments or proof obligations. These mechanisms are occupied
prior art; the project may use them, but cannot claim them as its novelty.

### Clausal congruence closure and local simple probing

The 2024 clausal congruence-closure work reconstructs AND, XOR, and ITE gates
from CNF, uses local hyper-binary resolution plus equivalent-literal
substitution, and can solve isomorphic miters before CDCL. Its experiments also
show that this pass and structured BVA are orthogonal. The reported generic
cost was about 4.41% on one competition set, which is too high for an
unconditional euf-viper front-end pass.

Project consequence: add a local HBR/equivalence-sweeping control on frozen
`GRAPH_32` components. Any theory-aware vivification result must beat this
purely clausal control after its full analysis overhead. EUF structure may seed
the candidate binary equivalences, but every substitution remains RUP/DRUP
replayable.

Source:

- [Clausal Congruence Closure](https://cca.informatik.uni-freiburg.de/papers/BiereFazekasFleuryFroleyks-SAT24.pdf)

### Vivification scheduling and clause retention

The 2025 vivification study reports that retaining more clauses during
vivification caused a cumulative slowdown on factoring benchmarks. The key
lesson is not merely to vivify, but to measure scheduling, retained-clause
policy, and interaction with later database reduction.

Project consequence: a theory-aware vivifier receives a strict component
budget and may not automatically protect every strengthened theory clause.
Telemetry must separate clauses removed, clauses shortened, clauses retained,
and their later use in conflict analysis.

Source:

- [Revisiting Clause Vivification](https://cca.informatik.uni-freiburg.de/papers/PollittFleuryBiereSakallahHeuleChenFisseha-POS25.pdf)

### Unlearning by criticality and recent use

`Learn to Unlearn` shows that keeping all clauses hurts both SAT and UNSAT,
periodically deleting nearly everything remains competitive on SAT but harms
UNSAT, and retaining a critical size/LBD tier plus recently used clauses is a
strong simple policy. The paper also documents a real regression caused by
granting strengthened clauses an extra retention chance.

Project consequence: do not infer permanent value from a clause merely because
it came from EUF, Hall, or orbit reasoning. Record a representation-neutral
critical bit and a recent-use bit; evaluate deletion policies separately on
SAT and UNSAT strata without using expected status in runtime routing.

Source:

- [Learn to Unlearn](https://cca.informatik.uni-freiburg.de/papers/GstreinPollittSchidlerFleuryBiere-SAT25.pdf)

### Extended-redundancy incremental inprocessing

The 2025 incremental inprocessing calculus explicitly covers clause additions
based on BVA, BCA, extended resolution, cardinality reasoning, and decision
diagrams. This closes a proof-design gap: a dynamic BVA or MDD mechanism cannot
be justified only as an informal equisatisfiable rewrite when incremental SAT
state is retained.

Project consequence: the first MDD/BVA prototype is static and default-off. A
later dynamic form must log extension-variable introduction and deletion under
an extended-redundancy checker before it can be promoted.

Source:

- [Incremental Inprocessing Rules beyond Resolution](https://cca.informatik.uni-freiburg.de/papers/FazekasPollittFleuryBiere-POS25.pdf)

### Disjoint projected enumeration without blocking clauses

The 2025 TabularAllSAT/AllSMT work combines chronological backtracking with
aggressive implicant shrinking to enumerate disjoint projected regions without
accumulating blocking clauses. This is close prior art for any claim that an
anti-model table automaton is novel merely because it avoids 5,040 explicit
blocking clauses.

Project consequence: compare the canonical forbidden-table search against a
chronological projected-enumeration control. The differentiated hypothesis is
the verified operation-table action, orbit quotient, and typed source
certificate, not blocking-clause avoidance alone.

Source:

- [Disjoint Projected Enumeration for SAT and SMT without Blocking Clauses](https://cca.informatik.uni-freiburg.de/papers/SpallittaSebastianiBiere-AIJ25.pdf)
