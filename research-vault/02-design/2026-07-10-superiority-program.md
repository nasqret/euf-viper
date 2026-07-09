# Program To Beat Z3 And Yices2 On QF_UF

Date: 2026-07-10

Status: active research program. No superiority claim is currently allowed.

## Mission

Build a standalone, sound, certifying Rust solver that has at least the
coverage of Z3 and Yices2 and is faster by both timeout-charged aggregate time
and geometric mean on common solved QF_UF instances.

This is not a request to tune one benchmark table. The result must survive:

- two independent runs of the complete SMT-LIB 2025 QF_UF corpus;
- 2-second, 60-second, and 1,200-second limits;
- Intel and AMD `x86-64-v3` WMI nodes;
- source-family-held-out or newly released QF_UF instances;
- independent SAT/EUF proof checking for UNSAT;
- complete congruence-closure validation for SAT.

An opt-in portfolio that invokes Yices is useful operationally, but it is not a
standalone victory over Yices. Content hashes and benchmark-name lookup are
forbidden as routing features.

## Evidence At Program Start

Promoted candidate SHA-256:

`e262a27d93e63c9073ba721fb6097344ee645fc98ad1134b3dd166f18bc610ab`

Full paired gate `142412` over 7,503 instances:

| Metric | Baseline | Candidate | Change |
| --- | ---: | ---: | ---: |
| Correct | 6,891 | 6,898 | +7 |
| Timeout-charged total | 2,614.91s | 2,599.66s | 1.0059x |
| Common-solve total | 1,380.53s | 1,369.81s | 1.0078x |
| Geometric speed | - | - | 1.0220x |
| Pairwise wins | 2,611 | 4,279 | candidate +1,668 |
| Wrong/errors | 0 | 0 | unchanged |

The one apparent baseline-only case was a timeout boundary (`1.9998s` versus
`2.0026s`). Seven-repeat replications removed it:

- AMD job `142478`: coverage `3/9 -> 9/9`, all-total `3.506x`, common-total
  `1.541x`, geometric `1.507x`.
- Intel job `142479`: coverage `1/9 -> 8/9`, all-total `1.321x`, no
  baseline-only solve.

Fresh comparator campaign `142480`/`142481`/`142482` completed all 30,012
observations with zero wrong answers, disagreements, execution errors, or
failed shards. Coverage was euf-viper 6,874, Z3 7,123, cvc5 6,831, and Yices2
7,420. On common solves euf-viper is `1.111x` faster than Z3 by total and
`2.035x` geometrically, but it is `3.584x` slower than Yices2 by total and
`2.407x` slower geometrically.

## Victory Levels

### V0: Valid candidate

- zero wrong answers and zero execution errors;
- candidate coverage is no lower than its immediate baseline;
- all-total, common-total, and geometric speed ratios are each at least 1.00;
- exact binary SHA and raw per-instance rows are archived.

### V1: Fast-head leader

- best median and geometric mean against Z3, cvc5, and Yices2 at two seconds;
- no material non-QG regression;
- explicit statement that coverage may still be lower.

### V2: Coverage parity

- at least 7,500/7,503 at 1,200 seconds to match Z3;
- 7,503/7,503 to match Yices2;
- no comparator fallback.

### V3: Standalone superiority

- coverage at least equal to Z3 and Yices2 at every declared timeout;
- at least 1.05x lower timeout-charged aggregate time in two full runs;
- geometric speed ratio at least 1.02x in both runs;
- held-out result has the same direction;
- proof and model validators report no discrepancy.

### V4: Certifying superiority

- V3 plus independent reconstruction of the base Tseitin CNF;
- checked proof for every UNSAT result, including finite-domain, symmetry,
  counting, and theory lemmas;
- proof overhead is measured separately and end to end.

## Operating Rules

Every hypothesis receives:

1. A structural signature that can be computed from the input.
2. A soundness argument and rollback control.
3. A default-off runtime flag in the experimental binary.
4. A same-binary A/B whenever code layout permits.
5. Unit, property, differential, and canary tests before WMI.
6. A targeted repeated gate on both CPU architectures.
7. A hot-400 gate and a hard-tail gate.
8. A full 7,503-instance paired gate before default promotion.
9. A journal entry even when rejected.

Local timing is a smoke test, not promotion evidence. A smaller CNF, fewer SAT
calls, or a faster selected family is not enough unless end-to-end time and
coverage pass.

## Wave 0: Measurement And Reproducibility

### 0.1 Exact binary identity

- Continue using explicit `x86-64-v3`, not host `native`, across mixed WMI
  nodes.
- Record SHA-256 in preparation output, campaign metadata, and result note.
- Refuse long campaigns when a prebuilt binary hash is absent or mismatched.

### 0.2 Opportunity analyzer

The committed `scripts/bench/analyze_ab_opportunities.py` generates:

- baseline-only and candidate-only sets;
- largest absolute speedups and slowdowns;
- timeout-adjacent cases;
- per-family aggregate metrics;
- a deduplicated follow-up experiment selection.

Extend it later with source-family holdouts, structural features, SAT-call
counts, clause counts, finite-domain signatures, and memory counters.

### 0.3 Resume correctness

Long campaigns must support rerunning exactly one named solver while preserving
all comparator rows. Retry-by-result and retry-by-solver are separate sets;
their union must be explicit in metadata.

## Wave 1: Remove Head Overhead

These experiments are narrow, reversible, and should precede architectural
changes.

### 1.1 Direct-root CNF

Use the existing direct assertion encoder for the initial solve instead of
introducing a Tseitin variable for every top-level assertion.

- Expected mechanism: fewer variables, clauses, watches, allocations, and FFI
  insertions.
- Signature: all instances; largest relative gain on small/cold problems.
- Soundness: differential SAT tests over nested `And`, `Or`, `Not`, `Iff`, and
  `Ite`; keep the old encoder as an oracle.
- Gate: synthetic Boolean enumeration, official smoke, hot-400, full corpus.

### 1.2 Streaming semantic parser

Replace `tokenize -> full S-expression tree -> semantic traversal` with a
borrowed byte scanner that consumes one top-level command at a time and copies
only unique symbols.

- Preserve quoted symbols, comments, annotations, and unsupported-syntax
  diagnostics exactly.
- Differentially parse every corpus file with old and new frontends.
- Measure parse time, allocations, peak RSS, and total time separately.

### 1.3 Compact terms

Store each argument slice once. Use `u32` term IDs, fingerprint buckets, exact
collision checks, and an arena or small-inline representation.

- Never trust fingerprints without exact equality.
- Compare term counts and serialized semantic IR for every corpus input.

### 1.4 Packed CNF and direct backend loading

Replace `Vec<Vec<i32>>` plus per-backend clause copies with flat literals and
offsets. Reserve variables once and avoid querying model values for variables
that cannot map to theory atoms.

- Measure allocations, bytes copied, FFI calls, and backend load time.
- Keep DIMACS export byte-equivalent modulo legal clause ordering.

### 1.5 Code layout and profile guidance

- Train PGO on family-grouped data disjoint from the final evaluation slice.
- Test LLVM PGO, BOLT-style post-link layout when available, `panic=abort`, and
  cold separation of certificate/CLI error paths.
- Keep `x86-64-v3`; never reintroduce the AVX-512 `SIGILL` failure.
- Promote only end-to-end improvements, not instruction-count reductions.

## Wave 2: Change The Finite-Tail Proof System

This is the highest-upside research front. Finite QF_UF tables expose CSP and
counting structure that ordinary resolution handles poorly.

### 2.1 Read-only finite-structure recognizer

Before changing solving, report:

- exhaustively ranged terms and their domains;
- verified domain-distinct constants;
- unconditional and guarded disequality graphs;
- candidate `AllDifferent` sets;
- Hall deficits and matching statistics;
- closed function tables and arities;
- verified permutation group generators and estimated orbit size;
- branch-overlap and equational-diamond metrics.

The recognizer must never affect answers. Its output creates structural target
manifests and prevents benchmark-name routing.

### 2.2 Native `AllDifferent` and Hall propagation

Lift complete range constraints into finite-domain variables. Maintain a
bipartite variable/value graph and use matching-based propagation.

- Conflict condition: a witnessed set `S` with `|N(S)| < |S|`.
- Propagation condition: Hall-tight sets remove values from outside variables.
- Every conflict or propagation needs a clause or pseudo-Boolean explanation
  that can be independently replayed.
- Keep full congruence-closure model validation as a second oracle.

This attacks the named pigeonhole/proof-complexity wall directly rather than
changing the spelling of pairwise at-most-one clauses.

### 2.3 Pseudo-Boolean backend experiment

Compare:

- current pairwise one-hot CNF;
- commander, totalizer, cardinality-network, and logarithmic encodings;
- native PB constraints with checked cutting-planes proofs;
- hybrid CNF for Boolean structure plus PB for range/`AllDifferent` structure.

Do not infer success from clause count. Require hard-tail coverage and total
time. Preserve a proof path before promotion.

### 2.4 Complete multi-table orbit canonization

The current verified generators and lex leaders do not guarantee a compact
canonical representative for every multi-function structure. Build:

- diagonal-first and first-occurrence/value-precedence constraints;
- compact canonizing permutation sets;
- stabilizer chains as constants/table cells become fixed;
- exhaustive small-domain orbit enumeration to prove one representative is
  retained.

All permutations must be verified automorphisms of the complete formula,
including predicates and distinguished constants.

### 2.5 Symmetry-aware cube and conquer

For the long finite tail:

- cube on canonical table cells or Hall-critical assignments;
- reject isomorphic cubes only with explicit permutation witnesses;
- balance cubes using measured propagation/conflict slopes;
- aggregate cube proofs for UNSAT.

This is a coverage mechanism for 60/1,200-second runs, not a substitute for
single-core two-second speed.

## Wave 3: General QF_UF Theory Engine

### 3.1 Model-directed Ackermann cuts

Do not materialize all possible congruence clauses before each refinement.
Bucket applications by current argument classes and generate only violated
function or predicate implications.

- Each cut is an EUF theorem.
- A bounded generator may abstain but may not validate SAT.
- Compare cut count, SAT calls, clause width, and total time.

### 3.2 Worklist congruence closure and proof forest

Replace repeated whole-graph signature scans and per-explanation BFS
allocations with:

- precomputed application use-lists;
- generation-stamped scratch arrays;
- rollbackable union-find;
- a proof forest with small, replayable explanations.

Initially dual-run the old closure and assert identical class partitions,
conflicts, and explanations.

### 3.3 Conditional/colored e-graph

Generalize positive-`or` branch intersection to nested Boolean structure.
Maintain guarded congruence colors and emit only:

- equalities valid in every branch;
- guarded branch consequences;
- definitional equality atoms needed for useful lemmas.

No branch fact may enter the global e-graph without a proof that it holds in
all relevant colors.

### 3.4 IPASIR-UP external EUF propagator

The major general-tail bet is a rollback e-graph attached to CaDiCaL's trail:

1. Observe only SAT variables mapped to equality/predicate atoms.
2. Receive assignment and backtrack notifications.
3. Detect partial-trail EUF conflicts.
4. Return delayed, independently replayed explanations.
5. Add equality propagation and theory-directed phases only after conflict-only
   mode is validated.

Stages:

- M0: complete-model callback reproduces current validator.
- M1: partial-trail conflict detection, no theory propagation.
- M2: equality and predicate propagation.
- M3: theory-directed decisions and phase hints.

Require fewer full SAT rounds and at least 1.10x on multi-round targets before
a full gate. Keep the complete-model validator permanently as a safety check.

## Wave 4: SAT Engineering Reconsidered

### 4.1 CaDiCaL pre/inprocessing matrix

The current lazy path starts from Plain mode. Test controlled arms for:

- elimination and equivalent-literal substitution;
- probing and transitive reduction;
- vivification and vivification instantiation;
- clausal congruence closure;
- equivalence sweeping and definition mining;
- factorization/BVA;
- SAT-oriented walk, target phases, rephasing, and stabilization.

Test one family at a time, then combinations. Reject preprocessing that makes a
smaller CNF but does not improve end-to-end time.

### 4.2 Preserve or deliberately discard SAT state

Compare:

- current fresh Kissat -> fresh dynamic Kissat -> fresh CaDiCaL handoff;
- CaDiCaL from the first solve with retained learned state;
- an intentional hard restart into a fresh CaDiCaL instance.

Persistence is a hypothesis, not an assumption. Hard restarts can help.

### 4.3 Clausal congruence closure before flattening

Biere et al. recover AND/XOR/ITE gates from CNF and run congruence closure to
completion. We already own the source Boolean and term DAG, so first test the
cheaper direction:

- structurally hash Boolean subterms before Tseitin encoding;
- perform equivalent-literal substitution on the DAG;
- retain gate metadata for later inprocessing;
- rerun simplification when learned units expose new equivalences.

Do not repeat unrestricted HBR, tree look-ahead, simple probing, or blocked
clause decomposition without a new structural restriction; the modern paper
documents why those older attempts needed limits or failed.

## Wave 5: Portfolio Without Self-Deception

An internal portfolio may race or schedule independently implemented engines,
but benchmark-specific lookup is forbidden.

Allowed features:

- term/application/equality counts;
- Boolean depth and connective histogram;
- finite-domain and table signatures;
- congruence graph fill/separator metrics;
- short online probe data such as conflicts, propagations, invalid models, and
  learned-theory-clause slope.

Validation:

- group by source family and source hash lineage;
- nested train/validation splits;
- a final untouched source-family holdout;
- report launcher overhead and geometric as well as aggregate performance.

The external Yices portfolio stays opt-in and is never counted as standalone
superiority.

## Wave 6: Proofs And Trust

### 6.1 Base CNF reconstruction

Independently reconstruct the Tseitin CNF from SMT-LIB and compare it with the
solver-emitted DIMACS. This removes the largest remaining certificate-v1 trust
assumption.

### 6.2 Theory and symmetry replay

Extend the checker to replay:

- transitivity and congruence clauses;
- finite-domain range/channeling clauses;
- symmetry automorphism witnesses and canonical constraints;
- Hall/PB explanations;
- conditional e-graph lemmas.

### 6.3 LRAT/FRAT path

Evaluate native LRAT or FRAT from the production SAT backend. Measure solve,
proof write, proof check, and total pipeline time separately.

## Experiment Ladder

1. Compile and hash exact control/candidate binaries.
2. Run unit, property, parser differential, and SAT/UNSAT canaries.
3. Run structural target with at least five or seven repeats.
4. Repeat target gate on AMD and Intel WMI nodes.
5. Run stable hot-400 with three repeats.
6. Run finite hard-tail and non-finite Goel manifests.
7. Run full paired 7,503 corpus with strict merge.
8. Run fresh four-solver 2-second comparison.
9. Rerun euf-viper at 60 and 1,200 seconds while preserving comparator rows.
10. Run an independent repeat and held-out evaluation.

Promotion requires no wrong answers, no execution errors, no coverage loss,
and all three full-corpus speed ratios at least 1.00. A large target gain can
justify a structural route, but the route must still pass the complete gate.

## Ranked Immediate Queue

| Rank | Experiment | Cost | Upside | Current action |
| ---: | --- | --- | --- | --- |
| 1 | Direct-root CNF | Low | Head speed | Implementing same-binary A/B control |
| 2 | Fresh four-solver two-second run | Medium | Truth baseline | Completed; Z3 tail and Yices head/tail gaps quantified |
| 3 | Exact-solver resume semantics | Low | Reproducibility | Fixing retry controls |
| 4 | CaDiCaL pre/inprocessing matrix | Low | Tail speed | Prepare after comparator run |
| 5 | Finite recognizer | Medium | Enables S-tier work | Next implementation wave |
| 6 | Native Hall/`AllDifferent` | High | Finite coverage | Primary research bet |
| 7 | Complete table canonization | High | Finite speed/coverage | Parallel research bet |
| 8 | Model-directed cuts | Medium | General tail | Implement after direct-root gate |
| 9 | Streaming parser/compact terms | Medium | 2x head target | Profile-guided implementation |
| 10 | IPASIR-UP rollback e-graph | Very high | General coverage | Staged prototype after recognizer |

## Literature Watchlist

- Biere et al., Clausal Congruence Closure, SAT 2024:
  https://doi.org/10.4230/LIPIcs.SAT.2024.6
- Biere, Jarvisalo, and Kiesl, Preprocessing in SAT Solving:
  https://fmv.jku.at/papers/BiereJarvisaloKiesl-SAT-Handbook-2021-Preprocessing-Chapter-Manuscript.pdf
- Biere et al., Detecting Cardinality Constraints in CNF:
  https://fmv.jku.at/papers/BiereLeBerreLoncaManthey-SAT14.pdf
- Fazekas et al., IPASIR-UP and user propagators:
  https://cca.informatik.uni-freiburg.de/papers/FazekasNiemetzPreinerKirchwegerSzeiderBiere-JAIR24.pdf
- Dutertre, Yices 2 architecture and QF_UF symmetry:
  https://yices.csl.sri.com/papers/cav2014.pdf
- Deharbe et al., Exploiting Symmetry in SMT Problems:
  https://doi.org/10.1007/978-3-642-22438-6_18
- Claessen and Sorensson, New Techniques that Improve MACE-style Finite Model
  Finding / Paradox:
  https://fitelson.org/paradox.pdf
- Regin, matching-based `AllDifferent` propagation:
  https://m.aaai.org/Library/AAAI/1994/aaai94-055.php
- Complete symmetry breaking for finite models, AAAI 2025:
  https://ojs.aaai.org/index.php/AAAI/article/view/33217
- Colored e-graphs:
  https://arxiv.org/abs/2305.19203
- Goel et al., partial Ackermannization:
  https://disi.unitn.it/rseba/papers/lpar06_ack.pdf
- Flatt et al., Small Proofs from Congruence Closure:
  https://arxiv.org/abs/2209.03398
- Symmetry-aware finite-model cube and conquer, CP 2023:
  https://doi.org/10.4230/LIPIcs.CP.2023.8

## Explicit Non-Goals

- No claim based only on median latency.
- No claim based on a Yices-dependent fallback.
- No content-hash answer cache or benchmark-name router.
- No promotion from a synthetic or selected-family gate.
- No acceptance of SAT without complete model validation.
- No acceptance of a new UNSAT rule without a replay or proof plan.
- No local heavy campaign when WMI can run it reproducibly.
