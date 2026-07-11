# Unorthodox Systems Paths For QF_UF Superiority

Date: 2026-07-11

Status: research design and prior-art audit. No novelty or superiority claim is
currently allowed.

Scope: systems-level and hardware-conscious approaches that do not reproduce
the conventional SAT plus incremental e-graph architecture of Z3 or Yices2.

## Decision

The two highest-value experiments are:

1. **Bit-sliced quotient swarm**: search batches of finite interpretations
   directly, using SIMD masks, table evaluation, Hall filtering, and verified
   orbit-canonical cubes. This is the best opportunity to beat Yices2 on the
   dominant QG and closed-table population rather than merely improve the
   current solver relative to Z3.
2. **Staged formula machine**: turn each static term and Boolean graph into a
   compact, formula-specific execution schedule assembled from verified native
   stencils. This is the best single-core opportunity to remove enough generic
   dispatch, hashing, allocation, and branch overhead to challenge Yices2 on
   the broad easy head.

The leading parallel-tail experiment is a **semantic proof-space crossbar**:
independent proof systems exchange checked EUF lemmas rather than copying raw
SAT clauses. It ranks third overall because a multicore wall-clock win is not a
sequential-track win and ordinary portfolio racing is already well known.

Persistent forks, perfect hashing, and GPU closure are supporting mechanisms,
not primary research claims. They survive only if their own end-to-end gates
pass.

## Why The Bar Is Yices2

The exact 60-second campaign over 7,503 formulas gives the current scale of the
problem:

- euf-viper solves 7,478 and Yices2 solves 7,500;
- on 7,475 common solves, euf-viper has only `0.2290x` Yices2's aggregate
  speed and `0.4110x` its geometric speed;
- euf-viper wins only 462 common cases, while Yices2 wins 7,013;
- the four-solver oracle chooses Yices2 on 6,950 formulas, euf-viper on 437,
  Z3 on 85, and cvc5 on 31.

The raw evidence is in
[`qf-uf-corpus-143248-analysis.json`](../../results/wmi/four-solver-60s-143248/qf-uf-corpus-143248-analysis.json)
and the campaign summary is in
[`2026-07-10-pgo-and-long-timeout.md`](../06-results/2026-07-10-pgo-and-long-timeout.md).
This is not a narrow 5% optimization problem. A successful architecture must
remove roughly a factor of two from broad common-case latency and eliminate a
small but expensive hard tail.

The structural audit identifies four immediate populations:

| Population | Size | Opportunity |
| --- | ---: | --- |
| Domain-7, closed table | 431 | Includes all ten 60-second QG timeouts and most of the measured Z3-tail deficit |
| Exact one-table subset | 261 | Clean first gate for direct finite-interpretation machinery |
| Large non-table equality graph | 39 | Includes all twelve large Goel timeouts and nearby controls |
| Very large Boolean syntax inside the closed-table set | 174 | Candidate for staged Boolean execution and DAG compression |

The QG family contains 6,396 of 7,503 corpus formulas. Beating Yices2 there is
the only plausible route to an overall timing lead. A mechanism that converts
two tail timeouts but leaves QG head time unchanged can beat Z3 on a selected
slice and still be irrelevant to the actual objective.

## Novelty Standard

"Unexpected" is not the same as novel. Every result must be labeled with one
of these levels until a systematic literature and source audit supports a
stronger statement:

1. **Known substrate**: a published technique applied without a new decision
   procedure, such as forkserver snapshots, perfect hashing, GPU graph kernels,
   or a standard SAT portfolio.
2. **New engineering combination**: known components connected in a QF_UF-
   specific way, with a measurable interaction not present in either component
   alone.
3. **Algorithmic novelty hypothesis**: a new state space, inference rule,
   proof exchange protocol, or generated evaluator. This may become a paper
   claim only after a formal prior-art review and ablation.
4. **Validated novelty claim**: the algorithm is precisely specified, adjacent
   work is distinguished, independent experts have reviewed the comparison,
   and artifacts reproduce the claimed advantage.

Absolute novelty cannot be guaranteed by an implementation sprint. The
campaign can, however, prevent false novelty claims and produce evidence for a
defensible one.

### Adjacent Work That Does Not Count As Our Novelty

- Yices2 already uses a compact integer-indexed term representation, parent
  vectors, Boolean-aware congruence classes, lazy explanations, equality
  learning, and QF_UF symmetry breaking. Recreating these is not a distinct
  architecture. See [The Nuts and Bolts of Yices](https://ceur-ws.org/Vol-1617/invited1.pdf)
  and [Yices 2.2](https://yices.csl.sri.com/papers/cav2014.pdf).
- SAT portfolio diversification and learned-clause exchange are established by
  ManySAT and HordeSat. See
  [HordeSat](https://arxiv.org/abs/1505.03340).
- Fast process snapshotting and forkserver-style execution are established in
  fuzzing and systems work. See
  [target-embedded snapshotting](https://www.usenix.org/conference/usenixsecurity23/presentation/stone).
- Bitwise `AllDifferent` filtering is established, including a reported gain
  over conventional GAC, and GPU `AllDifferent` propagation has been studied.
  See [AllDiffbit](https://www.ijcai.org/proceedings/2023/221) and
  [GPU constraint propagation](https://bioinf.dimi.uniud.it/publication/11390-1270025/).
- Compiling a declarative problem into specialized native code is established
  by systems such as
  [Souffle](https://souffle-lang.github.io/pdf/cav16.pdf), and synthesis of
  domain-specific CNF encoders has also been studied
  [for bit vectors](https://people.csail.mit.edu/asolar/papers/Inala0S16.pdf).
- Minimal and bucketed perfect hashing are static-data techniques, not new
  reasoning algorithms. Recent work explicitly targets cache-line-sized static
  buckets: [non-minimal k-perfect hashing](https://arxiv.org/abs/2607.07257).

Our potential novelty lies in the QF_UF-specific algorithms described below,
not in these substrates.

## Campaign Contract

### Correctness Before Timing

The Boolean-as-data soundness defect documented in
[`2026-07-10-bool-as-data-unsoundness.md`](../06-results/2026-07-10-bool-as-data-unsoundness.md)
must be repaired before any candidate is eligible for promotion. Experimental
engines may be prototyped behind a shadow or abstaining interface, but their
answers do not count until:

- every Boolean-valued term used as data has a total Boolean interpretation;
- `DontCare` SAT values cannot silently remove theory facts;
- SAT models pass a complete, independent EUF validator;
- every new UNSAT inference has a replayable witness or a checked clause;
- unsupported or uncertain structural recognition causes abstention and a
  sound fallback.

### Two Separate Performance Tracks

1. **Sequential track**: one hardware thread, cold process, startup and parsing
   included. This is the primary comparison with Z3 and Yices2.
2. **Parallel track**: fixed 4-core and optional GPU budgets, wall time, total
   CPU time, energy, and peak proportional-set size reported. A parallel result
   cannot be presented as a sequential victory.

Warm daemons, corpus-wide batching, and persistent caches may be reported as a
production-throughput track only when Z3 and Yices2 receive an equivalent
long-lived API harness. They do not count in the cold-process headline.

### Promotion Gate

A default mechanism must satisfy all of the following:

- zero wrong answers, validator disagreements, crashes, or execution errors;
- no coverage loss at 2, 60, or 1,200 seconds;
- target-family common-total and geometric ratios above `1.10x` versus the
  immediate euf-viper baseline on both Intel and AMD WMI nodes;
- target-family coverage at least equal to pinned Yices2 and target-family
  common-total speed at least `1.05x` better than Yices2;
- sample-40, hot-400, hard-tail, and complete 7,503-formula gates;
- complete-corpus timeout-charged speed at least `1.05x` and geometric speed
  at least `1.02x` versus both Z3 and Yices2 in two independent runs;
- the same direction on a source-family-held-out or newly released set;
- exact source revision, binary SHA-256, machine identity, raw rows, and proof
  or model artifacts archived.

A target gain that does not beat Yices2 is useful diagnostic evidence, not a
winning architecture.

## Ranked Mechanisms

## 1. Bit-Sliced Quotient Swarm

### Thesis

For a verified finite QF_UF subproblem, do not encode equality classes and do
not maintain an e-graph. Search interpretations directly. One lane represents
a partial finite structure; a machine word or SIMD vector represents many
structures. Function applications become direct table reads, equality becomes
lane-wise label comparison, and Boolean connectives become bitwise operations
over lane masks.

For domain size `d <= 8`, each term value fits in a byte. A 256-bit AVX2 vector
therefore evaluates 32 candidate values at once, while a bit-sliced Boolean
layer can evaluate 64 or 256 candidate structures per operation. Binary table
arguments map to at most `d^2 <= 64` cells. Hall filters and orbit-canonical
cubes prune whole lane groups before SAT-style branching.

The complete solver is a search over finite interpretations:

1. The recognizer proves the active finite domains and closed tables.
2. A cube generator creates disjoint partial interpretations.
3. A structure-of-arrays kernel evaluates term tables and the Boolean DAG for
   a batch of cubes.
4. Bitwise domain filtering, `AllDifferent`, and verified automorphisms reject
   lane groups.
5. SAT returns a concrete interpretation checked by the scalar EUF validator.
6. UNSAT returns a complete disjoint cube cover with local rejection witnesses.

This is not vectorized congruence closure. It replaces the congruence-closure
state space with quotient-model search.

### Novelty Classification

**Algorithmic novelty hypothesis.** Bit-parallel constraint filtering and
finite-model search are known separately. The candidate contribution is a
lane-parallel quotient-model procedure for QF_UF with a proof-producing cube
cover, formula-level Boolean mask evaluation, and verified symmetry reduction.

### Target Family

- First: exact one-table, domain-7 population, 261 formulas.
- Second: all 431 domain-7 closed-table formulas.
- Third: the 6,396-formula QG family when finite recognition is complete.
- Avoid initially: large non-finite Goel equality graphs.

### Hardware And Memory Model

- Baseline ISA: `x86-64-v3`, AVX2, BMI1/BMI2, no AVX-512 dependency.
- Data: byte-valued terms, 64-bit lane masks, structure-of-arrays table cells,
  fixed-size domain masks, cache-line-aligned batches.
- Per-core mutable state should remain in L2; immutable term and Boolean
  schedules may be shared read-only.
- Optional one batch worker per physical core; no cross-socket execution in
  the first gate.
- GPU is deliberately excluded from M1 so transfer and launch effects do not
  obscure the algorithm.

### Soundness Boundary

- Finite recognition must prove, rather than guess, the range of every value
  represented by a byte.
- Cube generation must partition the complete interpretation space. Orbit
  rejection requires an explicit verified automorphism.
- Every SIMD kernel has a scalar reference implementation. Exhaustive tests
  cover all structures for very small domains; randomized differential tests
  cover domain sizes through eight.
- SIMD masks are only pruning accelerators. A lane may be retained
  unnecessarily, but a lane may be removed only with a replayable witness.
- A SAT interpretation is reconstructed in SMT sorts and checked independently.
- If the proof-cover implementation is incomplete, the engine may return SAT
  or `unknown`, never UNSAT.

### Implementation Effort

Very high, but naturally staged:

- M0, 3-5 engineer-days: shadow recognizer, scalar finite interpreter, and
  opportunity telemetry.
- M1, 7-10 days: AVX2 Boolean and table evaluator with scalar differential
  oracle; SAT-only or abstaining mode.
- M2, 10-15 days: complete cube scheduler, Hall filtering, orbit witnesses,
  and UNSAT cover checker.
- M3, 5-10 days: proof compression, multithreading, and full campaign wiring.

### Observability

Record per formula:

- recognized domains, table arities, table cells, and proof of range closure;
- cubes created, completed, split, orbit-rejected, Hall-rejected, and Boolean-
  rejected;
- active lanes per batch, lane occupancy, batches per second, and tail-lane
  waste;
- scalar versus SIMD evaluations, cycles per table cell, branches, L1/L2/LLC
  misses, and vector instructions;
- SAT model-check time, UNSAT cover size, witness-check time, peak RSS, and
  energy;
- direct pairwise result and time against pinned Yices2, not only euf-viper.

### Kill Gate

Stop or demote the mechanism if any gate fails:

1. M0 finds fewer than 200 official formulas with proved closed finite
   interpretations or finds that the one-table target is not structurally
   uniform enough for shared kernels.
2. M1 achieves less than `8x` kernel throughput over the scalar reference,
   less than 70% median lane occupancy, or spends more than 20% of total time
   constructing batches.
3. On the exact one-table 261, three alternating 60-second repetitions on both
   CPU classes do not convert at least one current timeout and improve all
   euf-viper timing ratios by at least `1.50x`.
4. On the 431-case domain-7 gate, the engine does not match Yices2 coverage and
   beat Yices2 common-total and geometric time by at least `1.05x`.
5. Any unexplained scalar/SIMD mismatch permanently blocks UNSAT support.

### Why It Might Beat Yices2

Yices2's implementation is an exceptionally optimized but generic scalar
DPLL(T) engine with integer-indexed terms, parent vectors, and QF_UF
preprocessing. The quotient swarm pays none of the per-assignment class merge,
parent-list traversal, signature hashing, or SAT/theory callback costs on its
recognized family. It evaluates many complete finite structures with direct
table semantics in each instruction. This is a qualitatively different source
of speed, large enough in principle to overcome Yices2 rather than just Z3.

## 2. Staged Formula Machine

### Thesis

Treat an SMT-LIB instance as a program with a static control and dataflow graph.
After parsing, assemble a formula-specific native evaluator from precompiled,
verified instruction stencils. Patch term IDs, offsets, literal polarities, and
successor addresses into those stencils; do not invoke LLVM and do not run a
general JIT optimizer.

The generated schedule fuses:

- Boolean DAG evaluation and short-circuit masks;
- static application use lists and congruence checks;
- theory-atom extraction from a SAT assignment;
- violated-Ackermann-clause discovery;
- model reconstruction and validation;
- optional finite-table and partition microkernels.

Large repeated Boolean regions use compact bytecode rather than unrolled native
code to stay within the instruction cache. Small hot regions become straight-
line stencils with no hash-table lookup or variant dispatch. A static cost model
chooses native stencil, vector bytecode, or ordinary Rust reference execution.

### Novelty Classification

**New engineering combination**, with an **algorithmic novelty hypothesis**
only for fused generated fixpoint schedules. Runtime specialization, stencil
JITs, and generated analyzers are known. A publishable claim would require
showing that the generated EUF schedule changes the asymptotic or proof-search
behavior, not merely that native code is faster than an interpreter.

### Target Family

- Broad one-shot head, especially the 6,396 QG formulas where Yices2's low
  constant factors currently dominate.
- The 174 closed-table formulas with at least 80,000 parentheses, using compact
  Boolean bytecode and exact DAG sharing rather than full unrolling.
- Large Goel formulas only when telemetry shows multiple complete-model or
  refinement passes over the same static graph.
- Do not activate on tiny formulas unless patch cost is below predicted savings.

### Hardware And Memory Model

- `x86-64-v3` native stencils with an AArch64 reference path deferred.
- Dual-mapped or write-then-execute pages under strict W^X; no writable and
  executable mapping at the same time.
- Per-instance native code cap of 32 KiB initially, hard cap 64 KiB.
- Immutable formula data are packed by use order; mutable representatives,
  assignments, and stamps are separate dense arrays.
- Generated code must remain position independent so a forked child can share
  code pages.

### Soundness Boundary

- The generated schedule implements no trusted new inference. It must emit the
  same partition, violated lemmas, and model result as a small scalar reference
  evaluator.
- Stencil generation is deterministic and serializable. Every generated block
  has a typed manifest of inputs, outputs, clobbers, and memory ranges.
- Differential execution compares generated and reference state at each
  fixpoint during development.
- Random term graphs, all Boolean connective combinations, adversarial hash
  collisions, Boolean-as-data, and partial SAT models are mandatory tests.
- A generated-code fault, unsupported platform, code-size overflow, or failed
  self-check causes reference fallback, never answer acceptance.

### Implementation Effort

High:

- M0, 3-4 days: event trace and cost model from the current reference path.
- M1, 5-8 days: safe microcode interpreter and serialized formula schedule.
- M2, 7-12 days: native stencil assembler for Boolean evaluation and theory
  atom projection.
- M3, 7-12 days: fused congruence/Ackermann schedule and code-size router.
- M4, 3-5 days: proof-mode replay, WMI perf counters, and hardening.

### Observability

- schedule-build, patch, page-protection, and instruction-cache flush time;
- generated bytes, basic blocks, bytecode instructions, and native invocations;
- reference versus generated cycles per term, atom, model, and refinement;
- branch misses, indirect branches, I-cache misses, D-cache misses, and front-
  end stalls;
- number of times each generated schedule is reused and exact amortization;
- router predicted savings versus realized end-to-end savings;
- cold-process pairwise timing against Yices2.

### Kill Gate

1. Shadow telemetry must show that at least 70% of total corpus CPU time reaches
   a static evaluator region reusable enough to amortize specialization.
2. Formula schedule creation plus patching must be below 50 microseconds at the
   median and below 5% of end-to-end time at the 95th percentile of routed
   formulas.
3. Generated Boolean/term execution must be at least `2.5x` faster than the
   reference microkernel without increasing total instructions elsewhere.
4. The QG target must improve end-to-end common-total and geometric time by at
   least `1.30x` over euf-viper and come within `1.10x` of Yices2 before M3.
5. Final promotion requires beating Yices2 by `1.05x` on the routed held-out
   set. If the mechanism only reduces euf-viper's gap, it remains an internal
   optimization and loses rank as a primary research direction.
6. More than 1% router mispredictions with net slowdown or any generated/
   reference semantic mismatch kills default routing.

### Why It Might Beat Yices2

Yices2 already has compact data structures, so another generic Rust hash-table
cleanup is unlikely to win. Formula staging exploits information a reusable
solver deliberately leaves dynamic: exact term topology, exact parent uses,
literal polarity, fixed Boolean DAG shape, and the subset of fields required by
this one input. If patching is cheap, branch elimination and fused memory passes
can attack Yices2's constant-factor advantage across the entire head.

## 3. Semantic Proof-Space Crossbar And Multi-SAT Race

### Thesis

The only multi-SAT cooperative race worth building here must race genuinely
different proof systems and exchange only facts meaningful in the original
QF_UF problem. Each engine shares a common stable namespace for source Boolean
atoms and equalities while retaining its own private encoding.

Candidate workers are:

- eager Ackermann/transitivity CNF with Kissat;
- lazy base CNF with model-directed EUF cuts in CaDiCaL;
- the finite quotient swarm;
- an offline partition-machine worker for small components;
- a cube worker for symmetry-reduced finite tails.

The broker accepts only replayable semantic messages:

- source-level Boolean units or clauses;
- congruence and transitivity lemmas with antecedent equality paths;
- Hall conflicts with variable/value witnesses;
- orbit-pruned cubes with automorphism witnesses;
- fully proved residual UNSAT cubes.

A receiver verifies a message, lowers it to its own variables, and records
whether it was useful. Raw private CNF clauses are not exchanged across
incompatible encodings.

### Novelty Classification

**Algorithmic novelty hypothesis** for typed, proof-carrying lemma exchange
across different EUF proof spaces. The process race, diversification, ring
buffers, and ordinary same-CNF clause sharing are known portfolio techniques.

### Target Family

- The 39 large non-table equality-graph formulas and all twelve Goel timeouts.
- Mixed finite formulas where eager SAT and direct model search have
  complementary behavior.
- The 25-formula 60-second hard tail.
- Not the cold easy head unless a sub-millisecond online probe predicts a race.

### Hardware And Memory Model

- Primary evaluation: four physical cores on one socket, one worker per core.
- Shared read-only parsed IR and source atom table; private mutable solver heaps.
- Single-producer/single-consumer ring buffers per worker pair or a bounded
  broker queue; fixed message budget to prevent cache and NUMA pollution.
- Optional `fork` after immutable setup, but threads are allowed when backend
  APIs and allocators are safe.
- Report both wall time and summed CPU time. Pin workers and disable SMT sibling
  placement for the first campaign.

### Soundness Boundary

- No imported lemma affects search until an independent checker validates it
  in the source-level namespace.
- A malformed, stale, or unmappable lemma is dropped and counted.
- SAT acceptance always uses a complete independent model validator.
- UNSAT requires one complete worker proof or a checked composition of a
  disjoint cube cover; "all workers failed" is not UNSAT.
- Cancellation is asynchronous but cannot truncate the winner's proof or model
  artifact.
- Deterministic replay logs worker seeds, all imported messages, and the winner.

### Implementation Effort

Very high: 20-35 engineer-days after at least two independently useful engines
exist. A broker built before engine diversity is measured is premature.

### Observability

- worker start, first conflict, first model, first semantic export, and finish;
- exported, verified, rejected, imported, unit-producing, conflict-producing,
  and never-used messages by type and source;
- overlap of explored cubes or model fingerprints;
- wall time, total CPU, energy, PSS/USS, queue traffic, and cache misses;
- race-only versus race-plus-sharing ablation;
- virtual best-solver oracle, actual winner, and scheduling regret;
- direct four-core and single-core comparisons against equivalently configured
  Z3 and Yices2.

### Kill Gate

1. Before implementation, the virtual best of available internal engines must
   match Yices2 coverage and beat it by `1.10x` on the target. A race cannot
   exceed an oracle whose arms are all slower.
2. A no-sharing four-worker race must convert at least half of the current hard
   tail and beat Yices2 wall time by `1.20x` on the 39-case gate.
3. Semantic exchange must add at least `1.10x` over the no-sharing race or
   convert an additional timeout; otherwise remove the broker and keep the
   simpler portfolio.
4. Total CPU may be at most `2.5x` Yices2 on the target, peak PSS at most `2x`,
   and broker overhead below 3% of worker CPU.
5. No easy-head activation until a held-out online router has below 0.2%
   slowdown rate and positive aggregate gain.

### Why It Might Beat Yices2

Yices2 is a highly coherent single DPLL(T) architecture. A semantic crossbar
can exploit proof-system diversity unavailable to one search: resolution for
the eager head, direct finite interpretation search for QG, and lazy semantic
cuts for non-finite graphs. It only has a credible advantage if the component
engines independently own complementary wins; multiplying identical SAT seeds
will not close the observed Yices2 gap.

## 4. Offline Partition Machines

### Thesis

Precompute complete transition systems for small equality components. A state
is a canonical restricted-growth encoding of a set partition, not a union-find
heap. Transitions apply equality, disequality, and local function-congruence
events. Runtime graph decomposition maps blocks with at most `k` boundary
terms into these automata; solving becomes table lookup plus separator message
passing.

Bell numbers bound the raw state space: `B_10 = 115,975`, `B_11 = 678,570`,
and `B_12 = 4,213,597`. Initial tables must therefore stop at `k <= 10`, use
symmetry-reduced reachable states, and remain compressed. SIMD can advance
many component states through the same event stream.

### Novelty Classification

**Algorithmic novelty hypothesis.** Finite automata for equivalence relations
and offline table generation are known ideas, but a separator-composed,
proof-producing partition machine for QF_UF needs a dedicated prior-art audit.

### Target Family

- Formulas whose term/application graph decomposes into many blocks of at most
  ten live boundary terms.
- Repeated small equality gadgets in QG or hardware-verification formulas.
- Explicitly not the large biconnected Goel graphs unless separator telemetry
  shows small bags.

### Hardware And Memory Model

- Read-only transition tables shared by processes, memory-mapped at startup.
- Strict 64 MiB initial table budget and LLC-aware hot-state ordering.
- State IDs in 32 bits, transitions in compressed row groups, optional AVX2
  gather only after scalar cache behavior is measured.
- Offline generator may use WMI heavily; runtime remains single-core CPU.

### Soundness Boundary

- Exhaustively enumerate and verify every generated state and transition.
- Store a compact equality-path or local congruence witness with every rejecting
  transition.
- Separator composition must prove that forgotten terms cannot participate in
  later cross-component congruence.
- Any component larger than the proved table limit stays in the reference
  engine.

### Implementation Effort

High: 15-25 engineer-days including generator, checker, decomposition, and
compressed table format.

### Observability

- block, separator, and treewidth approximations;
- fraction of terms and runtime covered by table machines;
- reachable states, transition locality, table bytes, page faults, and LLC
  misses;
- table transitions versus reference merges and end-to-end savings;
- witness replay time.

### Kill Gate

- Shadow census must place at least 30% of measured corpus theory time in
  blocks with `k <= 10`.
- Tables must stay below 64 MiB and attain at least 90% hot-state LLC hit rate.
- The transition kernel must be `3x` faster than scalar closure and improve its
  routed target at least `1.15x` end to end.
- If it cannot beat Yices2 on the routed target after specialization, archive
  it as a negative result rather than enlarge `k` blindly.

### Why It Might Beat Yices2

For covered components, it replaces dynamic representative updates, use-list
maintenance, hashing, and rollback with a checked array transition. It can beat
Yices2 only if small-width structure is common enough and the tables fit cache;
the shadow census is intentionally able to kill it before major implementation.

## 5. Persistent Fork Snapshots

### Thesis

Parse, normalize, and construct immutable base state once. Fork after that
checkpoint so several proof engines or parameterizations inherit the same
pages by copy-on-write. A second optional checkpoint follows deterministic
preprocessing, enabling short speculative branches without rebuilding the
front end or CNF.

### Novelty Classification

**Known substrate and systems optimization.** Forkservers and process
snapshots are established. The only research question is whether SAT/SMT heap
mutation leaves enough pages clean for copy-on-write to pay off.

### Target Family

- Hard formulas routed to a multicore race.
- Repeated preprocessing variants over the same large 174-formula syntax set.
- Never the easy head until fork cost is proven negligible.

### Hardware And Memory Model

- Linux only; 4 KiB page accounting, transparent huge pages disabled for the
  first experiment because one write can copy a large page.
- Fork only from a single-threaded parent with fork-safe allocators and backend
  state.
- Separate immutable arenas from mutable watches, activities, assignments, and
  learned clauses so page dirtiness has semantic locality.
- Use `PSS`, `USS`, minor faults, copied pages, and teardown time, not RSS alone.

### Soundness Boundary

Process isolation does not change logical semantics. Each child still produces
a fully checked model or proof. The risks are systems failures: unsafe post-fork
locks, duplicated output, lost cancellation, and incomplete artifact flushes.

### Implementation Effort

Medium: 5-10 engineer-days for an experimental fork checkpoint, allocator
separation, cancellation, and metrics.

### Observability

- checkpoint and fork latency, child-ready latency, minor faults, dirtied
  pages, PSS/USS over time, duplicated bytes, and process teardown;
- parent setup saved per child and end-to-end race overhead;
- proof/model artifact durability under cancellation.

### Kill Gate

- Median fork-to-worker-ready must be below 0.5 ms on WMI.
- Four children must use less than `1.5x` the PSS of four independent workers.
- Copy-on-write faults must consume less than 5% of hard-target wall time.
- If mutable SAT heaps dirty more than 60% of inherited pages in the first
  100 ms, use shared immutable IR plus ordinary workers instead.
- Snapshotting alone cannot be called a Yices2-beating result.

### Why It Might Beat Yices2

It cannot by itself. It can make a genuinely diverse race affordable enough to
win tail wall time. Without better component engines, it only multiplies slower
searches.

## 6. Perfect-Hash And Cache-Line Term Layouts

### Thesis

Freeze all static keys after parsing and assign them collision-free slots:
symbols, source atoms, structural term descriptors, application occurrences,
and proof-witness nodes. Reorder IDs by expected traversal so a function's
applications, argument IDs, and use lists occupy contiguous cache lines.

Use a small bucketed perfect hash only when construction cost and query volume
justify it. For small key sets, sorted arrays, direct indexing, or generated
switches may be faster.

### Novelty Classification

**Known substrate and optimization.** The term ordering may be QF_UF-specific,
but it is not a new decision procedure.

### Target Family

- Large static term graphs and the 174 huge-syntax closed-table formulas.
- Repeated source-atom lookup during refinement and proof reconstruction.
- Not dynamic congruence signatures: representative tuples change during
  search and therefore are not a static perfect-hash key set.

### Hardware And Memory Model

- Cache-line buckets of 8-16 entries, 32-bit IDs, exact key verification, and
  read-only packed arrays.
- Construction is single-threaded and charged to solve time.
- Measure Intel and AMD separately because cache and branch tradeoffs differ.

### Soundness Boundary

- A claimed perfect hash must be verified over the complete static key set.
- Any fingerprinted non-perfect table performs exact key comparison before use.
- Reordering IDs must preserve a serialized semantic-IR equivalence check.

### Implementation Effort

Low to medium: 4-8 engineer-days after lookup telemetry identifies a real hot
map.

### Observability

- build time, bits per key, probes, negative queries, cache lines per lookup,
  branch misses, and end-to-end fraction;
- packed versus current allocation count and peak RSS;
- separate static-key and dynamic-signature metrics.

### Kill Gate

- Do not implement if target lookup consumes under 8% of corpus CPU time.
- Build cost must amortize within one solve and remain below 2% of total time.
- Require at least `1.5x` lookup throughput and `1.02x` full-corpus end-to-end
  gain with no CPU-class regression.
- If it does not contribute to a candidate that beats Yices2, describe it only
  as an implementation optimization.

### Why It Might Beat Yices2

Yices2 already uses compact integer-indexed tables, so perfect hashing alone is
unlikely to win. It matters only as an enabler for the staged formula machine
or fork-shared immutable state.

## 7. GPU Batch Closure And Finite Search

### Thesis

Use a GPU only when there are thousands of independent, similarly shaped work
items: finite-model cubes, partition states, or separate service requests.
Represent assignments and domain masks in structure-of-arrays form. A
wavefront evaluates the same Boolean/table schedule across cubes and compacts
survivors between kernels.

Two tracks must remain separate:

- **single-instance tail**: one hard finite formula supplies enough cubes to
  saturate the device;
- **batch throughput**: many independent formulas are solved together through
  a persistent service.

The second track is operationally useful but does not count as a cold
single-query SMT-COMP win unless comparators receive equivalent batching.

### Novelty Classification

**Known accelerator substrate**, with a possible **new engineering
combination** for proof-producing QF_UF quotient cubes. GPU graph closure and
GPU constraint propagation already exist.

### Target Family

- Domain-7 finite tails after the CPU quotient swarm exposes at least 16,384
  independent live cubes.
- Large batches in verification services.
- Reject for small Goel graphs, ordinary parser-heavy inputs, or short easy
  formulas.

### Hardware And Memory Model

- Persistent GPU context, pinned host buffers, asynchronous transfers, and
  fixed-shape kernels.
- Device memory stores immutable schedules and large cube batches; CPU handles
  parsing, structural recognition, proof checking, and irregular residuals.
- Benchmark PCIe and shared-memory accelerators separately. No result may hide
  context initialization or transfer time.

### Soundness Boundary

- GPU rejection is accompanied by a compact witness rechecked on CPU.
- GPU SAT candidates are full models revalidated on CPU.
- Kernel errors, device loss, timeout, or malformed witness cause abstention.
- UNSAT requires all cube witnesses plus a checked exhaustive cover.

### Implementation Effort

Very high: 20-40 engineer-days after the CPU algorithm is stable. Porting an
unproven CPU design to GPU first is forbidden.

### Observability

- context, allocation, transfer, launch, kernel, compaction, and CPU-check time;
- occupancy, divergence, memory bandwidth, active cubes, cubes per watt, and
  break-even batch size;
- end-to-end single-query and throughput results separately.

### Kill Gate

- No prototype before CPU telemetry shows at least 16,384 concurrent cubes on
  ten or more official hard formulas.
- Host/device overhead must remain below 10% and device occupancy above 60%.
- Require `5x` CPU-kernel throughput and `1.50x` end-to-end wall improvement on
  the single-instance finite-tail target.
- The GPU path must beat Yices2 wall time on that target including setup. A
  batch-only win is reported only as throughput engineering.

### Why It Might Beat Yices2

A GPU can exceed a scalar e-graph only on a wide, regular finite search with
enough parallel work. It is unlikely to challenge Yices2's 20-30 ms easy head
and should be killed quickly if the cube frontier is narrow or divergent.

## 8. Content-Addressed Quotient Memoization

### Thesis

Many Boolean SAT assignments may induce the same EUF partition or the same
residual quotient problem. Canonicalize a validated partition, live
disequalities, and unresolved application signatures into an exact quotient
key. Cache either:

- a checked conflict lemma;
- a residual cube result;
- a model extension; or
- an offline partition-machine state.

Use a fast fingerprint only to find candidates; compare the full canonical key
before reuse. Share only immutable, checked entries across workers.

### Novelty Classification

**Algorithmic novelty hypothesis** if the quotient key supports proof-safe
reuse across distinct Boolean assignments or encodings. Ordinary SAT
transposition tables and memoization are established.

### Target Family

- Multi-round model-directed refinement with repeated invalid partitions.
- Symmetric finite formulas with many Boolean assignments per quotient.
- Not one-shot cases with no repeated quotient.

### Hardware And Memory Model

- Bounded shard-local tables, 128-bit fingerprints, exact compressed keys,
  clock or utility-based eviction, and read-only promotion of high-value
  entries.
- Hard memory budget of 64 MiB initially; no global lock in the hot path.

### Soundness Boundary

- Exact key equality is mandatory before reuse.
- Cached conflicts carry replayable source-level lemmas; cached SAT extensions
  still undergo complete model validation.
- Scope includes every source atom on which the result depends. Omitting a
  guard is a soundness error.

### Implementation Effort

Medium: 7-12 engineer-days after shadow traces quantify duplicate quotients.

### Observability

- exact and fingerprint hit rates, false candidates, key-build time, bytes per
  entry, evictions, reused proof types, and avoided SAT/theory work;
- quotient multiplicity distribution by family;
- cross-worker versus local utility.

### Kill Gate

- Shadow traces must show at least 20% exact quotient repetition on a target
  consuming at least 5% of total corpus time.
- Key construction plus lookup must be below 10% of avoided work.
- Require `1.15x` target end-to-end gain and no memory-driven regression.
- If gains arise only from benchmark repetition across files, reject the path
  as corpus caching rather than solving.

### Why It Might Beat Yices2

It could collapse large symmetric Boolean search regions that a trail-based
solver revisits under different assignments. Without high exact quotient
reuse, Yices2's incremental e-graph will be cheaper than canonicalization.

## 9. Explicitly Rejected Or Non-Headline Systems Tricks

These may be measured, but they cannot support a superiority or novelty claim:

- **Warm solver daemon without comparator daemons**: changes process-start and
  I/O accounting unfairly.
- **Corpus-name, path, or content-hash routing**: memorizes the benchmark rather
  than solving its structure.
- **Result cache across official instances**: invalid as solver performance.
- **Blind multi-seed Kissat race**: ordinary portfolio behavior and unlikely to
  close a structural Yices2 gap.
- **Generic GPU SAT port**: mature CDCL is irregular and transfer-heavy; start
  only from a regular quotient kernel with a measured frontier.
- **Minimal perfect hash for changing class signatures**: the key set changes
  with the model, so the premise of static perfect hashing is false.
- **AVX-512-only path**: violates the mixed-node portability requirement and
  repeats the prior illegal-instruction risk.
- **Intel TSX rollback**: unavailable or disabled on relevant AMD and many Intel
  systems; unsuitable as the correctness or performance foundation.
- **Huge pages for mutable fork state**: one write may amplify copy-on-write;
  use only after page-dirtiness evidence.
- **External Yices2 fallback**: useful operationally, but it cannot establish a
  standalone win over Yices2.

## Execution Program

## Phase A: Prior Art And Opportunity Census

Run before solver behavior changes.

1. Produce a machine-readable structural manifest for all 7,503 formulas:
   finite domains, closed tables, table arity, Boolean DAG occurrences and
   unique nodes, term graph blocks/separators, equality graph size, current
   model/refinement passes, and exact family lineage.
2. Add shadow traces for quotient repetition, static evaluator time, lookup
   time, parent/use-list traversal, and candidate lane width.
3. Build a prior-art matrix for each novelty hypothesis across SMT, SAT, finite
   model finding, constraint programming, databases/JITs, graph processing,
   fuzzing snapshots, and parallel proof systems.
4. Inspect current Yices2 source and documentation for any equivalent finite
   model, generated-code, or semantic-exchange path.
5. Freeze target manifests before performance implementation. No benchmark
   name or content hash may be a routing input.

Deliverables:

- `systems-opportunity.json` with formula-level features and measured costs;
- one prior-art note per surviving algorithmic hypothesis;
- exact target manifests for 261 one-table, 431 domain-7, 174 huge-syntax, 39
  large-graph, hot-400, and hard-tail sets;
- a no-go decision for every mechanism that fails its census gate.

## Phase B: Reference Semantics

1. Repair the global Boolean-as-data and total-model soundness boundary.
2. Implement small scalar reference models for quotient search, generated
   formula execution, partition transitions, and semantic messages.
3. Exhaust finite structures for tiny domains and randomize typed term graphs.
4. Differentially compare every reference result with Z3 and cvc5, then use
   Yices2 as a performance comparator.
5. Make all experimental engines abstaining by default; only the existing
   independently validated route may answer during shadow runs.

## Phase C: Top-Two Prototypes

Run two isolated branches with no shared optimization beyond measurement:

- C1: scalar quotient interpreter, then AVX2 quotient swarm on exact one-table
  formulas;
- C2: serialized formula schedule, then stencil execution for Boolean and
  theory-atom projection.

Each branch must preserve a same-binary off/on switch and report build cost,
solve cost, proof/model-check cost, memory, hardware counters, and Yices2
pairwise results. Do not combine C1 and C2 until each passes its independent
target gate.

## Phase D: Tail Diversity

1. Run a virtual-oracle study over every independently successful internal
   engine.
2. Prototype ordinary no-sharing races first.
3. Build the semantic crossbar only if the oracle and race gates pass.
4. Add fork snapshots only after independent worker setup is measured.
5. Test quotient memoization and partition machines from shadow evidence, not
   intuition.

## Phase E: Composition Without Attribution Loss

Use a factorial gate rather than stacking all accepted tricks:

- quotient swarm off/on;
- staged formula machine off/on;
- semantic exchange off/on where parallel;
- snapshot setup off/on where parallel.

Report main effects and interactions. A combination is rejected if its gain is
smaller than the best component, if it loses coverage, or if its router depends
on family identity rather than prospective structure.

## Phase F: Superiority Campaign

For every surviving sequential and parallel binary:

1. Hash the exact artifact and archive build metadata.
2. Run local correctness, property, differential, and proof/model tests.
3. Run repeated target gates on Intel and AMD WMI nodes.
4. Run sample-40, hot-400, finite tail, Goel tail, and full 7,503 paired gates.
5. Compare cold processes with pinned Z3, cvc5, and Yices2 at 2, 60, and 1,200
   seconds.
6. Repeat the full campaign independently and evaluate a source-family holdout.
7. Reconstruct and check SAT proofs, semantic lemmas, orbit witnesses, cube
   covers, and SAT models.
8. Report every rejected arm and all raw rows. Do not select only the timeout
   at which the solver looks best.

## Top-Two Milestone Schedule

### Milestone Q0: Quotient Feasibility

- Exact finite recognizer and scalar interpreter.
- Exhaustive domains 1-4.
- Structural census of 261 and 431 targets.
- Go/no-go after five days.

### Milestone Q1: SIMD SAT Candidate Search

- AVX2 table and Boolean masks.
- Scalar differential checks on every candidate batch.
- SAT model reconstruction only; UNSAT abstains.
- Target microbench and repeated 261-case WMI gate.

### Milestone Q2: Complete Quotient Proof

- Disjoint cube scheduler, Hall and orbit witnesses.
- Independently checked UNSAT cover.
- 431-case direct comparison with Yices2.
- Promote to broad QG experiment only after a target Yices2 win.

### Milestone S0: Staging Feasibility

- Profile static evaluator share and reuse counts.
- Serialized reference schedule and exact state differential.
- Go/no-go after four days.

### Milestone S1: Native Stencils

- Boolean DAG and atom-projection stencils under W^X.
- Hard code-size and patch-time limits.
- Huge-syntax bytecode path.
- QG and hot-400 repeated gates.

### Milestone S2: Fused Theory Schedule

- Static use-list and violated-lemma schedule.
- Reference lockstep and proof replay.
- Full 7,503 gate only if the routed target is within `1.10x` of Yices2.

## Expected Decision Tree

1. If quotient M0 coverage is broad and M1 beats Yices2 on one-table QG, make
   quotient search the primary finite engine.
2. If quotient M1 is fast but cannot prove UNSAT efficiently, keep it as a SAT
   finder and cube generator while another proof engine covers UNSAT.
3. If staging does not amortize on cold processes, retain the serialized
   schedule and discard native code; do not hide failure behind daemon mode.
4. If partition width is small, add offline partition machines to the staged
   engine. Otherwise kill the table-generation path.
5. If internal engine diversity has a Yices2-beating oracle, build the semantic
   crossbar and snapshots. Otherwise invest in new proof systems, not more
   portfolio plumbing.
6. If no sequential combination beats Yices2 on QG, the full-superiority goal
   has failed for this architecture even if it remains faster than Z3 on the
   common head.

## Publication-Level Claim Shape

The strongest defensible outcome would not be "a faster e-graph." It would be:

> A proof-producing QF_UF portfolio whose dominant finite fragment is solved by
> lane-parallel quotient-model search and whose general fragment is executed
> by formula-staged kernels, with typed semantic lemmas exchanged between
> independent proof spaces.

That claim is substantially different from Z3 and Yices2 only if ablation
shows that quotient-space search or generated schedules, rather than an
ordinary SAT race or benchmark routing, produce the measured win. The campaign
is designed to discover that boundary early and to terminate attractive but
noncompetitive ideas without compromising soundness or evidence quality.
