# No-Compromise QF_UF Novelty Campaign

Date: 2026-07-11

Status: active research contract. Novelty labels are hypotheses until the
exclusion audit, source audit, implementation ablation, and held-out campaign
all pass.

## Mission

Build a standalone, sound, certifying QF_UF solver that is structurally
different from the mature Z3 and Yices2 DPLL(T)/e-graph designs and beats both
on complete-corpus quality and parser-inclusive timing.

The campaign does not accept:

- selected-family timing as an overall result;
- median speed without tail coverage;
- a comparator process as fallback;
- benchmark names, statuses, hashes, or prior timings as routes;
- an unverified SAT model or unchecked UNSAT extension;
- a novelty claim based only on vocabulary, Rust, SIMD, or a new combination
  name.

"No compromise" means correctness and evidence are harder constraints than
speed. It does not mean declaring an unmeasured idea successful.

## Quantitative Starting Point

The exact `58efe9d` binary has these complete-corpus checkpoints:

| Budget | euf-viper | Z3 | Yices2 | Main deficit |
| --- | ---: | ---: | ---: | --- |
| 2s coverage | 6,948 | 7,176 | 7,434 | 487 solves to exceed Yices2 |
| 60s coverage | 7,478 | 7,490 | 7,500 | 23 solves to exceed Yices2 |
| 1200s coverage | 7,502 | 7,500 | 7,503 | one final solve |
| 2s total | 2,327.84s | 2,245.09s | 748.96s | `3.108x` uniform reduction to Yices2 |
| 60s total | 5,930.09s | 3,998.14s | 1,307.54s | `4.535x` uniform reduction to Yices2 |
| 1200s total | 8,575.78s | 8,676.80s | 2,010.00s | `4.267x` reduction to Yices2 |

At 1,200 seconds the old binary narrowly exceeds Z3 on coverage and
timeout-charged total, but loses common-solve aggregate time. Yices2 is the
actual performance bar. The measured binary also has the known Boolean-data
defect, so these numbers are opportunity measurements until repaired commit
`53c12f7` reproduces them.

The structural atlas proves that a Yices2-changing route must be broad. The
frozen `TABLE_CORE OR GRAPH_32` envelope contains 7,305/7,503 formulas. A few
spectacular tail conversions cannot win the overall ranking.

## Novelty Exclusion Zone

The following are useful ingredients but cannot be the headline contribution:

1. eager EUF-to-SAT reduction;
2. full, partial, dynamic, or model-directed Ackermannization;
3. sparse transitivity or chordal equality completion;
4. rollback congruence closure and partial-trail theory propagation;
5. MCSat-style partial model construction;
6. ordinary constant/range symmetry, lex leaders, or one-hot finite tables;
7. Hall propagation, adequate ranges, Boolean DAG sharing, or SAT portfolios
   considered separately;
8. DRAT/LRAT, congruence explanations, or model validation by themselves;
9. parser arenas, cache layouts, PGO, LTO, SIMD, or GPU execution by
   themselves.

The detailed evidence is in:

- `2026-07-11-novelty-exclusion-map.md`;
- `2026-07-11-z3-yices-boundary-audit.md`.

Every surviving claim must name the closest known mechanism and the exact
semantic, proof-system, or integration difference.

## Proposed Solver Architecture

The endpoint is a staged quotient machine with six independently removable
mechanisms. It is not one monolithic solver rewrite.

### N1: Pre-CNF Complete-Model Scouts

Before allocating CNF, evaluate a fixed suite of complete typed quotient
interpretations over the source Boolean DAG:

- maximally diverse/free-term quotient;
- maximally collapsed quotient consistent with explicit disequalities;
- greedy disequality-coloring quotient;
- low-cost congruence-respecting quotient repairs;
- fixed false/true choices for otherwise unconstrained Boolean-valued UFs.

A scout may return only SAT, together with a total model that a separate source
evaluator accepts. A miss discards all state and enters the baseline unchanged.
No scout may return UNSAT.

This is first because its soundness boundary is small and it directly targets
Yices2's broad head advantage. Shadow promotion requires at least 5% unique
hits among satisfiable instances and less than 2% miss overhead. Behavioral
promotion requires `1.20x` on hits and improvement on every complete-corpus
metric.

### N2: Theory-Conditioned Boolean Quotient Compiler

Retain the source Boolean DAG and share nodes not only by syntax, but under a
checked unconditional or guarded EUF congruence. Each share records its
assumptions and a reconstruction witness. This must reduce the actual
propositional problem rather than run ordinary hash-consing or post-CNF gate
extraction.

Telemetry must project at least 25% fewer CNF variables or clauses on 8/10 hard
closed-table timeout formulas before behavior changes. Exhaustive formulas
through six theory atoms and at least one million generated typed formulas
must preserve semantics.

### N3: Proof-Carrying Multi-Table Orbit Quotient

For proved finite closed structures, compute a verified automorphism action,
build a stabilizer chain, reject noncanonical partial tables, and emit replayable
orbit witnesses. Unlike ordinary symmetry clauses, this mechanism quotients
search states and later lifts models and proofs.

The first exact scope is 261 domain-7 one-table formulas. Exhaustive carriers
through size five must retain exactly one representative per isomorphism
class. The first WMI gate requires at least one timeout conversion and all
timing ratios above `1.05x` on both CPU classes.

### N4: Bit-Sliced Quotient Swarm

Run 64 or 256 canonical finite quotient candidates in parallel machine-word or
SIMD lanes. A fused evaluator applies source constraints, table consistency,
and orbit rejection to the whole lane block. Surviving candidates are checked
by the scalar model evaluator. UNSAT is permitted only after exact exhaustive
coverage with a replayable partition of the searched quotient space.

This is a finite/table bulk engine, not GPU decoration and not a one-hot SAT
table. Its feasibility gate measures candidates per cycle, lane utilization,
memory traffic, and exact agreement with scalar enumeration through domain
size five. Reject if the end-to-end table gate is below `2x`; Yices2 requires
a large gain, not a micro-optimization.

### N5: SAT-Native Quotient-State Search

Develop reference engines whose search object is neither pairwise Ackermann
clauses nor an equality e-graph:

1. **Canonical Quotient RAM:** class assignments address one sorted record
   memory that enforces observed functionality without application-pair
   implications.
2. **Frontier Quotient Transducer:** SAT selects a path through canonical
   partial-algebra states along a structural frontier; exact fallback handles
   unsafe forgetting.
3. **Permuted finite-field interpretation:** a high-risk finite-table engine
   searches compact polynomial function programs under a jointly searched
   relabeling.

Each starts as a slow semantic reference checked against brute quotient
enumeration. If emitted CNF contains pairwise functional-consistency
implications, or runtime invokes congruence closure to decide a candidate, the
claimed representation has collapsed to known work and is rejected.

### N6: Component-Level Proof-System Migration

Only after N1-N5 are measured, allow one ground interference component to move
between eager clauses, quotient-state search, and finite orbit/Hall reasoning.
Migration is driven by prospective fill plus online proof-complexity evidence:
conflict growth, clause width/LBD, invalid-model recurrence, and useful-cut
yield. Learned information crosses representations only through a small,
checker-replayable fact language.

The novelty hypothesis is reversible per-component migration with proof
provenance, not rollback closure or dynamic Ackermannization. Telemetry-only M0
must classify held-out eager wins and proof-complexity tails with balanced
accuracy at least 0.80 and overhead below 1%.

## Systems Substrate

Three systems mechanisms support, but do not constitute, novelty:

- a staged formula machine with compact typed opcodes and fused source
  evaluation/CNF emission;
- perfect-hash, cache-line term layouts generated after parsing;
- a semantic proof-space crossbar that races independently complete engines
  and shares only checked representation-neutral facts.

The first two must improve parser-inclusive full-corpus time. The crossbar is a
parallel-track result unless it also wins under the single-core allocation used
for the main claim.

## Execution Waves

### Wave 0: Sound Reference

1. Revert rejected parser optimization.
2. Atomize every Boolean term used as data.
3. Complete or reject every partial backend model.
4. Differential-test Boolean-data formulas against Z3 and cvc5.
5. Run WMI all-feature, targeted soundness, sample-40, hot-400, hard-tail, and
   full-corpus gates.
6. Freeze the repaired binary and hashes before novelty timing.

Current state: local repair passes. Exact branch `soundness/accepted-58efe` is
at `53c12f7`; corrected WMI jobs `143680`, `143681`, and `143682` are the
correctness, sample-40, and 10,000-case differential gates. Initial job
`143674` failed before computation because the SLURM script selected the submit
directory instead of `--chdir`; its blocked dependents were cancelled.

### Wave 1: Shadow Census

Implement telemetry that cannot alter CNF or answers:

- scout hit classes and validation cost;
- syntax DAG versus theory-conditioned quotient DAG counts;
- automorphism group/order and stabilizer depth;
- bit-sliced lane occupancy and projected work;
- quotient-RAM/frontier widths and state counts;
- per-component proof-complexity features.

Run all 7,503 formulas once and freeze selector manifests before viewing
behavioral timing. A mechanism with no measured opportunity is rejected here.

### Wave 2: Semantic References

Build deliberately slow, independent reference implementations for model
scouts, stabilizer canonicality, scalar quotient swarm, CQRAM, and no-forget
frontier states. Exhaustively compare small carriers and generated formulas.
Optimized implementations remain dual-runnable against these references in
tests.

### Wave 3: Isolated Behavioral Gates

Implement N1 first, then N3 and N2, then N4/N5. Every candidate is default-off
and uses the same binary in both arms when possible. Gate order:

1. exact semantic/property tests;
2. frozen structural target, at least three alternating repeats;
3. sample-40;
4. hot-400;
5. finite and non-finite hard tails;
6. full 7,503 at 2 seconds;
7. 60-second timeout continuation;
8. 1,200-second timeout continuation.

No two novelty mechanisms are combined in this wave.

### Wave 4: Broad-Envelope Tests

An isolated tail win must expand to its rank-changing population:

- table mechanisms: `DOMAIN7_ONE_TABLE`, then `DOMAIN7_TABLE`, then
  `TABLE_CORE`;
- graph mechanisms: `GRAPH_2500`, then `GRAPH_500`, then `GRAPH_32`;
- residual quality: `DEEP_LET_512` and `FINITE_HALL`;
- final envelope: `TABLE_CORE OR GRAPH_32`, then add deep-let residuals.

Selectors are frozen in the tail atlas and may not be retuned on these runs.

### Wave 5: Factorial Composition

Only individually surviving mechanisms enter pairwise `2 x 2` experiments.
Report main effects and interactions. A combination is rejected if aggregate
gain hides a regression in either original target. The complete combination is
tested only after every included main effect remains positive.

### Wave 6: Superiority Campaign

Run the final standalone binary against freshly pinned Z3, cvc5, and Yices2:

- 2s, 60s, and 1,200s;
- AMD and Intel WMI nodes;
- two independent full repetitions;
- source-family holdouts and a separately frozen external corpus;
- parser-inclusive wall/CPU time and peak RSS;
- independent SAT-model and UNSAT-proof checking.

## Promotion Contract

At every required timeout, a superiority candidate must have:

1. zero wrong answers, execution errors, malformed models, and failed proofs;
2. coverage strictly above both Z3 and Yices2, or complete coverage when a
   comparator is already complete;
3. at least `1.05x` lower timeout-charged total than each comparator;
4. at least `1.05x` lower common-solve aggregate than each comparator;
5. at least `1.02x` geometric speed on common solves;
6. lower median and p95 latency than both comparators;
7. the same direction on both CPU classes, both full repeats, and the holdout;
8. certificate generation and checking reported separately and successfully.

For the current 2025 corpus this means, at minimum:

- at 2s: at least 7,435 solves and total below 711.51s;
- at 60s: at least 7,501 solves and total below 1,242.16s;
- at 1,200s: 7,503 solves and total below 1,909.50s.

Those are acceptance floors, not optimization targets.

## Agent And Branch Discipline

- One semantic owner and one disjoint write scope per mechanism.
- One adversarial reviewer tries to break each mechanism before timing.
- Each behavioral candidate has an isolated branch or worktree from the frozen
  repaired baseline.
- Every iteration records source and binary hashes, flags, manifest hashes,
  machine, raw results, proof status, and one of `reject`,
  `retain-experimental`, `promote-route`, or `promote-default`.
- Failed mechanisms remain immutable. Revival requires a new causal hypothesis
  and comparison with both the original failure and current baseline.

## Immediate Ordered Work

1. Finish WMI soundness and sample gates for `53c12f7`.
2. Run deterministic Boolean-data differential generation locally and on WMI.
3. Promote or reject the repaired baseline through hot/full gates.
4. Implement N1 scout telemetry and independent model evaluator.
5. Implement N2 DAG quotient telemetry and N3 automorphism oracle in parallel.
6. Build scalar N4 and CQRAM/FQT reference kernels without solver routing.
7. Select the first behavioral novelty only from measured shadow opportunity.

This ordering preserves speed attribution while still exploring radical
representations in parallel.
