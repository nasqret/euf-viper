# Viper Fabric Execution Contract

Date: 2026-07-22

Status: implementation active; all new behavior is default-off; component
migration is forbidden until its fixed-arm prerequisites pass.

Machine-readable contract: `campaigns/viper-fabric-2026-07.json`

## Objective

Build the best measured standalone single-core QF_UF solver. The release must
beat Yices2, Z3, cvc5, and OpenSMT on the exact full and official corpora, repeat
on two CPU classes, generalize to a sealed source-family holdout, validate every
SAT model, and independently check every UNSAT proof.

The central research hypothesis is not an instance portfolio. It is a single
semantic solver whose components can change proof systems while retaining
stable identities and exchanging only checker-replayable facts.

## Measured Deficit

The audited `30828a4` campaign remains the immutable comparator.

| Budget | euf-viper | Yices2 | Coverage deficit | Yices2 common geometric advantage | Yices2 common aggregate advantage |
| --- | ---: | ---: | ---: | ---: | ---: |
| 2s | 7,269 | 7,445 | 176 | 1.93x | 3.98x |
| 60s | 7,480 | 7,500 | 20 | 2.04x | 5.01x |
| 1,200s | 7,502 | 7,503 | 1 | 2.07x | 4.95x |

At 60 seconds the current median is 26.77ms versus 17.15ms for Yices2, while
the p95 is 1.234s versus 0.190s. The architecture must therefore improve both
the broad head and the proof-complexity tail. Closing one timeout is not enough.

## Nonnegotiable Decisions

1. Keep the current T11 branch isolated. T11 remains certificate and proof
   research and contributes no performance credit without a paired campaign.
2. Use clean `main` revision `27b3ff4` as the implementation base and audited
   revision `30828a4` as the immutable benchmark reference.
3. Preserve exact eager behavior as engine E0. Every new mechanism begins
   default-off and must have byte-identical off-mode behavior.
4. Build fixed engines before a router. Migration is forbidden until at least
   two fixed alternatives pass correctness and timing gates and their
   coverage-aware oracle has a 95% lower bound of at least 10% headroom.
5. Never route using path, family, benchmark name, hash, expected status, or
   prior timing. Only bounded semantic features available before the decision
   may be used.
6. Do not compose mechanisms merely because their projections look smaller.
   Each mechanism must improve parser-inclusive wall time in isolation.
7. Do not implement SIMD, GPU, JIT, or broad memoization until a scalar census
   proves sufficient regular work, reuse, and occupancy.
8. No external solver fallback can support a standalone superiority claim.

## Architecture

### A. Semantic Substrate

The substrate adapts the existing `Problem`, `TermArena`, `BoolProblem`, and
source evaluator into a compact representation-neutral view.

Required properties:

- stable 32-bit term, function, Boolean-node, atom, and component IDs;
- deterministic IDs derived from typed traversal, never addresses or hashes;
- one term/application arena and one source Boolean DAG;
- component ownership frozen before any eager expansion or theory rewrite;
- explicit cross-component Boolean constraints;
- append-only proof events referring only to stable semantic IDs;
- structure-of-arrays hot fields for terms, applications, and native clauses;
- no second parse and no reconstructed symbol table on the ordinary path.

Initial modules:

```text
src/fabric/mod.rs
src/fabric/component.rs
src/fabric/partition.rs
src/fabric/native_clause.rs
src/fabric/proof.rs
src/fabric/telemetry.rs
```

The first full-corpus shadow records component counts, projected eager fill,
Boolean cross edges, finite bounds, and source-to-component ownership. It may
not solve, learn, migrate, or change emitted CNF.

### B. Engine E0: Sparse Eager SAT

E0 is the exact current behavior and remains the fast-head control. Existing
finite encoding, dynamic completion, model validation, and backend selection
are retained. No Fabric allocation is permitted when its feature is disabled.

E0 supplies:

- a correctness and performance baseline;
- representation-neutral base clauses;
- component-attributed conflicts and validation failures for telemetry;
- a safe destination for unsupported Fabric components.

### C. Engine E1: Rollback EUF

E1 is a fixed conflict-only rollback congruence engine connected to a SAT
trail. It is prior art and a control, not the novelty claim. It must use
incremental use-lists and signature updates rather than whole-application
rescans. Explanations contain only registered atoms and are replayed by the
independent checker.

Whole-instance rollback has already failed. E1 exists to establish component
complementarity and a safe fixed comparison for E2 and migration.

### D. Engine E2: Canonical Partition CDCL

E2 searches directly over typed equality partitions. It does not assign one
independent Boolean variable to every equality and does not one-hot encode
class labels.

#### State

- rollback union-find for forced equalities;
- persistent disequality adjacency between representatives;
- canonical class birth order using restricted-growth labels;
- per-sort existing-class plus unique-next-class domains;
- observed function memory keyed by canonical argument-class tuples;
- native Boolean and equality clauses with watched undecided literals;
- an implication trail with decision level, reason, and stable proof event.

#### Literal semantics

Native literals are:

```text
Eq(t, u)       t and u are in the same quotient class
Neq(t, u)      t and u are in distinct quotient classes
Bool(t)        Boolean-valued ground term t is true
NotBool(t)     Boolean-valued ground term t is false
Class(t, k)    t occupies canonical class k, when k is in a proved bound
```

Every literal is three-valued under a partial partition. A watched clause
propagates only when all other literals are false. Congruence can force merges,
function-table entries, or conflicts. An absent merge is never treated as a
disequality.

#### Decisions

The initial decision is equality versus separation between orbit-representative
classes. For proved finite components, a term may instead choose an existing
class or the single canonical next class. Class labels cannot be permuted into
new branches.

#### Learning

The implication graph includes clause, congruence, disequality, and canonical
class reasons. Conflict analysis learns a native nogood and backjumps. The
first reference may use chronological learning; first-UIP becomes mandatory
before a performance campaign. Learned clauses are translated to the common
proof language and independently replayed.

#### Termination and answers

All resource caps return `abstain`. SAT requires a total source model accepted
by the independent evaluator. UNSAT requires a checked native proof or an
exhaustive cover DAG. A partially explored search can never return UNSAT.

### E. Engine E3: Canonical Quotient Frontier

E3 is selected only for low-separator or highly symmetric finite components.
Its state key contains:

- the canonical live partition restricted to the frontier;
- observed function-memory rows touching the frontier;
- residual source Boolean obligations;
- a source-complete forgotten-state summary;
- the next typed structural position.

Equivalent residual states share one node. SAT leaves reconstruct and validate
a total model. UNSAT uses a checked DAG whose outgoing decisions exactly cover
the native domain. Forgetting is forbidden until an independent small-domain
oracle proves the summary sufficient.

The existing `quotient_state_search.rs` and `quotient_csp.rs` are semantic
references. They are not production routes because they are test-only, bounded,
and do not perform native clause learning.

### F. X1: Theory Extended Resolution

The solver records repeated congruence explanations, equality paths,
application-collision antecedents, and learned-clause suffixes. A census runs
before behavior changes.

If a replayable motif is frequent enough, introduce a fresh extension atom
with an exact definition over existing literals. Later explanations may use the
atom, reducing width, LBD, and repeated proof work. Generic AND/XOR/ITE learned
clause factoring is a mandatory control. The candidate survives only if the
theory-specific layer adds causal benefit.

An extension atom is never a semantic equality and cannot enter congruence
closure. The checker expands or validates every definition before accepting a
dependent clause.

### G. X2: Repeated Semantic Symmetry Simplification

Use the typed term/application graph to prove automorphisms of uninterpreted
values, interchangeable constants, and structurally equal component regions.
Choose connectivity-aware orbit representatives and add only checked unit or
binary restrictions during the first implementation.

After simplification changes connectivity, recompute the bounded symmetry
view. Every round must reduce a declared structural measure, so the schedule
terminates. Generic SAT symmetry preprocessing is a mandatory control.

### H. X3: Component-Local Migration

Migration is the composition mechanism and remains locked until E1, E2, or E3
establish enough fixed-arm complementarity.

Permitted online pressure signals:

- projected and realized eager fill;
- component-attributed conflicts and propagations;
- learned width and LBD distributions;
- repeated invalid-model signatures;
- theory-cut yield, duplication, and explanation work;
- partition/frontier width and memo reuse;
- deterministic semantic ticks approximating cache-line work.

The first implementation is one-way. A component starts in E0 and may migrate
once to E1, E2, or E3. Oscillation is forbidden. The source Boolean shell
retains global ownership. Learned state crosses only through checked unit,
binary, or bounded-width bridge clauses over stable atoms.

The migrating engine must beat every fixed engine on held-out targets. Beating
only E0 is insufficient.

## Proof Language

The independent checker recognizes a small typed event language:

```text
SourceClause
AssertEquality
AssertDisequality
CongruenceMerge
NativeUnit
NativeConflict
LearnNativeNogood
DefineExtension
UseExtension
SymmetryRestriction
BridgeClause
PartitionSplit
ClassChoiceCover
FrontierTransition
FrontierForget
SatModel
UnsatRoot
```

Every event identifies its premises by earlier indices. The checker rebuilds
source terms, sorts, function signatures, base Boolean semantics, component
ownership, and all conclusion bytes without calling producer canonicalization
or routing helpers.

## Implementation Order

1. Pin the Rust toolchain and validate clean baseline tests.
2. Add and validate this campaign contract.
3. Extract a production-capable partition state from the test reference.
4. Add deterministic semantic component decomposition and shadow telemetry.
5. Implement native literals, watched clauses, and an implication trail.
6. Add congruence and disequality propagation with explicit reasons.
7. Add chronological native learning, then first-UIP and nonchronological
   backjumping.
8. Add independent SAT model checking and UNSAT proof replay.
9. Run the E2 fixed-engine opportunity and timing gates.
10. Run the scalar E3 frontier census and stop before SIMD unless it passes.
11. Run X1 and X2 opportunity censuses, then isolated behavioral gates.
12. Compute fixed-arm oracle headroom. Implement migration only if its gate
    passes.
13. Compose user-approved mechanisms and run P4/P5 superiority campaigns.

## Per-Mechanism Decision Packet

Every isolated result must include:

- exact source and binary revisions and SHA-256 hashes;
- mechanism-off and mechanism-on commands;
- source manifest, structural selection, and all exclusions;
- correctness, SAT-model, UNSAT-proof, and fallback counts;
- paired coverage, common geometric, common aggregate, PAR-2, median, p95,
  peak RSS, and startup changes;
- family and SAT/UNSAT strata;
- causal telemetry such as learned width, state reuse, or extension hits;
- anti-target overhead and every off-only solve;
- an explicit `promote`, `reject`, or `unresolved` decision;
- user approval before composition or default behavior changes.

## Final Victory Gate

The release must satisfy all of the following in the same frozen binary:

| Corpus | 2s | 60s | 1,200s |
| --- | ---: | ---: | ---: |
| Full 7,503 | at least 7,446 | at least 7,501 | 7,503 |
| Official 3,521 | at least 3,491 | at least 3,519 | 3,521 |

It must also be at least 1.05x better than every comparator in common geometric,
common aggregate, and timeout-charged time; have zero wrong answers, execution
errors, missing rows, unchecked SAT models, or unchecked UNSAT proofs; repeat on
two CPU classes and two independent full runs; and preserve the direction on a
sealed source-family holdout.

Until every condition passes, the project may claim mechanisms, conversions,
or bounded benchmark wins, but not the best overall QF_UF solver.
