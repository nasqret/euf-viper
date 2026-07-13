# T3 M0 Component-Pressure Telemetry Contract

Date: 2026-07-13

Status: preregistered design; migration forbidden

Machine-readable contract: `campaigns/t3-m0-component-pressure-v1.json`

Executable validator: `scripts/bench/validate_t3_m0_contract.py`

## Decision

T3 does not yet have enough evidence to implement component migration. The
frozen rollback panel contains only 24 sources: all targets are Goel and all
controls are QG. It can define telemetry fields and fixed-arm labels, but it
cannot estimate a family-independent selector.

Using coverage-aware PAR-2 with a 60-second timeout, the best fixed arm totals
`223.453` seconds while the per-source oracle totals `215.403` seconds. Thus

\[
H = \frac{\min_a \sum_i \operatorname{PAR2}(i,a)}
         {\sum_i \min_a \operatorname{PAR2}(i,a)} - 1
  = 0.0374.
\]

This preliminary `3.74%` headroom is below the preregistered `10%` gate.
Common-solve-only timing suggests much larger separation, but it discards
coverage and is not an admissible migration objective. T3 remains stopped until
at least two independently accepted fixed representations have a broader,
lineage-disjoint label panel whose 95% cluster-bootstrap lower bound on `H` is
at least `0.10`.

## Semantic Unit

Telemetry is attached to formula-local components, not benchmark files or
families. T1 supplies a typed, representation-neutral term/application graph.
Stable component and term IDs are deterministic typed traversal indices and
must remain unchanged across eager, rollback, dynamic-Ackermann, quotient, and
finite representations. Content hashes remain integrity metadata outside the
runtime feature vector.

Component ownership is frozen immediately after typed parsing and before any
representation-specific rewriting. A later representation may split internal
storage, but every emitted clause, assignment event, explanation, and model
violation must map back to one or more frozen component IDs.

## Checkpoints

### S0: Static Prefix

S0 occurs after typed parsing and representation-neutral base-CNF construction,
before finite routing, Ackermann expansion, refinement cuts, rollback setup, or
SAT search. The allowlist is:

- term, application, function, and constant counts;
- function arity and term-depth histograms;
- equality/disequality graph vertices, edges, components, degree summaries,
  articulation points, and bounded separator estimates;
- base-CNF variables, clauses, literals, and cross-component atom sharing;
- projected eager-Ackermann pair and clause counts;
- capped chordal-fill estimates;
- proved finite-domain sizes, closed-table counts, disequality clique bounds,
  and bounded Hall slack.

Every value must be a deterministic function of the source semantics available
at S0. Timing, paths, names, expected status, and benchmark identity are not S0
features.

### S1: Bounded Eager Shadow Prefix

S1 runs the identical fixed eager prefix for every arm. It stops at the first
invalid complete model or at the first reached cap among 4,096 conflicts,
65,536 theory events, and 0.5% of the per-instance budget. Its allowlist is:

- component-attributed assignments, decision levels, backtracks, and conflicts;
- invalid complete-model count and repeated invalid-signature count;
- validator CPU share measured only inside the bounded prefix;
- refinement cuts emitted and accepted;
- projected versus realized representation fill.

Backend-specific LBD and any event after the common checkpoint are excluded.
An arm may not influence the prefix that generates its own selector features.

## Forbidden Inputs

The selector must never receive source path, family, lineage, taxonomy,
manifest position, raw or normalized content hash, benchmark or symbol names,
expected status, final SAT/UNSAT/unknown result, final runtime, winning arm, or
post-checkpoint events. Family, lineage, duplicate closure, and hashes live in
a separate split and integrity ledger only.

## Fixed Arms And Labels

The initial arm vocabulary is fixed as:

1. current eager encoding;
2. whole-instance conflict-only rollback control;
3. dynamic Ackermannization;
4. model-directed cuts.

An arm that has not independently passed correctness and evidence-integrity
review may be measured as a research control but cannot be a migration target.
Each source uses four repeats in a balanced Williams order and a 60-second
timeout. A miss is charged PAR-2 = 120 seconds.

A winner label is unique only when one arm has coverage dominance, or when all
arms have equal coverage and one arm is at least 5% faster by median with the
same direction in at least three of four paired blocks. All other sources are
`unresolved`. The 24-source rollback panel currently yields 12 dynamic labels,
11 rollback labels, one unresolved source, and no current or model-cuts label;
this is descriptive telemetry, not training data.

## Census And Splits

Static S0 features are collected for all 7,503 sources. The first label panel is
the deduplicated union of `GRAPH_32`, `DOMAIN7_TABLE`, `FINITE_HALL`, and
`DEEP_LET_512`, plus 512 controls sampled by semantic quantile and lineage. Its
maximum size before overlap is 1,762.

Split groups are the transitive union closure of family, generator lineage, and
raw plus normalized duplicates. No connected group crosses development and
sealed evaluation. Development and sealed evaluation each require at least 64
independent lineages for every winner class retained for training.

External evaluation contains at least `max(256, 64*K)` sources, where `K` is the
number of retained winner classes, at least three unseen families, and at least
64 lineages per class. The sealed set is opened once after the classifier,
thresholds, and feature implementation are frozen.

## Model And Gates

The only M0 classifier is a deterministic depth-four decision tree. No learned
embedding, path token, symbol token, family classifier, or sealed-set feature
selection is allowed.

M0 passes only if all of the following hold:

- at least two migration-eligible fixed arms survive their own correctness and
  broad timing gates;
- the 95% family/lineage-cluster-bootstrap lower bound on oracle headroom is at
  least `0.10` under coverage-aware PAR-2;
- the 95% cluster-bootstrap lower bound on sealed balanced accuracy is at least
  `0.80`;
- the 95% upper bound on p95 telemetry time ratio is below `1.01` across eight
  paired blocks;
- telemetry-off and telemetry-on semantic traces are byte-identical;
- every source, feature row, label row, split group, binary, interpreter, and
  campaign artifact is hash bound and independently replayed.

Any missing row, leaked group, forbidden feature, changed semantic trace,
incorrect result, hash mismatch, non-unique label counted as a winner, or
failed bound rejects M0. Failure stops T3 before M1.

The repository CI validates these exact caps and thresholds. It also rejects a
weakened headroom or accuracy gate, removal of required leakage denials,
post-checkpoint feature admission, trace-equivalence weakening, and preliminary
headroom inconsistent with the frozen PAR-2 totals.

## Execution Order

1. Integrate the reviewed T1 typed stream and stable semantic IDs.
2. Finish T4/T5/T6 and production-evidence integrity gates.
3. Admit only independently accepted fixed representations to the arm set.
4. Run the all-source S0 census and freeze duplicate/group closure.
5. Run the four-arm label panel and compute coverage-aware oracle headroom.
6. Stop if the survivor or headroom gate fails.
7. Otherwise freeze the depth-four tree, run telemetry overhead and trace
   equivalence, then open the sealed evaluation once.
8. Implement one-way migration only after every M0 gate passes.

## Novelty Boundary

Fixed eager encoding, rollback congruence closure, dynamic Ackermannization,
and portfolios are established techniques. The differentiated hypothesis is a
checked, representation-neutral, per-component pressure signal that authorizes
one-way migration while preserving stable semantic ownership and replayable
lemmas. M0 tests whether that hypothesis has enough measurable headroom to
justify implementation; it does not itself establish novelty or performance.

Related: [[2026-07-13-validation-pressure-rollback]],
[[2026-07-13-rollback-control-rejected]], and
[[2026-07-13-unresolved-track-refresh]].
