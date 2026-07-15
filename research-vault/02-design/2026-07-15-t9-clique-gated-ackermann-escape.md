# T9 Clique-Gated Ackermann Escape

Date: 2026-07-15

Status: preregistered before implementation or candidate timing

## Decision Boundary

T9 tests whether a structural transitivity-pressure selector can repair the
only euf-viper timeout in the terminal 1,200-second campaign by moving bounded
Ackermann and chordal completion before the first SAT call. It is an opt-in
candidate, not a new default route.

The experiment is narrower than the rejected `leaf-budget` route. It does not
enable leaf quotienting, does not wait for an invalid complete model, and may
not inspect a path, family, expected status, observed result, elapsed time, or
sealed comparator outcome. Reusable allocation guards from the old branch are
implementation material only; its leaf selector and timing claims remain
rejected.

## Frozen Diagnosis

The sole full-corpus timeout is
`QF_UF/2018-Goel-hwbench/QF_UF_sokoban.2.prop1_ab_br_max.smt2`, with source
SHA-256
`cfe0e5e611139004e7f8a06461c4cbf3066bb604786377db1a94d40e797f3112`.
Its direct-root encoding has 21,744 variables, 89,470 clauses, 147,132 literal
occurrences, and 102,152 watch slots. A complete eager dump has 43,916
variables and 342,033 clauses, including 186,075 equality-transitivity clauses,
zero congruence clauses, and zero finite-domain clauses.

A bounded ten-round trace spent about 5.07 ms in SAT and 823.36 ms in theory
validation, emitted exactly the 32-cut-per-round cap, and reached maximum cut
width 13. Older Linux telemetry reached 1,192 rounds and 37,714 cuts, with
31.10 seconds in validation versus 3.66 seconds in SAT. The existing automatic
full-Ackermann route misses this shape only because 89,470 base clauses are
below its arbitrary 100,000-clause threshold.

The frozen candidate projection for this source is 3,686 Ackermann clauses,
9,900 chordal fill edges, at most 1,517,715 triangle visits, 38,695 variables,
and 93,156 pre-triangle clauses. These are projections, not solve or speed
evidence. Historical forced completion solved the source in roughly 0.609
seconds on Linux, while the sealed Yices2 row is roughly 0.117 seconds. T9 can
close coverage and still fail the performance objective.

## Frozen Structural Selector

`clique-auto` is eligible only when all of the following source-derived facts
hold:

- no finite-domain clauses have been emitted;
- no finite coverage or closed-table encoding exists;
- the verified disequality-clique lower bound is at least 48;
- total disequality edges exceed the clique minimum by at most eight;
- the equality graph has at least 2,500 vertices and 10,000 edges;
- there are at most 256 uninterpreted applications; and
- the actual selected SAT backend is Kissat.

Every quantity is computed before SAT and without expected-result or timing
data. The only experimental setting is strict
`EUF_VIPER_T9_ACKERMANN=off|clique-auto`; absent means `off`, and any other
value fails closed.

## Allocation-Free Plan Gate

Checked integer arithmetic must reject the route before cloning or allocating
the candidate transaction unless all projected bounds pass:

- at most 5,000 Ackermann clauses;
- at most 20,000 chordal fill edges;
- at most 2,000,000 triangle visits;
- at most 50,000 final SAT variables; and
- at most 6,000,000 added literal slots.

The plan also binds term, graph, function, arity, argument-slot,
candidate-pair, clause, literal, fill-pair, and backend counts. Materialization
must equal the accepted plan exactly. Any overflow, count divergence, backend
change, allocation failure, or unsupported sort aborts the transaction and
uses the unchanged baseline CNF; it may not partially retain completion
clauses.

## Stage 0: Full Projection Census

Run a no-solve projection over the source-verified 7,503-row manifest. Freeze
the complete selected set and every plan/rejection reason before timing.
Require:

- exactly 7,503 present rows with zero parser, hash, overflow, or planning
  errors;
- the sole 1,200-second timeout is selected;
- `frogs.1.prop1_ab_br_max` and `frogs.4.prop1_ab_br_max` are not selected;
- every QG-classification source is not selected;
- feature-off emitted CNF is byte-identical to current main; and
- projection and later materialization have zero count or cap disagreement.

The target/anti-target control is the frozen 12-Goel plus 12-QG rollback
manifest, SHA-256
`85c18f76bc4908477e906eb0706cb06724ef23ef0536112651fe75e86ff18390`.
Its scientific rollback result remains rejected; only its source identities
are reused.

## Stage 1: Correctness And Timing Falsifier

After exhaustive small-formula checks and independent code review, build one
binary exposing `off` and `clique-auto`. On one pinned WMI core, run four
balanced ABBA repeats per arm at two seconds on the frozen 24-source control
and every Stage-0-selected source. A five-second development canary may precede
this gate but cannot promote the route.

Require all of the following:

- zero wrong answers, errors, unsupported outcomes, missing rows, and
  baseline-only solves;
- correct UNSAT on the sole terminal timeout and no eligible-target coverage
  loss;
- candidate improvement over current main on every newly converted source;
- byte-identical CNF and backend selection on every nonselected source;
- nonselected anti-target p95 overhead at most `1.01`;
- no materialization count differs from its frozen projection; and
- against same-node Yices2, at least `1.05x` median and geometric speed on the
  complete selected population, with no candidate timeout that Yices2 solves.

The Yices2 gate is mandatory. A solve below two seconds or a full-coverage
count does not compensate for losing it. If Stage 1 passes, repeat the same
binary on the frozen `sample-40` and `hot-400` controls before any full-corpus
campaign.

## Promotion Boundary

T9 may enter a broad 2/60-second paired WMI campaign only after Stage 0, Rust
soundness, independent review, exact-head hosted CI, and Stage 1 all pass. A
full 1,200-second rerun is justified only after the cheaper gates improve both
coverage and selected-population Yices2 timing.

Ackermannization, chordal completion, structural routing, and bounded planning
are known ideas. The research hypothesis is their exact combination as a
transitivity-pressure escape from repeated complete-model validation. No
novelty claim is allowed until implementation survives ablations against the
100,000-clause threshold, unfilled full Ackermann, chordal-only completion, and
the rejected leaf gate, followed by a pinned prior-art review.

Related: [[2026-07-09-dynamic-ackermann-chordal]],
[[2026-07-12-flat-clause-and-budgeted-ackermann-gates]], and
[[2026-07-13-validation-pressure-rollback]].
