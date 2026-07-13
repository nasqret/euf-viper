# Validation-Pressure Eager-To-Rollback Pilot

Date: 2026-07-13

Status: standalone default-off engineering control implemented and published;
eager-to-rollback migration not implemented; no timing or novelty claim

## Measured Problem

The hard Goel path is dominated by repeated complete-model checking rather
than SAT search. Existing profile evidence includes `frogs.3`, where
congruence validation costs about 19.2 seconds versus 2.1 seconds in CaDiCaL,
and `hanoi.3`, where validation costs about 1.5 seconds versus 0.17 seconds in
CaDiCaL. The current fallback rebuilds a solver and recomputes complete
congruence closure after every SAT model.

The first eager Kissat call already computes a total assignment and checked EUF
conflict clauses, but the current interface retains only the number of
conflicts. A later migration pilot must preserve that evidence rather than
validating the same model again. The implemented control intentionally starts
from the base Boolean CNF in a fresh CaDiCaL search, so it does not yet satisfy
this migration requirement.

## Pinned Trigger

The strict setting is:

```text
EUF_VIPER_EAGER_TO_ROLLBACK=off|force|auto
```

`off` is the default and unknown values are configuration errors. `force` is
for causal mechanism tests. `auto` migrates only after the first complete
Kissat model is invalid and

\[
  t_{\mathrm{validation}} \geq
  \max(2\ \mathrm{ms}, t_{\mathrm{first\ SAT}}).
\]

The pilot is restricted to the existing eager Kissat path, no proved finite
encoding, and no forced full Ackermannization. This is a validation-pressure
trigger. The current Kissat wrapper does not expose conflicts, LBD, learned
clauses, or trail state, so it would be inaccurate to call it a SAT
proof-pressure classifier.

## State Boundary

Preserve across migration:

- typed terms, applications, and Boolean true/false terms;
- the base CNF and stable atom-to-variable mapping;
- direct-root and accepted equality-abstraction clauses;
- the first total assignment and independently checked EUF conflict clauses.

Rebuild once:

- a fresh incremental CaDiCaL solver;
- rollback union-find without path compression;
- application use lists, exact signature tables, reversible proof edges, and
  assigned disequalities.

The first pilot observes only existing equality and Boolean-term atoms. It
emits conflicts with replayable reasons. It requests no external decisions or
propagations. A complete SAT model is still checked by the existing independent
congruence validator.

## Fail-Closed Contract

Initial caps are one million terms, applications, and observed variables; 100
million signature visits; one million explanation-edge visits per conflict;
clause width 4,096; and 10,000 external conflicts. Arithmetic is checked and
allocation is fallible.

Overflow, allocation failure, callback-order violation, panic, malformed
literal, duplicate no-progress conflict, cap exhaustion, interruption, or
model mismatch fails the explicit standalone backend closed as `unsupported`.
It never silently falls through to another backend. A future automatic
migration path may restart the existing fallback from its original CNF, but
that behavior is not implemented. None of these failures can become a SAT or
UNSAT answer.

Every external clause must replay as an EUF consequence. Exact-path UNSAT
certification eventually records these clauses and binds them into the DRAT
manifest. Until then, the independent `certify` rerun can validate the result
but is not evidence for the exact migrated execution.

## Novelty Boundary

Rollback congruence closure, DPLL(T), IPASIR-UP, and whole-instance
eager-versus-lazy switching are established techniques. This pilot is an
engineering control against `current`, `model-cuts`, and dynamic full
Ackermannization. It is not the publication claim.

The later novelty candidate is one SAT search with stable semantic atoms and
checked bridge facts in which individual UF components migrate among eager,
rollback, and Hall/PB representations under measured pressure. That candidate
is opened only if this simpler control reduces invalid-model validation and
wins end-to-end target timing without a baseline-only solve.

## Implementation Gates

1. **Complete in isolation.** Public branch
   `research-cadical-external-propagator` at `81e0c36` vendors the pinned
   RustSAT 0.7.5 binding with CaDiCaL 2.2.1 and exposes a restricted scoped
   solve/status/abort session. External decisions and propagation return zero;
   callback panics, malformed literals/clauses, registration failures, operation
   unwind, and teardown failures are fail-closed. Vendored tests pass `19` unit,
   `11` integration, and `2` doc cases; root tests pass `222` default and `228`
   all-feature cases; hosted run `29217315701` passes. This bridge does not yet
   implement rollback closure or produce EUF explanations.
2. **Complete in isolation.** Public branch `research-rollback-euf-core` at
   `0d9ec50` implements deterministic union by size without path compression,
   rollbackable application/disequality incidence, capped causal explanations,
   and fresh-closure replay. The randomized gate covers `10,240` transitions
   and compares every term pair after each one. Root tests pass `230` default
   and `234` all-feature cases; hosted run `29217833901` passes. The core is not
   connected to the callback bridge on that prerequisite branch.
3. **Complete as a standalone control.** Public branch
   `research-rollback-propagator` at `4b60113` exposes only the explicit
   `EUF_VIPER_BACKEND=cadical-rollback` route. It loads the base Boolean CNF
   before equality abstraction, finite-domain axioms, eager congruence, or
   Ackermann completion; observes stable typed atoms; emits conflict-only EUF
   explanations through the scoped bridge; and retains the authoritative
   complete-model validator. Backend errors fail closed instead of falling
   through. Telemetry separates base loading, propagator construction, SAT
   search, assignments, levels, backtracks, checked conflicts, propagator model
   checks, final validation, and total complete validations. Root tests pass
   `241` default and `247` all-feature cases, and hosted run `29270646223`
   passes. This is integration evidence, not timing evidence or eager-state
   migration.
4. Preserve first-model timing, assignment, and conflicts with default-off
   byte-identical behavior.
5. **Harness complete; execution pending.** Branch
   `research-rollback-propagator` at `e8fb05c` freezes the 12 exact
   Goel/GRAPH targets from the opportunity atlas and selects six SAT plus six
   UNSAT non-Goel anti-targets by a source-hash-bound deterministic rank. One
   immutable binary runs complete ABBA blocks against `current`, `model-cuts`,
   and dynamic completion. Journals are canonical hash chains; every source,
   environment, binary, CPU affinity, comparison, shard, and observation is
   rebound by the independent auditor. The WMI prepare/array/audit chain and
   interrupted-submission receipts are implemented and hermetically tested;
   hosted run `29272420042` passes. No timing result exists because WMI SSH is
   unavailable.
6. Require, independently for every comparison, at least two completed
   multi-round targets, fewer complete model validations on every such target,
   checked rollback conflicts on every such target, zero wrong answers or
   execution errors, no baseline-only solve, candidate coverage at least the
   baseline, target geometric speedup at least `1.10x`, and anti-target p95
   overhead at most `1.10x`. A missing population rejects rather than passing
   vacuously.
7. Replay every emitted conflict independently before broad timing. The
   standalone backend performs that replay now; the pending campaign must
   demonstrate nonzero checked conflict telemetry on every qualifying target.
