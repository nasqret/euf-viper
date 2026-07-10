# Base-CNF Lazy-First EUF

Date: 2026-07-10

Status: implementation candidate after the deep-let finite gate. No source
change or performance claim yet.

## Observation

At 60 seconds, the accepted binary times out on 12 Goel hardware-benchmark
instances that Z3, cvc5, and Yices2 usually solve in milliseconds to a few
seconds. Parsing is not the dominant explanation. The present `model-cuts`
CaDiCaL refinement mode avoids generating eager congruence candidates, but it
still loads all equality-transitivity clauses before its first SAT call.

The earlier automatic model-cuts gate did not test a lazy first call: the
normal eager Kissat call still ran first and could consume the whole external
timeout before refinement was reached.

## Hypothesis

For large Boolean, non-finite EUF instances, start incremental CaDiCaL with
only the Boolean/Tseitin base CNF. Omit both generic equality transitivity and
generic congruence clauses. Validate every complete SAT assignment with the
existing congruence-closure explanation engine and add only novel conflict
clauses. This re-tests classic lazy DPLL(T) using the current SAT backend and
model validator rather than the older SAT technology that motivated eager
encoding.

## Soundness Boundary

Let $B$ be the Boolean base CNF and let each learned clause $L_i$ be an EUF
consequence returned by the existing explanation engine.

- If CaDiCaL proves $B \land \bigwedge_i L_i$ unsatisfiable, the original SMT
  formula is unsatisfiable because every $L_i$ is theory-valid.
- A CaDiCaL SAT assignment is never returned directly. It is accepted only if
  full congruence closure finds no violated equality, disequality, function
  congruence, or predicate congruence.
- A repeated cut, round limit, interruption, or solver error abstains and uses
  the existing fallback. It does not become SAT or UNSAT.

The experiment changes clause timing, not the trusted validator.

## Minimal Implementation

1. Add an explicit refinement axiom-load mode with `transitivity` and `none`.
2. Keep current and model-cuts behavior byte-for-byte unchanged under their
   existing settings.
3. Add a default-off `cadical-lazy` backend that invokes model cuts with axiom
   load `none` before any eager SAT call.
4. Preserve finite-domain axioms already proved by preprocessing, but do not
   automatically route finite instances to this experiment.
5. Record SAT calls, validation calls/time, cuts generated/added/duplicate,
   cut widths, and whether transitivity or congruence was loaded eagerly.

## Correctness Tests

- Direct equality/disequality contradiction.
- Unary and multi-argument function congruence conflicts.
- Boolean predicate congruence conflicts.
- Pure equality cycles requiring transitivity.
- SAT formulas with theory-valid and theory-invalid first models.
- A round-cap result must abstain.
- Random small formulas differential-tested against both current refinement
  and Z3, including SAT and UNSAT cases.
- The CNF variable count must not grow merely to support the lazy mode.

## Performance Gates

1. **Forced Goel-12:** accepted binary versus the same source with lazy-first,
   three alternating repeats. Require no loss, no wrong answer, and all-total,
   common-total, and geometric ratios above one.
2. **Goel controls:** include nearby cases already solved quickly by the
   accepted path. Reject a route that shifts timeouts into the easy boundary.
3. **Sample 40:** require unchanged coverage and all three ratios above one.
4. **Hot 400:** require no loss and no aggregate or geometric regression.
5. **Full 7,503:** only a predeclared structural route may be enabled. Path,
   family, status, source hash, and prior outcomes are forbidden features.

The first forced gate tests the mechanism, not the route. If it succeeds, route
training uses only bounded lexical counts with source-SHA-held-out validation,
followed by an independent sample and a full measured runtime gate.

## Stop Conditions

- Any wrong answer or invalid-model acceptance.
- Any baseline-only solve in the forced mechanism gate.
- More SAT calls without lower end-to-end time on the target population.
- A structural route whose projected margin is smaller than its measured
  runtime overhead.
- Full-corpus coverage loss or any speed ratio at or below one.
