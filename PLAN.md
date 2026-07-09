# Plan

## Objective

Build a fast-head, certifying Rust QF_UF solver and benchmark campaign that can
make reproducible comparisons against Z3, cvc5, and Yices2, then serve as the
front tier of a coverage-oriented portfolio.

## Milestones

- [x] Create Rust project scaffold in `/Users/airbartek/codex/z3`.
- [x] Implement a strict QF_UF ground-conjunction parser and congruence-closure
  verifier.
- [x] Add generated synthetic benchmark families.
- [x] Add durable memory, journal, Obsidian vault, Jupyter Book, and CAS
  artifact scaffold.
- [x] Install local Z3 comparator and run small canary comparisons.
- [x] Run first WMI synthetic benchmark job.
- [x] Run Magma artifact on LTS.
- [x] Add a DPLL(T) layer for arbitrary Boolean structure.
- [x] Add diamond/common-consequence preprocessing for QF_UF disjunctions.
- [x] Add branch-aware positive-`or` pruning against surrounding disequalities.
- [x] Add repeated median Z3 comparator for cold-start-resistant local timing.
- [x] Integrate SAT backends through RustSAT plus a Linux Kissat bridge.
- [x] Install or build cvc5 comparator in a reproducible environment.
- [x] Download SMT-LIB QF_UF benchmark release and build a full corpus manifest.
- [x] Run WMI cluster campaign with fixed timeout, memory, and artifact logs.
- [x] Expand `euf-viper` beyond one solved official eq-diamond sample instance.
- [x] Run the full 7,503-instance QF_UF corpus at a fixed two-second budget.
- [x] Add per-instance A/B comparison and structural manifest filtering.
- [x] Add pinned Yices 2.7.0 to every comparator schema and solver log.
- [x] Run the full four-solver corpus at a fixed two-second budget.
- [x] Add restartable SLURM array sharding with strict complete-result merging.
- [x] Run the full corpus at 60 seconds per solver.
- [x] Run a competition-budget campaign using sharded SLURM jobs.
- [x] Quantify family balance and report QG versus non-QG results separately.
- [x] Emit exact DIMACS plus SAT proof traces for UNSAT eager runs.
- [x] Check SAT proofs independently and replay EUF-derived axiom manifests.
- [ ] Independently reconstruct the base Tseitin CNF from SMT-LIB input.
- [x] Route invalid eager SAT models through measured CaDiCaL lazy refinement.
- [x] Test finite-cap, finite-bypass, sequential-AMO, direct-CaDiCaL, and
  root-pigeonhole tail hypotheses under paired WMI gates; remove every
  candidate that fails coverage and speed gates.
- [x] Add an opt-in structural Yices portfolio and pass a full 7,503-instance
  coverage and aggregate-speed gate.
- [x] Add a post-validation dynamic Ackermann/chordal route and pass targeted,
  hot-path, hard-family, and full 7,503-instance paired speed/coverage gates.
- [x] Add verified finite-domain symmetry breaking, remove parser token-string
  duplication, and pass full paired gate `142412`: coverage `6,891 -> 6,898`,
  all-total `1.0059x`, common-total `1.0078x`, geometric `1.0220x`, with zero
  wrong answers or execution errors.
- [x] Confirm the coverage-changing cases with seven repeats on both WMI CPU
  architectures (`142478`, `142479`) and eliminate the apparent baseline-only
  timeout as a reproducible regression.
- [x] Add deterministic A/B opportunity analysis with coverage, family,
  timeout-neighborhood, and largest-delta reports.
- [x] Complete fresh four-solver two-second campaign `142480`/`142481`/`142482`
  using the exact promoted binary SHA-256. The solver beats cvc5 overall and
  beats Z3 by `1.111x` common-total and `2.035x` geometric speed, but trails Z3
  by 249 solves and Yices2 by 546 solves.
- [ ] Rerun the accepted standalone solver at 60 and 1,200 seconds.
- [ ] Reduce the remaining finite-model tail without regressing a full-corpus
  paired speed or coverage metric.
- [x] Run local/LTS CAS checks for the quotient-congruence artifacts.
- [ ] Publish benchmark tables only after independent checker validation.

## Acceptance Criteria For A Superiority Claim

No claim that `euf-viper` is faster than Z3 is accepted until all of the
following exist:

1. A named benchmark corpus with immutable source URLs or checksums.
2. Exact solver revisions for `euf-viper`, Z3, cvc5, and Yices2.
3. Machine, CPU, memory, timeout, and parallelism metadata.
4. Raw per-instance timing and result logs.
5. A discrepancy audit for every nonmatching `sat`, `unsat`, `unknown`, timeout,
   or crash.
6. A public reproducibility script.

The stronger claim "beats both Z3 and Yices2" additionally requires:

7. Standalone operation without invoking either comparator as a fallback.
8. Coverage at least equal to both comparators at 2, 60, and 1,200 seconds.
9. Lower timeout-charged aggregate time and lower geometric mean on common
   solved instances in two independent full-corpus runs.
10. A source-family-held-out or newly released QF_UF evaluation to rule out a
    corpus-specific router or detector.
11. Independently checked UNSAT evidence for every newly introduced
    preprocessing, symmetry, counting, or theory-propagation rule.

## 2026-07-10 Research Program

The detailed hypothesis ledger and execution order are in
`research-vault/02-design/2026-07-10-superiority-program.md`. The program has
three parallel technical fronts:

1. Remove head overhead using direct-root CNF, streaming semantic parsing,
   compact term/clause storage, SAT-boundary copy removal, and profile-guided
   code layout.
2. Change the proof system on finite tails using native finite-domain
   `AllDifferent`/Hall propagation, pseudo-Boolean explanations, and complete
   multi-table orbit canonization.
3. Replace model-level theory retries on general QF_UF with model-directed
   Ackermann cuts and, if justified, a rollback e-graph attached through
   CaDiCaL's external-propagator interface.

Every candidate remains default-off until it passes the same-binary targeted
gate, hot-path gate, hard-tail gate, and complete 7,503-instance gate. A
target-family win is evidence for routing, not evidence for promotion.

## Current Limitation

At 1,200 seconds, Yices2 is faster and complete: 7,503/7,503 correct at a
0.0278s median versus `euf-viper` at 7,478/7,503 and 0.0910s. On 7,478 common
`euf-viper`/Z3 solves, `euf-viper` has a 1.069x geometric speedup, but its hard
tail makes common-instance total time 20,668.55s versus Z3's 5,365.05s. Z3
adds 22 solves and Yices covers all 25 remaining gaps. No global superiority
claim is allowed. The opt-in Yices-dependent portfolio reaches 7,503/7,503 and
is 1.046x faster than direct Yices by paired aggregate time, but its geometric
speed is 0.8788x and the router was trained on this corpus. It is not an
independent solver victory. The accepted 2026-07-09 standalone iteration
improves the previous binary from 6,993 to 7,002 solves at two seconds while
also passing all three speed metrics. Its 60-second and 1,200-second coverage
remain unmeasured, so the older competition-budget boundary still governs.
The newer finite-symmetry/parser binary has passed a paired full-corpus gate
against its immediate predecessor and a fresh four-solver campaign. At two
seconds it solves 6,874 instances versus Z3's 7,123, cvc5's 6,831, and Yices2's
7,420. On 6,833 common euf-viper/Z3 solves it is `1.111x` faster by aggregate
and `2.035x` geometrically, but Z3's extra coverage still wins timeout-charged
total time. Yices2 remains `3.584x` faster on common aggregate time and adds
555 pairwise solves. Long-timeout campaigns remain pending, so no overall Z3
or Yices2 superiority claim is allowed.
