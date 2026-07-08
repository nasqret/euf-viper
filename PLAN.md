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

## Current Limitation

At 1,200 seconds, Yices2 is faster and complete: 7,503/7,503 correct at a
0.0278s median versus `euf-viper` at 7,478/7,503 and 0.0910s. On 7,478 common
`euf-viper`/Z3 solves, `euf-viper` has a 1.069x geometric speedup, but its hard
tail makes common-instance total time 20,668.55s versus Z3's 5,365.05s. Z3
adds 22 solves and Yices covers all 25 remaining gaps. No global superiority
claim is allowed.
