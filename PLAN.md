# Plan

## Objective

Build a Rust EUF/QF_UF verifier and benchmark campaign that can make a
reproducible, evidence-backed comparison against Z3 and cvc5.

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
- [ ] Add a DPLL(T) layer for arbitrary Boolean structure.
- [ ] Add diamond/common-consequence preprocessing for QF_UF disjunctions.
- [ ] Integrate an optional SAT backend or IPASIR-compatible bridge.
- [ ] Install or build cvc5 comparator in a reproducible environment.
- [ ] Download SMT-LIB QF_UF benchmark releases and select SMT-COMP slices.
- [ ] Run WMI cluster campaigns with fixed timeout, memory, and artifact logs.
- [ ] Run LTS CAS checks for the finite-model and quotient-congruence artifacts.
- [ ] Publish benchmark tables only after independent checker validation.

## Acceptance Criteria For A Superiority Claim

No claim that `euf-viper` is faster than Z3 is accepted until all of the
following exist:

1. A named benchmark corpus with immutable source URLs or checksums.
2. Exact solver revisions for `euf-viper`, Z3, and cvc5.
3. Machine, CPU, memory, timeout, and parallelism metadata.
4. Raw per-instance timing and result logs.
5. A discrepancy audit for every nonmatching `sat`, `unsat`, `unknown`, timeout,
   or crash.
6. A public reproducibility script.

## Current Limitation

The implemented solver returns `unsupported` for positive `or`, `=>`, `xor`,
and Boolean atoms because those require SAT search.  That limitation is
intentional: silent unsound answers are unacceptable.
