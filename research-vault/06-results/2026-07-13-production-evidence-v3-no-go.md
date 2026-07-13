# Production Evidence Schema V3: Qualified NO-GO

Date: 2026-07-13

Reviewed revision: `578deb8c228b212703bf6473e820170f40c1864c`

Decision: retain the design, but do not merge this branch or use it for a
performance or coverage claim.

## What Passed

Schema v3 closes the substantive schema-v2 acceptance holes under its frozen
SAT-only mode. The independent checker reconstructs source/config-derived CNF,
the exact variable and atom namespace, static clauses, every assignment and
validation event, dynamic theory cuts, the final backend API clause stream, and
the typed source model. The primary analyzer invokes that checker before SAT
classification. Parent paths use no-follow descriptor traversal, journals are
hash framed, incomplete tails fail closed, and final shadow publication rehashes
sidecars before publishing `complete`.

Local review passed 230 Rust tests with four intentional ignores, 28 focused
production-evidence tests, and all 330 Python tests. A subsequent no-default
link was not completed because the shared local volume filled; this was an
infrastructure interruption, not a test assertion failure.

## Blocking Findings

1. The branch is not reconstructed on current main. Its merge base is
   `073118a`, while current main contains the accepted T1 source and later
   campaign controls. The branch changes nearly one thousand lines of
   `src/main.rs`; merging it directly would bypass the required current-main
   review and risks losing newer behavior.
2. `production-evidence` is added to Cargo's default features. Even with the
   evidence CLI unused, this changes dependencies, binary layout, and cold code
   without a paired no-regression timing gate. The performance candidate's
   default binary must remain unchanged until that gate passes.
3. Evidence mode is a separate certifying SAT configuration, not a certificate
   for the ordinary fast default. It disables finite-domain, equality-
   abstraction, full-Ackermann, chordal, and non-model-cut routes; direct
   congruence-closure SAT is nondecisive; every UNSAT result becomes
   `unsupported`. This is sound fail-closed behavior, but it cannot establish
   overall solver coverage or certify the existing default configuration.
4. The implementation has bounded/unit evidence only. No current-main,
   7,503-source locked shadow campaign has established zero checker failures,
   exact SAT coverage, or the serialization/publication timing cost.

## Required Repair

- reconstruct schema v3 on current main and retain every T1/parser and campaign
  control added since `073118a`;
- make `production-evidence` explicitly opt-in and verify off-mode source and
  behavior equivalence;
- state the contract as SAT-only certifying mode and reject any implication
  that it certifies the normal default or UNSAT;
- rerun all feature matrices, independent mutation tests, and a complete locked
  corpus shadow before reconsidering integration or a certifying claim;
- require a separate paired timing gate before enabling the feature in any
  performance binary.

No production-evidence result contributes to the current Z3/Yices2 comparison.
