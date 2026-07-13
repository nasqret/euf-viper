# T5 Evidence Review: NO-GO 3

Date: 2026-07-13

Reviewed revision: `64770d8cf43c666421f69f78c7ede125b402d829`

Decision: do not push or submit the component-quotient source census to WMI.

## What Passed

All eight runtime/import files had ordinary index state, exact `HEAD` blob
identity, and exact executable modes. The checkout guard rejects hidden index
flags and checks the complete runtime import set. Captured-byte semantic
reconstruction, canonical JSON, all source/record/target/aggregate invariants,
standalone-receipt equality, and canonical Python identity passed review. All
71 focused regressions, shell syntax checks, and direct Python compilation
passed.

## Blocking Findings

1. The finalizer checks a staging descriptor but creates a different inode at
   the final pathname and then copies bytes into it. A concurrent observer can
   see a zero-length or partial archive before the destination is checked. This
   is neither atomic publication nor publication of the checked inode.
2. The batch wrapper invalidates `.current` and installs cleanup only after
   checkout, Python, corpus, manifest, and lock preflights. An early failure can
   therefore leave an older successful attempt marked current.
3. The wrapper claims ownership after a pathname-absence check. If another
   process creates the path before the finalizer's exclusive open, failure
   cleanup can delete a bundle that this attempt did not create.

## Required Repair

- publish the fully written and descriptor-checked staging inode with an atomic
  no-replace operation while the final pathname remains absent;
- invalidate and fsync `.current`, then install cleanup, before every
  failure-prone preflight;
- remove pathname ownership inferred from a prior absence check, and permit
  deletion only for an inode atomically published by the current attempt;
- add deterministic tests for partial-path visibility, early preflight failure
  with an old marker, and destination-creation races.

The branch remains isolated. A fresh independent review is required after the
repair and before any public branch or WMI action.
