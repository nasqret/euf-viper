# Production Evidence V3 Current-Main Review: NO-GO

Date: 2026-07-13

Reviewed revision: `d47e1c6013b46adcd9b5b2c910e35d29a3e16bae`

Decision: do not publish the research branch or start hosted/full-matrix or
corpus validation.

## What Passed

The branch is a clean linear reconstruction on current-main checkpoint
`f8d9205`. Cargo defaults and `certificates` do not imply
`production-evidence`; T1 has executable preservation tests; the checker binds
configuration and independently reconstructs CNF, variable maps, clause/event
streams, assignments, and the source model. Unsupported, UNSAT, direct
congruence-closure SAT, dirty builds, and untrusted executables remain
nondecisive. Locked runner and analyzer paths call the checker before SAT
classification. Documentation accurately limits the feature to restricted
SAT-only certification. Thirty-four focused Python tests passed in review.

## Blocking Findings

1. The locked WMI prepare builds with `--features certificates`, while the
   recorder now always requests `--evidence-out`. Because the evidence feature
   is correctly separate, the real certificates-only binary rejects that flag.
   A shell fake in the recorder test hid this impossible preparation path.
2. Ordinary solves still construct transcript vectors and duplicate backend
   clause streams even when `capture_evidence` is false. Similar bookkeeping
   occurs across Kissat, CaDiCaL, Varisat, and DPLL paths. This can change memory,
   runtime, timeout, or OOM behavior despite the feature being nominally off.
   Existing tiny/parity tests do not measure or forbid that work.
3. The new solve-argument parser rejects extra or unknown legacy arguments that
   current main previously ignored after selecting the ordinary input. That is
   an unrelated compatibility change without an approved contract or test.

## Required Repair

- explicitly build locked evidence campaigns with both `certificates` and
  `production-evidence`, while keeping the Cargo features separate;
- test preparation with a real binary and fail before submission when the
  evidence feature is absent;
- allocate and retain transcripts, clause copies, assignments, and model data
  only under `capture_evidence`, with counters proving zero off-mode work;
- preserve ordinary solve CLI behavior when `--evidence-out` is absent and
  isolate strict parsing to the new flag;
- rerun fresh independent review before branch publication.
