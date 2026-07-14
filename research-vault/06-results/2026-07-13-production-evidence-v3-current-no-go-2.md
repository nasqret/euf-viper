# Production Evidence V3 Current-Main Review 2: NO-GO

Date: 2026-07-13

Reviewed revision: `939bc60715ecf7f089a904c6db073cad261a44ba`

Decision: do not publish the research branch and do not submit a WMI evidence
campaign.

## What Passed

The repair keeps `certificates` and `production-evidence` as separate Cargo
features while requesting both in locked preparation. It probes the compiled
feature report, guards the evidence allocations found by source inspection,
keeps UNSAT nondecisive, and preserves the independent CNF, transcript, model,
and analyzer gates. All 78 focused non-Rust review tests passed. Local Rust
matrices remained unexecuted because dependency builds exhausted the shared
volume.

## Blocking Findings

1. The WMI submitter reused a revision-keyed checkout, exported the ambient
   submission environment, and allowed untracked/ignored files. Cargo config,
   Python startup modules, wrappers, flags, or build helpers could therefore
   influence compilation or checking without changing the recorded revision.
2. Ordinary no-evidence output was not byte-compatible with checkpoint
   `f8d9205`. The no-argument and help usage text exposed new evidence lines,
   while the compatibility test checked only a successful result class rather
   than exact stdout, stderr, and exit code across all legacy cases.
3. Zero evidence-only work was tested only on one SAT happy path per backend.
   UNSAT, contradiction, refinement, invalid model, interruption/limit,
   unavailable backend, unsupported, and error exits were not covered.
4. No test ran the exact release binary built with
   `certificates,production-evidence` through recorder, SAT emission and
   independent checking, UNSAT fail-closed handling, locked runner/analyzer,
   filesystem races, and the ordinary CLI differential. Feature reporting by
   a real binary and separate debug smokes do not establish that composition.

## Required Repair

- use a private attempt-specific checkout/result namespace, reject every
  tracked, untracked, or ignored execution influence, and export an explicit
  receipt-bound environment allowlist;
- compare exact ordinary stdout, stderr, and exit code with `f8d9205` for help,
  missing/extra/unknown arguments, stdin/file success, parse failure, and I/O
  failure whenever `--evidence-out` is absent;
- instrument and test zero evidence-only work on every solver exit path;
- encode all default/no-default/feature combinations in hosted CI and run the
  exact combined release through the complete miniature evidence pipeline;
- require another independent review and a one-instance Linux canary before
  any corpus submission.
