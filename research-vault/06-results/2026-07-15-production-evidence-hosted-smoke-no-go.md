# Production Evidence Hosted Smoke: WMI No-Go

Date: 2026-07-15

## Decision

Exact research commit `b9da60ba50164fd14d9db2177c245cb4ac1cf681`
passes the hosted Linux compilation and miniature end-to-end smoke boundary.
It is not accepted for WMI, merge, benchmark evidence, or a production-path
certificate claim.

## Hosted Result

- Branch: `research-production-evidence-v3-current`.
- First exact head: `e838c1fd77d988e935903fd524273028ea75eb9b`.
- First run: `29384179332`; all stages through the combined release and CLI
  check passed, then the negative smoke used the wrong expected exit code.
- Repair: `b9da60b`; require exit 1 and the exact semantic status-mismatch
  diagnostic when unsupported UNSAT evidence is falsely requested as SAT.
- Passing run: `29384633378`, `5m43s`.
- Passing scope: default, no-default, certificate-only, production-evidence-
  only, combined, all-feature, exact combined release, real comparator install,
  ordinary CLI, and recorder/checker/runner/analyzer smoke.

## Independent Blockers

1. Preparation records the hashes it later asks shards to trust; no external
   expected prepare-receipt SHA is supplied to dependent jobs.
2. Source is checked before and after Cargo, and binaries are checked before
   pathname execution, but neither check binds the exact bytes consumed.
3. Python and Rust publication can return after a final pathname replacement;
   cleanup is not always tied to the published inode.
4. Dynamic loaders, shared libraries, native compiler subprocesses, Cargo
   registry inputs, and Z3's `libz3` are outside the runtime manifest.
5. The `f8d9205` CLI expectations are stored in the candidate checkout instead
   of produced by an independently checked-out and built baseline.
6. Zero-work instrumentation is strong but test-only; no accepted release
   allocation/timing differential exists.

## Required V4 Shape

- Separate prepare from array submission and capture the receipt hash outside
  the campaign worktree before releasing dependents.
- Build from an enforceably read-only attempt-private source snapshot and bind
  its embedded manifest.
- Execute checked artifacts through stable descriptors or fail closed.
- Record the complete loader/library/native-toolchain/Cargo execution closure.
- Verify final published path identity after directory synchronization and use
  inode-owned cleanup.
- Build and run `f8d9205` independently for CLI and off-mode differentials.

No WMI job or corpus run used this branch.
