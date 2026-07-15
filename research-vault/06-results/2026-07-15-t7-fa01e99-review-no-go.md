# T7 fa01e99 Review: Independence And Timing No-Go

Date: 2026-07-15

## Decision

Exact repair commit `fa01e995e6accdb2498dcae9d8355396571bbc0d`
remains local and nonpublishable. It fixes several first-round defects and its
bounded artifacts report three qualifying M3 sources, but independent review
demonstrated that opportunity history, certification, source identity, and the
timing gate are still forgeable or underbound. No hosted qualifying run, ABBA
canary, full panel, WMI action, merge, or performance claim is authorized.

## Verified Repairs

- Lexical `define-fun` expansion no longer lets caller `let` bindings capture
  free names.
- The terminal event's four forests, deduplication order, candidate pool,
  metrics, and selected indices can be reconstructed independently from
  source-bound active facts.
- Median computation, wall/user/system/RSS collection, singleton affinity, and
  post-timing proof production are implemented.
- The retained diagnostic artifacts validate internally as three qualifying
  sources and zero reported failures. Their binary, manifest, report-file, and
  internal-summary digests are respectively `a6b5fd46...a69f`,
  `bea69013...a657`, `1b4c5f85...66fc`, and `3265c763...5103`.

## Blocking Findings

1. Reuse history records prior selected clauses but not each prior conflict's
   complete independently reconstructible candidate pool and selection. A
   reviewer doubled and rehashed real history, adjusted counters, and the
   validator still admitted it.
2. Canary/full analysis trusts embedded certificate fields and journal
   arithmetic. Synthetic rows with nonexistent transcript paths and no offline
   certification can pass without reopening transcripts, source bytes, SAT
   models, or proofs.
3. Median groups use `manifest_index` without enforcing identical path, source
   hash, bytes, expected status, manifest membership, and transcript source
   across arms and repeats. A substituted source was accepted.
4. The aggregate instrumentation cap is arm-combined. A 9.17% off-arm
   materialization cost and zero on-arm cost manufactured a `1.101x` pass while
   the combined fraction stayed below 5%. The inclusive event timer also ends
   before all disposition, statistics, and receipt work.
5. Two qualifying M3 sources plus one timeout still produce `ready`, contrary
   to the failed-stage stop rule requiring all three controls to complete.
6. The readiness note cites ephemeral `/private/tmp` artifacts. Clean macOS
   builds differ in Mach-O UUID/signature regions, and hosted CI neither runs
   the T7 Python gate nor pins the explicit Rust toolchain.

## Reproduced Test State

- Git object verification was clean apart from pre-existing dangling objects.
- `cargo +1.96.0 test --all-features`: 258 passed, 4 ignored.
- Focused T7 Python tests: 20 passed.
- Independent QF_UF parser tests: 22 passed.
- The reviewed worktree and index remained clean.

## Required Repair

Record and independently reconstruct every prior conflict pool and selection;
reopen and verify every source, transcript, model/proof, and manifest record;
bind complete source identity across repeats; impose per-arm instrumentation
limits over equivalent work with fully inclusive accounting; fail if any M3
source fails; and retain repository-bound reproducible evidence with an exact
hosted test/toolchain contract. Repeat independent review before publication.
