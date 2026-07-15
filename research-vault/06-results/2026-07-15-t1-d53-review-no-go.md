# T1 d53b32b Review: Scheduler And Build Evidence No-Go

Date: 2026-07-15

## Decision

Exact commit `d53b32b6ee45406c4d72cc10a6c641ebeabf196d` is published on
`research-typed-parser-timing` only as a diagnostic reproducer. Independent
review permits no qualifying hosted evidence, WMI canary, full timing, merge,
or promotion. No T1 cluster job was submitted.

## Confirmed

- Canary mode is exactly shard `0` with throttle one and no audit; full mode is
  exactly 128 shards with throttle one and a full-only audit.
- A canary-labeled 128-shard result cannot reach `research_only_pass`.
- ABBA pairing, per-source medians, log-geometric mean, nearest-rank p95,
  population parity, and timeout/error gates are arithmetically consistent.
- Default Rust passed 239 tests; all features passed 245. The exact hosted
  Python set passed 266 with six Linux-only tests skipped. Focused T1 passed 61
  with the same six skips. Shell syntax and diff checks passed.

## Blocking Findings

1. Held and released receipts observe only a subset of Slurm state. Partition,
   node, CPU, memory, frequency, controller, and cluster fields are copied from
   requests. Wrong partition/nodelist, an unrelated array-task ID, and a
   one-of-64-CPU `whole_node_control=true` claim were accepted.
2. Directory identity is closed before inotify attaches by pathname, without a
   no-follow attachment or snapshot-parent watch. A root swap can scan one inode
   and monitor another.
3. Hosted and remote builds do not explicitly bind Rust/Cargo 1.96. Static
   target flags apply beyond the final executable. Cargo, rustc, compiler,
   linker, and archiver are hashed and later executed by pathname, permitting a
   replace-and-restore gap.
4. Interrupted shard publication leaves a partial directory that cannot resume.
   The submitter does not durably retain released or cancelled terminal state.

## Required Repair

Capture and verify complete held/released `scontrol` state, bind array master and
task identities plus throttle, compare allocation with observed physical cores,
attach descriptor-safe no-follow watches, pin immutable Rust/Cargo 1.96 and
final-link-only flags, execute sealed tool bytes, and make publication
transactional and resumable with terminal receipts. Repeat independent review
before any hosted qualification or WMI action.

## Hosted Diagnostic

Exact-head run `29398685115` completed campaign validation and built the guarded
release in 1m48s. It then failed with `guarded T1 release must not contain
DT_NEEDED entries`; the root Rust test step was skipped. This confirms that the
final executable closure is not static and does not alter the WMI no-go.
