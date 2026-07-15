# T1 Typed Parser Causal Timing Gate

## Decision Boundary

The 7,503-source parity campaign accepted the typed streaming parser as a
semantic candidate. It did not measure speed. This gate isolates the next
question: when the parser is the only changed component, does the stream arm
improve both parsing and parser-inclusive solving without moving the tail?

The production `solve` command remains tree-parsed. The only new Rust surface
is the research command:

```text
euf-viper research-parser-timing --parser tree|stream \
  --phase parse|end-to-end -
```

It accepts standard input only. It reads that input before starting the clock,
selects one parser explicitly, and emits one canonical JSON observation. Both
timed arms call the production `Problem`-producing parser path and never clone
symbol telemetry. Before timing, a separate `research-parser-semantics` process
attests each arm with exact structural counters and SHA-256 over an explicit
length-prefixed canonical encoding of the complete typed snapshot. There is no
environment selector and no fallback.

## Frozen Experiment

The machine contract is
`campaigns/t1-typed-parser-timing-v1.json`. It freezes:

- baseline `tree`, candidate `stream`;
- phases `parse` and `end_to_end`;
- order `tree, stream, stream, tree` for every source and round;
- one warmup and five measured rounds;
- a fresh process and two-second timeout for every observation;
- exact `source_count=7503`, 128 deterministic shards, at most 32 concurrent
  shards, and no timing-repetition dimension or contract-dimension override;
- accepted parity manifest SHA-256
  `32aba287e33c5665847f0a0a71311da6214feb5e69f458877ba02ef96976a2d4`
  and the hash-bound local parity decision receipt plus every frozen artifact
  named by that receipt; and
- strict promotion thresholds before any measurement exists.

The array harness opens each source once with `O_NOFOLLOW`, verifies its inode,
bytes, length, and SHA-256 against prepare, and retains that byte buffer. Every
fresh process receives the same buffer through stdin. The timing binary is
opened and hashed once and, on Linux, executed through its inherited descriptor.
This removes source pathname lookup and mutable source rereads from the arm
comparison. The submitter fixes `cpu_idle`, node `c1n1`, one physical core per
task, no SMT thread, and core affinity. A worker rejects a multi-CPU affinity set
instead of selecting one after allocation. Children inherit that singleton
affinity.

For round (i), let positions (0,3) be tree and (1,2) be stream. The two
within-round candidate/baseline ratios are

\[
r_{i,1}=\frac{t_{i,1}}{t_{i,0}}, \qquad
r_{i,2}=\frac{t_{i,2}}{t_{i,3}}.
\]

This pairing reverses local order in the second half of ABBA. Across all common
sources and measured pairs, the paired statistic is

\[
R_{\mathrm{pair}}=
\exp\!\left(\frac{1}{N}\sum_{j=1}^{N}\log r_j\right).
\]

For source (s), let (m_{s,A}) and (m_{s,B}) be arm medians. The aggregate
ratio is

\[
R_{\mathrm{agg}}=
\frac{\sum_s m_{s,B}}{\sum_s m_{s,A}}.
\]

Every source contributes the nonnegative overhead

\[
o_s=\max(m_{s,B}/m_{s,A}-1,0).
\]

The tail statistic is the ceiling nearest-rank p95 over all 7,503 values
(o_s), including zero-overhead wins. Its population therefore cannot be empty
or selected after observing results. Warmups never enter these statistics.

## Acceptance Contract

Both phases must satisfy all of the following simultaneously:

1. (R_{\mathrm{agg}} < 1).
2. (R_{\mathrm{pair}} < 1).
3. All-source p95 nonnegative overhead is strictly below (0.01).

In addition:

- both phases have exactly 7,503 common sources and every observation completes
  without timeout or error;
- exact semantic counters and canonical SHA-256 match before timing for each
  source;
- every solve result and its canonical SHA-256 agree exactly and every result
  matches the manifest;
- a source is counted solved by an arm only when all ten measured observations
  for that arm return the expected decisive result;
- no source may be solved only by tree; a candidate solve elsewhere cannot
  compensate for a source-level loss; and
- malformed output, duplicate/missing/reordered observations, identity drift,
  or non-finite JSON rejects the campaign.

Every timing observation and semantic attestation stores lossless base64 stdout
and stderr, SHA-256 over those exact bytes, and the parsed object. Validation
decodes and hashes the raw bytes, parses only those bytes with strict JSON, and
requires object equality. Changing `elapsed_ns`, semantic counters, or a
canonical digest without changing the captured process output therefore fails.
The harness aborts when either output stream exceeds its exact-capture bound;
it never stores a prefix and labels it as complete output.

The audit reports SAT, UNSAT, and family strata. It also reports per-process
maximum RSS from `wait4`, timing wins/ties/losses, common-source counts, timeout
counts, and every shard's worker identity.

## Evidence Chain

`scripts/bench/typed_parser_timing.py` owns strict prepare, run-shard, and audit
artifacts. JSON readers reject duplicate keys, symbolic non-finite values, and
finite-syntax overflow such as `1e999`. Artifacts are written mode `0400` to a
checked temporary inode, fsynced, then hard-linked to an absent destination; no
phase replaces an existing artifact. At shard close, the worker publishes raw
records and then a separate no-replace receipt containing the records SHA-256,
record count, worker digest, and domain-separated SHA-256 record-chain head.
The global audit first consumes those preexisting receipts, seals the exact shard
directory inventory read-only, and publishes a no-replace shard-set receipt
before metrics. It revalidates that anchored set before metrics and again after
analysis, before publishing the audit result. Self-consistent post-close rewrites
of raw output, parsed timing fields, semantic counters, record chains, and shard
receipts therefore differ from the anchored shard set and reject.

The WMI wrappers independently verify:

- the exact 40-hex HEAD and its published origin ref;
- a fresh unique checkout with a clean index and no tracked, untracked, or
  ignored state, hidden index flags, Cargo configuration, Python path injection,
  compiler wrappers, or ambient contract/manifest selectors;
- a private `git archive` snapshot of the exact revision, with Cargo home and
  target outside it; a recursive inotify monitor is ready before the pre-build
  all-blob inventory and rejects every create, write, attribute, move, or delete
  event through the repeated post-build inventory;
- raw Git blob, SHA-256, size, and executable-mode equality for every tracked
  source file before and after the locked release build;
- Cargo runs from `/` with a fresh private `CARGO_HOME` and an explicit rejection
  of root Cargo configuration, so ancestor checkout state cannot select a build;
- a separate sanitized Cargo invocation materializes `Cargo.lock` into a fresh
  versioned vendor tree, whose complete file/mode/size/SHA-256 inventory is equal
  before and after the build; a second recursive monitor starts before that
  tree's pre-build inventory and rejects transient dependency mutation; the
  release invocation uses a second fresh Cargo home and `--locked --offline`
  with that exact vendor tree, so compilation has no network-selected input;
- direct Cargo, Rust compiler, C compiler, linker, and archiver identities,
  including canonical path, bytes, SHA-256, and version; the C driver's
  `-fuse-ld=bfd` selection must resolve to that linker, and the receipt also
  binds linked libc, allocator/backend, linker flags, and final release ELF;
- canonical Python path, bytes, SHA-256, and version; and
- fixed contract, accepted-manifest, parity-receipt, and clean-checkout receipt
  hashes. Before any `sbatch`, the remote preflight verifies the accepted
  manifest bytes and all 7,503 path, source SHA-256, and byte-count bindings.

The Slurm submission additionally fixes `cpu_idle`, node `c1n1`, singleton
physical-core affinity, one hardware thread per core, and `--mem-bind=local`.
Worker evidence binds both CPU and memory policies plus the resulting NUMA node.

The submitter forms an `afterok` prepare-array-audit chain. This research branch
does not push or submit it. `.github/workflows/campaign-contract.yml` runs the
focused timing/receipt/build-guard Python tests, syntax-checks every T1
WMI/submit/common/CI script, builds the real exact locked release under source
and dependency monitors, invokes both research commands through the descriptor
harness, and runs default plus all-feature Rust runtime matrices on Linux.

## Remaining Validity Limits

- The two-second limit is now a hard acceptance condition: any timeout rejects
  the campaign rather than censoring a row. It still does not establish
  long-timeout superiority over another solver.
- Process startup is outside the Rust internal clock but maximum RSS includes
  the full process. The fixed node, physical-core binding, recorded CPU model,
  microcode, NUMA, governor, turbo/frequency, libc, allocator, and ABBA pairing
  expose rather than erase residual noise. Current-frequency values may vary.
- The first campaign is unconditionally `research-only-first-campaign` and
  nonpromotable. Missing enforced governor/fixed-frequency or exclusive-node
  control is recorded as a nonpromotion reason; it cannot silently pass a 1%
  production gate. Missing CPU, microcode, governor, turbo, or frequency-state
  identity is rejected rather than treated as an unenforced control.
- The gate concerns the exact compiled revision, default solver configuration,
  and frozen corpus. It does not prove benefit in incremental SMT workloads.
- A timing pass remains research-only evidence and permits a separately reviewed
  replication with enforceable controls. It does not change production routing.
