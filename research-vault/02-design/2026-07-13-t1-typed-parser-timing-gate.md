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
selects one parser explicitly, and emits one canonical JSON observation. The
parse clock stops before semantic-fingerprint construction. The end-to-end
clock includes parsing and the unchanged solver, but excludes result telemetry.
There is no environment selector and no fallback.

## Frozen Experiment

The machine contract is
`campaigns/t1-typed-parser-timing-v1.json`. It freezes:

- baseline `tree`, candidate `stream`;
- phases `parse` and `end_to_end`;
- order `tree, stream, stream, tree` for every source and round;
- one warmup and five measured rounds;
- a fresh process and two-second timeout for every observation;
- 7,503 sources, 128 shards, and at most 32 concurrent shards; and
- strict promotion thresholds before any measurement exists.

The array harness opens each source once with `O_NOFOLLOW`, verifies its inode,
bytes, length, and SHA-256 against prepare, and retains that byte buffer. Every
fresh process receives the same buffer through stdin. The timing binary is
opened and hashed once and, on Linux, executed through its inherited descriptor.
This removes source pathname lookup and mutable source rereads from the arm
comparison. Each shard binds itself to the first CPU in its SLURM affinity set;
children inherit the singleton affinity.

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

A miss is a source with (m_{s,B}\ge m_{s,A}). Its overhead is
(m_{s,B}/m_{s,A}-1), and p95 is the ceiling nearest-rank quantile over misses.
Warmups never enter these statistics.

## Acceptance Contract

Both phases must satisfy all of the following simultaneously:

1. (R_{\mathrm{agg}} < 1).
2. (R_{\mathrm{pair}} < 1).
3. Miss-row p95 overhead is strictly below (0.01).

In addition:

- every measured parse observation must complete and all semantic fingerprints
  must be identical;
- every completed solve result must agree exactly, including the stable result
  fingerprint, and every decisive result must match the manifest;
- a source is counted solved by an arm only when all ten measured observations
  for that arm return the expected decisive result;
- stream solved count must not regress from tree solved count; and
- malformed output, duplicate/missing/reordered observations, identity drift,
  or non-finite JSON rejects the campaign.

The audit reports SAT, UNSAT, and family strata. It also reports per-process
maximum RSS from `wait4`, timing wins/ties/losses, common-source counts, timeout
counts, and every shard's worker identity.

## Evidence Chain

`scripts/bench/typed_parser_timing.py` owns strict prepare, run-shard, and audit
artifacts. JSON readers reject duplicate keys, symbolic non-finite values, and
finite-syntax overflow such as `1e999`. Artifacts are written to a checked
temporary inode, fsynced, then hard-linked to an absent destination; no phase
replaces an existing artifact.

The WMI wrappers independently verify:

- the exact 40-hex HEAD and its published origin ref;
- a clean index tree and no skip-worktree/assume-unchanged flags;
- raw Git blob and executable-mode equality for every T1 runtime file;
- direct Rust toolchain binaries selected by `rustup which`, including path,
  bytes, SHA-256, and version;
- canonical Python path, bytes, SHA-256, and version; and
- the final release binary and campaign tool/contract hashes.

The submitter forms an `afterok` prepare-array-audit chain. This research branch
does not push or submit it.

## Remaining Validity Limits

- Two-second per-observation censoring targets the current fast-head claim. It
  cannot establish long-timeout coverage or superiority over another solver.
- Process startup is outside the Rust internal clock but maximum RSS includes
  the full process. Kernel, allocator, frequency, and shared-node noise remain;
  ABBA and same-source pairing reduce but do not erase them.
- The gate concerns the exact compiled revision, default solver configuration,
  and frozen corpus. It does not prove benefit in incremental SMT workloads.
- Passing permits a separately reviewed production-routing experiment. It does
  not change the production default by itself.
