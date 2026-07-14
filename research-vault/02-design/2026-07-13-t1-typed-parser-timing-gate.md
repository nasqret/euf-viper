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
- exact `source_count=7503`, `repetitions=128` deterministic shards, at most 32
  concurrent shards, and no contract-dimension override; and
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
- a fresh unique checkout with a clean index and no tracked, untracked, or
  ignored state, hidden index flags, Cargo configuration, Python path injection,
  compiler wrappers, or ambient contract/manifest selectors; prepare also uses
  a fresh per-run Cargo home and target under an exact allowlisted environment;
- raw Git blob and executable-mode equality for every T1 runtime file;
- direct Rust toolchain binaries selected by `rustup which`, including path,
  bytes, SHA-256, and version;
- canonical Python path, bytes, SHA-256, and version; and
- caller-supplied contract, manifest, and clean-checkout receipt hashes in every
  job, plus the final release binary and exact runtime blobs.

The submitter forms an `afterok` prepare-array-audit chain. This research branch
does not push or submit it. `.github/workflows/campaign-contract.yml` runs the
focused timing/receipt Python tests, syntax-checks every T1 WMI/submit/common
script, and retains the repository's all-feature Rust test job on Linux.

## Remaining Validity Limits

- The two-second limit is now a hard acceptance condition: any timeout rejects
  the campaign rather than censoring a row. It still does not establish
  long-timeout superiority over another solver.
- Process startup is outside the Rust internal clock but maximum RSS includes
  the full process. Kernel, allocator, frequency, and shared-node noise remain;
  ABBA and same-source pairing reduce but do not erase them.
- The gate concerns the exact compiled revision, default solver configuration,
  and frozen corpus. It does not prove benefit in incremental SMT workloads.
- Passing permits a separately reviewed production-routing experiment. It does
  not change the production default by itself.
