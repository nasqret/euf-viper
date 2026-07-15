# T1 Parser Timing Gate

The typed streaming parser has full semantic-parity evidence, but parity alone
does not establish speed. The frozen
[`t1-typed-parser-timing-v1.json`](../../campaigns/t1-typed-parser-timing-v1.json)
contract measures the authoritative tree parser against the stream candidate in
one compiled binary. Production solving continues to select the tree parser.

## Isolated Observation

The benchmark-only command is:

```console
euf-viper research-parser-timing \
  --parser tree|stream --phase parse|end-to-end -
```

It accepts only stdin. Source reading finishes before the internal timer. Both
arms time the production `Problem`-producing parser path, and the timed code
cannot call symbol-cloning telemetry. A separate untimed command attests exact
semantic counters and SHA-256 over a canonical complete typed snapshot before
any row is admitted. Thus the causal arm is the parser implementation, not file
I/O, telemetry, solver options, or result formatting.

The harness opens a source once, verifies the prepared SHA-256 and byte count,
and replays that immutable buffer to fresh processes. Exact base64 stdout and
stderr, their SHA-256 digests, and the parsed payload are retained for every
timing and semantic process. Audit parses only the decoded captured bytes and
requires equality with the stored object. Output beyond the exact-capture limit
aborts the shard; it is never truncated and represented as complete evidence.
Each source uses one
warmup and five measured rounds in the fixed order

\[
A, B, B, A,
\]

where (A) is tree and (B) is stream. The two ratios in round (i) are

\[
r_{i,1}=t_{i,B_1}/t_{i,A_1}, \qquad
r_{i,2}=t_{i,B_2}/t_{i,A_2}.
\]

The paired estimate is the geometric mean

\[
R_{\mathrm{pair}}
=\exp\left(\frac{1}{N}\sum_{j=1}^{N}\log r_j\right).
\]

For source medians (m_{s,A}) and (m_{s,B}), the aggregate estimate is

\[
R_{\mathrm{agg}}
=\frac{\sum_s m_{s,B}}{\sum_s m_{s,A}}.
\]

## Gates

Both parse and end-to-end phases must have
(R_{\mathrm{pair}}<1) and (R_{\mathrm{agg}}<1). The ceiling nearest-rank p95
of

\[
\max(m_{s,B}/m_{s,A}-1,0)
\]

over all 7,503 preregistered sources must be strictly below (1\%\). The tail
population is fixed and cannot be empty.

The performance tests are conjunctive with semantic tests:

- exact `source_count=7503`, 128 deterministic shards, `max_parallel=1`, one
  warmup, five measured rounds, two-second timeout, and
  `tree,stream,stream,tree` order are immutable; 128 is not a repetition count;
- every observation completes, so both phases have exactly 7,503 common rows;
- exact semantic counters and canonical SHA-256 agree before timing;
- solver output and its canonical SHA-256 agree between arms;
- every decisive result matches the manifest;
- no baseline-only solve exists at any source; and
- no malformed, duplicate, missing, reordered, non-finite, or identity-drifted
  evidence is accepted.

A source counts as solved by an arm only if every measured end-to-end
observation for that arm returns the expected SAT or UNSAT answer. One timeout
or error rejects the campaign; no source is censored from speed metrics. The
audit reports SAT/UNSAT and family strata, paired wins/ties/losses, and maximum
RSS.

## Reproducibility

The submitter accepts exactly one explicit mode, `--canary` or `--full`, and
creates a unique fresh checkout. Remote host, published ref, campaign parent,
and generated tag are fixed by checked-in code; the former `EUF_VIPER_*`
selectors are rejected rather than read or silently cleared. The immutable contract binds the
accepted parity manifest SHA-256, locally frozen decision receipt, and every
frozen evidence artifact named by that receipt; before any job submission, the
remote preflight rehashes all 7,503 manifest paths and source files. Prepare
rejects tracked, untracked, ignored, hidden-index, Cargo-config,
Python-shadow, compiler-wrapper, and ambient-selector influences. Every Slurm
wrapper starts in an absolute `--chdir` root and validates its canonical path,
exact HEAD, origin ref, and common-helper Git blob before sourcing that helper
through its already-open descriptor. Root, revision, ref, mode, and bound hashes are positional job arguments,
not ambient environment selectors. `SLURM_SUBMIT_DIR` is never used. Prepare
extracts a private exact-revision
source snapshot and starts a recursive Linux mutation monitor
before the pre-build all-blob inventory, and keeps Cargo homes, dependencies,
and target outside the watched tree. Under a sanitized environment, Cargo first
materializes the locked registry dependency set into a fresh versioned vendor
tree. That tree receives exact pre/post file, mode, size, and SHA-256 inventory
receipts, and a second recursive monitor publishes canonical, nonempty,
PID/root-bound readiness only after all watches are installed and before its pre-build
inventory. The release compile then runs from `/` with a separate fresh Cargo
home, `--locked --offline`, an explicit vendor source replacement, and no
network. Any source or dependency create, write, attribute, move, or delete
event rejects the build even if bytes are restored before the repeated
post-build inventory. Readiness is a canonical, nonempty artifact bound to the
monitor PID, parent PID, watched root, watch count, and mask after watch setup.
Monitor shutdown is EOF on a parent-owned pipe opened
through a mode-`0600` FIFO and then unlinked; creating a sentinel pathname cannot
end it. A watchdog proves both monitor processes remain non-zombie children for
the entire compiler lifetime, and every non-owner child closes the control and
evidence descriptors before execution. Both readiness artifacts, inventories,
event logs, monitor receipts, the build receipt, and the built executable remain
open by descriptor across monitor closure. The guard and timing harness were
also opened and Git-blob checked before monitoring; post-monitor execution uses
their `/proc/self/fd` names, so replacing their checkout pathnames cannot select
new code.

The guarded build receipt binds Python, Cargo, Rust, the native C compiler,
the exact linker selected by that driver, archiver, allocator/backend, linker
flags, and final release bytes. The release is compiled with `+crt-static` and
is rejected unless independent ELF inspections prove zero `PT_INTERP` and zero
`DT_NEEDED`; the campaign makes no hand-written dynamic-loader-closure claim.
Linux observations execute the same descriptor whose bytes were attested. WMI placement
is fixed to `cpu_idle` and `c1n1`, one non-SMT physical core and Slurm-local NUMA
memory placement per task. Full mode serializes all 128 array elements with
`0-127%1`; each element requests the sole allowed node exclusively and runs the
shard step with `--cpu-freq=high:UserSpace`. The worker must prove a
whole-node CPU allocation, singleton affinity, a propagated Slurm frequency
request, and fixed userspace governor bounds or fail before recording timing evidence. The
bounded canary schedules only shard 0 and never submits the complete audit.
Both modes are permanently nonpromotable research evidence.

All JSON is duplicate-key rejecting and finite. A value such as `1e999` is
rejected after parsing even though its syntax is standard JSON. Generated
artifacts use checked-inode, fsynced, mode-`0400`, atomic no-replace publication.
Each shard closes with a pre-audit receipt binding its exact raw records, count,
worker, and SHA-256 chain. Audit seals the shard directory, publishes a separate
no-replace shard-set receipt before metrics, and revalidates every receipt and
records file both before metrics and after analysis. Full WMI jobs form a
prepare-array-audit `afterok` chain; canary mode forms only prepare plus one array
task. Hosted Linux CI reproduces the monitored exact locked release,
executes the real Rust ELF through the descriptor harness, and runs default and
all-feature Rust runtime matrices.

No WMI measurement belongs to this implementation commit. Every campaign is
unconditionally research-only and permanently nonpromotable. Noncompliant or canary evidence
cannot acquire a complete audit, and the audit schema still requires
`promotable=false`. A pass
would justify a separately reviewed experiment, not production routing and not a claim
against Z3, Yices2, or cvc5.
