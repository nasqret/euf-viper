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
and replays that immutable buffer to fresh processes. Each source uses one
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

- exact `source_count=7503`, 128 deterministic shards, one warmup, five measured
  rounds, two-second timeout, and `tree,stream,stream,tree` order are immutable;
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

The submitter creates a unique fresh checkout. Prepare rejects tracked,
untracked, ignored, hidden-index, Cargo-config, Python-shadow, compiler-wrapper,
and ambient-selector influences. Prepare fetches into a fresh per-run Cargo
home and target under an exact allowlisted environment. Every job receives and
verifies the expected contract, manifest, and checkout-receipt SHA-256. Prepare
then binds the exact revision/tree/runtime blobs, workset, source bytes, Python,
Cargo, Rust compiler,
and final solver binary. Linux observations execute the already-hashed solver
descriptor. Each worker uses singleton CPU affinity and records its identity.

All JSON is duplicate-key rejecting and finite. A value such as `1e999` is
rejected after parsing even though its syntax is standard JSON. Generated
artifacts use checked-inode, fsynced, atomic no-replace publication. WMI jobs
form a prepare-array-audit `afterok` chain. The campaign-contract workflow runs
the focused Python tests, all T1 shell syntax checks, and the existing
all-feature Rust test on Linux.

No WMI measurement belongs to this implementation commit. Passing the future
campaign would authorize review of production routing, not automatic promotion
and not a claim against Z3, Yices2, or cvc5.
