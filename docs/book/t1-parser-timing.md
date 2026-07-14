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

It accepts only stdin. Source reading finishes before the internal timer. A
parse observation times only construction of `Problem`; its semantic snapshot
fingerprint is computed afterward. An end-to-end observation times parser plus
the unchanged solver and computes telemetry afterward. Thus the causal arm is
the parser implementation, not file I/O, solver options, or result formatting.

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
(R_{\mathrm{pair}}<1) and (R_{\mathrm{agg}}<1). A nonbenefiting source has
(m_{s,B}\ge m_{s,A}); the ceiling nearest-rank p95 of
(m_{s,B}/m_{s,A}-1) over those sources must be strictly below (1\%\).

The performance tests are conjunctive with semantic tests:

- all measured parse observations complete with one exact semantic fingerprint;
- completed solver output and its stable fingerprint agree between arms;
- every decisive result matches the manifest;
- stream solved count does not regress; and
- no malformed, duplicate, missing, reordered, non-finite, or identity-drifted
  evidence is accepted.

A source counts as solved by an arm only if every measured end-to-end
observation for that arm returns the expected SAT or UNSAT answer. Timed-out
sources do not enter common-source speed metrics. The audit reports SAT/UNSAT
and family strata, timeout counts, paired wins/ties/losses, and maximum RSS.

## Reproducibility

Prepare binds the published Git revision, contract, manifest, workset, source
bytes, Python harness, direct Cargo and Rust compiler binaries, and final solver
binary. Linux observations execute the already-hashed solver descriptor. Each
array worker uses singleton CPU affinity and records its host, machine, CPU, and
affinity mechanism.

All JSON is duplicate-key rejecting and finite. A value such as `1e999` is
rejected after parsing even though its syntax is standard JSON. Generated
artifacts use checked-inode, fsynced, atomic no-replace publication. WMI jobs
form a prepare-array-audit `afterok` chain.

No WMI measurement belongs to this implementation commit. Passing the future
campaign would authorize review of production routing, not automatic promotion
and not a claim against Z3, Yices2, or cvc5.
