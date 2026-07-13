# Rollback Control Rejected

Date: 2026-07-13

Revision: `6e402f0a9595bd3f9c1ba99ea193bf237474d9f7`

WMI: prepare `145927`, array `145928`, audit `145929`

## Decision

Reject whole-instance conflict-only rollback as a default or direct promotion
candidate. Preserve it as a labeled fixed representation for telemetry only.

The final audit intentionally exited nonzero because its scientific status was
`reject`; all 12 array shards completed successfully. The audit found zero
wrong answers, zero execution errors, no baseline-only solve, and independently
replayed conflicts on every multi-round target.

## Results

| Comparison | Baseline/candidate coverage | Candidate-only | Target geometric speedup | Anti-target p95 overhead | Gate |
| --- | ---: | ---: | ---: | ---: | --- |
| current | 15 / 23 | 8 | 7.6029x | 11.1689x | reject |
| dynamic Ackermann | 15 / 23 | 8 | 9.0741x | 32.7545x | reject |
| model cuts | 15 / 23 | 8 | 7.3178x | 23.3462x | reject |

The preregistered anti-target cap was `1.10x`. All three comparisons passed
coverage, target speed, validation-count, and conflict-replay checks, then
failed only the anti-target p95 gate.

## Interpretation

The mechanism is not broadly competitive: starting and maintaining rollback
EUF on easy finite/QG anti-targets costs one to two orders of magnitude. It is
nevertheless a strong oracle arm on validation-dominated Goel cases, converting
eight frozen baseline misses and accelerating three common targets.

This result does not authorize component migration. It authorizes only a
telemetry census asking whether target pressure can be predicted before paying
rollback setup and maintenance. M0 must remain family/lineage disjoint, below
1% p95 overhead, and stop if oracle headroom is not at least 10% or fewer than
two fixed representations remain useful.

## Evidence

- final audit file SHA-256:
  `fffb152c97aef625caf25b7c3b5373720856a2fba39b6c42a5f9b9c46e3831ff`;
- manifest SHA-256:
  `85c18f76bc4908477e906eb0706cb06724ef23ef0536112651fe75e86ff18390`;
- binary SHA-256:
  `0cff30a189d464231dabf6a893a31dc23f9a44a7d115c65ee784508597cdb4ad`;
- 576 observations, 12 journals, four repeats per arm; and
- repository artifact: `results/wmi/rollback-control-145929/`.

Related: [[2026-07-13-validation-pressure-rollback]] and
[[2026-07-13-unresolved-track-refresh]].
