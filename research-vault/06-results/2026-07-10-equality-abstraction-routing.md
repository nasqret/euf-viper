# Equality Abstraction Routing

Date: 2026-07-10

Status: rejected. A path-independent guarded-disequality route passed the
historical analysis folds and its original 55-instance population gate, but
its actual routed implementation lost every speed metric after the scoped-let
baseline was promoted. It remains default-off and did not advance to hot-path
or complete-corpus gates.

## Soundness Boundary

The abstraction computes equalities common to Boolean branches by partition
meet and join. Every emitted edge is a logical consequence of the original
assertions. Fact insertion adds a positive unit only when the equality atom was
already materialized by the initial Boolean CNF; fresh atoms are disabled for
the routed mode. SAT answers still pass complete EUF model validation.

The selector is not an inference rule. A false positive can cost time but does
not change satisfiability; a false negative only omits valid strengthening.

## Frozen Build

- Source commit: `dafb853`.
- WMI binary SHA-256:
  `c9e475fe6b09fe7425e0cf44bac1afc1f47881cb24ad9c471cbd07d94afa8c04`.
- Fact configuration: existing atoms only, fresh atoms off, total quota 4,096,
  fresh quota 256.
- Linux invalid-model fallback: promoted `cadical-refine` configuration.

## Complete Shadow Telemetry

Corrected WMI jobs `142801`/`142803` profiled all 7,503 corpus instances:

| Metric | Value |
| --- | ---: |
| Applicable formulas | 7,401 |
| Formulas with star edges | 4,610 |
| Total star edges | 327,816 |
| Capped analyses | 82 |
| Infeasible abstractions | 1 |
| Profiles recovered despite solver timeout | 203 |
| Missing profiles | 0 |
| Analysis / successful solver time | 1.456% |

This overhead is too large for unconditional head-path activation.

## Rejected Broad Modes

Same-binary production sample gate `142898` kept coverage 37/37 but facts lost
every speed criterion: all-total 0.9879x, common-total 0.9763x, and geometric
0.9337x.

The 445-case hard-hit gate `142899`/`142907` added 18 solves with no losses and
improved timeout-charged total 1.0291x. Broad activation still failed
common-total at 0.9898x and geometric speed at 0.9781x, so it is rejected.

## Prospective Route

`scripts/bench/analyze_eq_fact_routes.py` joined the frozen hard-hit A/B data,
equality shadow metrics, and finite structural telemetry. Predicates were
restricted to pre-SAT numeric structure; family, path, basename, expected
status, and solver outcomes were forbidden as route features.

The simplest high-ranked predicate was:

\[
\texttt{guarded\_disequality\_clauses} > 0.
\]

On the 445-case development set it selected 41 cases, added 11 solves, and
projected 1.0237x all-total, 1.0068x common-total, and 1.0043x geometric speed.
Every one of five stable source-hash folds preserved coverage and passed all
three speed criteria.

Frozen corpus telemetry selects exactly 55/7,503 instances (0.733%). The
selection is stored in:

- `results/eq-abstraction-guarded55.jsonl`;
- `results/eq-abstraction-guarded55-remote.jsonl`.

## Repeated Full-Population Gate

WMI array `142947` and strict merge `142951` tested every one of the 55 selected
instances, five repeats per arm, with the same binary and only
`EUF_VIPER_EQ_ABSTRACTION=off|facts` changed:

| Coverage | All-total | Common-total | Geometric | Baseline wins | Candidate wins |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 18 -> 29 | 1.2086x | 1.4738x | 1.4191x | 10 | 8 |

There were 11 candidate-only solves, no baseline-only solves, wrong answers, or
execution errors. This validates the selector population, not yet the runtime
cost of computing the selector on all other inputs.

## Implementation Contract

The experimental mode is `EUF_VIPER_EQ_ABSTRACTION=guarded-facts`. It must:

1. use the exact verified guarded-disequality recognizer;
2. skip equality abstraction entirely on unselected formulas;
3. insert facts before finite-domain atoms are materialized;
4. force fresh equality atoms off;
5. reuse cached finite analysis rather than duplicating expensive work;
6. remain non-default until sample, guarded55, hot-400, and complete-corpus
   same-binary gates all pass.

## Actual Routed Build

Commit `cce247b` implements the contract with a lazy shared finite-analysis
context. A structural scan first rejects formulas that cannot contain the
guarded pattern. Only the remaining formulas compute the exact verified
guarded-clause count, and equality abstraction runs only when that count is
positive. Fact integration precedes finite-domain atom materialization, and
the routed mode forcibly disables fresh atoms.

The frozen WMI binary SHA-256 is
`d26631dec1cd5c6df2c5f145e7d5597ac630cdf427e0eb80ca7ba7508eb31881`.
Rust all-feature release tests pass 96/96 and the campaign-analysis suite
passes 38/38.

Five-repeat same-binary sample gate `143160` changed only
`EUF_VIPER_EQ_ABSTRACTION=off|guarded-facts`:

| Coverage | All-total | Common-total | Geometric | Baseline wins | Candidate wins |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 37 -> 37 | 1.0006x | 1.0012x | 1.0018x | 16 | 21 |

There were no one-sided solves, wrong answers, or execution errors. The margin
is narrow but passes the predeclared sample boundary; it is not sufficient for
promotion by itself.

The next five-repeat gate `143161` reran all 55 structurally selected cases on
the current baseline:

| Coverage | All-total | Common-total | Geometric | Baseline wins | Candidate wins |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 29 -> 29 | 0.9960x | 0.9852x | 0.9816x | 27 | 2 |

There were no one-sided solves, wrong answers, or execution errors. All 11
instances that had been candidate-only in the earlier `off|facts` gate are now
solved by the baseline. The intervening scoped-let promotion captured those
gains, leaving only equality-analysis overhead. This is a direct example of
why candidates are rebased and remeasured rather than stacking projected
wins.

## Artifacts

- Shadow telemetry: `results/wmi/eq-abstraction-shadow-142801/`.
- Production sample: `results/wmi/eq-abstraction-production-sample40-142898/`.
- Production hard hits:
  `results/wmi/eq-abstraction-production-hard-hits-142899/`.
- Route analysis:
  `results/wmi/eq-abstraction-production-hard-hits-142899/route-analysis.json`.
- Repeated selector population:
  `results/wmi/eq-abstraction-guarded55-142947/`.
- Actual routed sample:
  `results/wmi/eq-abstraction-guarded-mode-sample40-143160/`.
- Actual routed selected population:
  `results/wmi/eq-abstraction-guarded-mode-guarded55-143161/`.

## Decision

Reject both broad `facts` and the current `guarded-facts` route. Keep the
implementation default-off for controlled research, but do not spend hot-400
or complete-corpus resources on a candidate that already fails its selected
population. Any future equality-fact route needs a newly frozen population
with gains not already supplied by scoped parsing. Do not infer a Z3 or Yices2
victory from the historical within-solver gate.
