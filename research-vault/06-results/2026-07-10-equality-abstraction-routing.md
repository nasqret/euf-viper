# Equality Abstraction Routing

Date: 2026-07-10

Status: broad fact insertion is rejected. A path-independent guarded-
disequality route passed all analysis folds and a repeated 55-instance
full-population gate. The actual routed implementation is under test and is
not default-enabled.

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

## Artifacts

- Shadow telemetry: `results/wmi/eq-abstraction-shadow-142801/`.
- Production sample: `results/wmi/eq-abstraction-production-sample40-142898/`.
- Production hard hits:
  `results/wmi/eq-abstraction-production-hard-hits-142899/`.
- Route analysis:
  `results/wmi/eq-abstraction-production-hard-hits-142899/route-analysis.json`.
- Repeated selector population:
  `results/wmi/eq-abstraction-guarded55-142947/`.

## Decision

Reject `facts` as a broad mode. Implement `guarded-facts` exactly as frozen,
then promote only if runtime routing preserves coverage and all speed metrics
through the complete corpus. Do not infer a Z3 or Yices2 victory from this
within-solver gate.
