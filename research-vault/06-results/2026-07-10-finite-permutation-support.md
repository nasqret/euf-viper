# Finite Injection To Permutation Support

Date: 2026-07-10

Status: the original focused policy passed targeted, repeated, finite-family,
hot-400, and second-architecture gates but failed the full-corpus geometric
criterion. Its necessary clique-core prefilter passed the repeated 151-case
gate, then failed hot-400 and is rejected.

## Hypothesis

If `n` terms are each ranged over the same verified `n`-element domain and are
pairwise disequal, they form an injection from an `n`-element set to itself and
therefore a permutation. For every domain value `d`, the clause

\[
\bigvee_{t \in C} (t = d)
\]

is a logical consequence for every verified `n`-clique `C`. The existing
one-hot encoding already states that each term takes exactly one value and
encodes the disequalities. The new clauses add the implied column-support side
of the permutation matrix.

The rule is default-off. SAT models are still checked by complete EUF
congruence closure, and no comparator fallback is involved.

## Implementation

- Telemetry and recognizer: commit `6cdebbb`.
- Uniform support experiment: commit `1b93041`.
- Formula-structural focused policy: commit `555047d`.
- Corpus metric analyzer: commit `f2bf3b3`.
- Focused portable binary SHA-256:
  `29326f8773bfe68386b37c753041e7b55e20c1d8cc81d86be74a808b077a427d`.
- Runtime modes: `EUF_VIPER_FINITE_PERMUTATION_SUPPORT=0|all|focused`.

The focused policy fires when the formula has one closed table, or when the
guarded-disequality graph is exactly one domain-sized injection. This is a
formula metric, not a benchmark name or content hash.

Source inspection of Yices2 2.7.0 found range recognition and value-precedence
symmetry breaking, but no injection-to-permutation test, Hall matching, or dual
value-support clause generation. This is therefore not a reimplementation of
an existing Yices path.

## Controlled Results

All rows used the same binary in both arms. Only the named environment mode
changed. There were zero wrong answers and zero execution errors.

| Gate | Instances | Timeout/repeats | Coverage | All-total | Common-total | Geometric |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Uniform target `142564` | 6 | 120s / 3 | 6 -> 6 | 2.180x | 2.180x | 2.046x |
| Uniform finite `142567` | 151 | 2s / 3 | 126 -> 127 | 1.034x | 1.044x | 1.071x |
| Uniform boundary `142572` | 4 | 3s / 7 | 3 -> 4 | 1.445x | 1.074x | 1.007x |
| Focused boundary `142578` | 4 | 3s / 7 | 3 -> 4 | 1.821x | 1.449x | 1.334x |
| Focused finite `142581` | 151 | 2s / 3 | 126 -> 128 | 1.043x | 1.047x | 1.070x |
| Focused hot `142597` | 400 | 2s / 3 | 400 -> 400 | 1.006x | 1.006x | 1.001x |
| Focused full `142610` | 7,503 | 2s / 1 | 7,357 -> 7,362 | 1.012x | 1.013x | 0.997x |
| Cross-architecture boundary `142702` | 4 | 3s / 7 | 3 -> 4 | 1.807x | 1.386x | 1.337x |

The focused full finite gate had 67 candidate wins and 59 baseline wins. Its
candidate-only solves were:

- `NEQ027_size10.smt2`: repeated median about `2.68s -> 1.28s` at the 3-second
  boundary gate;
- `NEQ031_size10.smt2`: seven baseline timeouts versus seven candidate solves
  at a `0.96s` median.

The 120-second target also changed `NEQ027_size11.smt2` from `17.78s` to
`2.07s` and `PEQ011_size8.smt2` from `0.171s` to `0.140s`.

The cross-architecture boundary reproduced the NEQ gain on the second WMI CPU
class while the two excluded PEQ controls stayed within about 1%. The complete
corpus gained five net solves and improved timeout-charged and common-total
time, but geometric speed regressed by 0.284%. It therefore failed the declared
global default gate.

## Full-Corpus Route Audit

Corpus-wide finite telemetry job `142731` completed 7,499/7,503 records; four
NEQ parser-heavy cases exceeded the two-second telemetry timeout. The original
focused selector fired on 6,197 successful instances:

| Family | Selected instances |
| --- | ---: |
| QG-classification | 6,156 |
| NEQ | 19 |
| PEQ | 12 |
| SEQ | 10 |

The one-closed-table condition was therefore much broader than the 151-case
development slice suggested. This explains why a nominal finite-family route
could perturb geometric timing over the whole corpus.

Commit `fbcefb5` adds a necessary graph prefilter: focused mode proceeds to
clique enumeration only if the candidate graph has at least `n` vertices in
its `(n-1)`-core. Every real `n`-clique survives this peeling, so the filter
cannot remove a support opportunity. It removes only searches that provably
cannot emit a clause. Commit `b80c238` also restores the cheapest structural
rejection before constructing the candidate graph.

The exact-binary repeated 151-case gate `142796`/`142800` passed:

| Coverage | All-total | Common-total | Geometric | Wins |
| ---: | ---: | ---: | ---: | ---: |
| 130 -> 130 | 1.0017x | 1.0035x | 1.0085x | 92 -> 38 |

There were zero candidate-only or baseline-only cases, wrong answers, or
execution errors. This advances the revision to hot-400, but is not sufficient
for global promotion.

Repeated hot-400 gate `142867`/`142871` rejected the revision:

| Coverage | All-total | Common-total | Geometric | Wins |
| ---: | ---: | ---: | ---: | ---: |
| 321 -> 319 | 0.9795x | 0.9609x | 0.9728x | 36 -> 283 |

`gensys_icl325.smt2` and `gensys_icl_sk002.smt2` were reproducible
baseline-only solves. There were no wrong answers or execution errors. The
candidate therefore stops before a complete-corpus run.

## Rejected Uniform Policy

Uniform support lost `PEQ013_size7.smt2` at the two-second boundary and slowed
the repeated multi-table cases:

- `PEQ013_size7.smt2`: `1.28s -> 2.17s`;
- `PEQ016_size6.smt2`: `0.90s -> 1.11s`.

The 151-instance structure scan was complete with zero failures. Joining its
metrics to the uniform A/B rows showed:

| Structural population | Instances | Coverage effect | All-total | Common-total | Geometric |
| --- | ---: | ---: | ---: | ---: | ---: |
| Focused-selected | 42 | +2 | 1.150x | 1.205x | 1.302x |
| Excluded | 109 | -1 | 0.989x | 0.995x | 0.999x |

This split was then tested prospectively in `142578` and `142581`; the focused
policy retained both new solves and removed every baseline-only case. The
uniform policy is rejected.

## Artifacts

Raw ignored artifacts are under:

- `results/wmi/finite-permutation-target-142564/`;
- `results/wmi/finite-permutation-all151-142567/`;
- `results/wmi/finite-permutation-focused-boundary-142578/`;
- `results/wmi/finite-permutation-focused-all151-142581/`;
- `results/wmi/finite-permutation-focused-hot-142597/`;
- `results/wmi/finite-permutation-focused-full-142610/`;
- `results/wmi/finite-permutation-focused-boundary-crossarch-142702/`;
- `results/wmi/finite-structures-full-c958-142731/`;
- `results/wmi/finite-kcore-all151-142796/`;
- `results/wmi/finite-kcore-hot400-142867/`.

The structure report is
`results/wmi/finite-permutation-all151-142567/finite-structures.json`; its
metric-only full-clique manifest contains 40 instances.

## Decision

Do not default-enable the original focused policy: its full gate failed
geometric speed. Reject the clique-core revision because it lost coverage and
all speed criteria at hot-400. Native Hall propagation remains the broader
follow-up because the current rule handles only proved full-domain injections.
