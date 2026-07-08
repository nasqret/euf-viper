# Invalid-Model CaDiCaL Fallback A/B

Date: 2026-07-08

## Change

Keep the eager Kissat first pass. If Kissat returns SAT but full EUF model
validation finds a theory conflict, refine the same CNF with incremental
CaDiCaL instead of Varisat. Linux x86_64 uses this route by default after the
accepted gate. `EUF_VIPER_INVALID_MODEL_FALLBACK=varisat` is the rollback.

Baseline binary SHA-256:
`d5a48044eb53407ed451850de418d06fe6edf2f691765bb14b465019ede4fa5e`

Candidate binary SHA-256:
`ed8f343965d36718854fa99ce2342b46d7dd77e58d4fff2e0cef683736de89d8`

## Targeted profile

WMI job `139433` ran five repeats on five selected cases. The geometric
candidate speedup was 1.1789x. On the affected peg-solitaire case, median time
fell from 713.41ms to 301.87ms, a 2.3633x speedup. SAT calls fell from 91 to 29
and learned theory lemmas from 2,848 to 860. The other four eager-UNSAT cases
did not exercise the new branch and showed ordinary solver variance.

## Repeated control

WMI job `139477` ran five measured repeats plus warmups on the deterministic
40-instance sample. Neither configuration exercised a known affected case.
Both covered 39/40 with no wrong answers. Common aggregate speed was 1.0091x
for the candidate while geometric speed was 0.9867x, establishing the noise
band rather than an optimization win.

## Full-corpus gate

WMI array `139497` used 64 shards with at most four active tasks, one paired
alternating observation per configuration, and a two-second timeout. Strict
merge `139498` validated all 15,006 observations. The interval from first shard
start to merge completion was 24m59s; peak task MaxRSS was 232,472 KiB.

| Metric | Baseline | Candidate |
|---|---:|---:|
| Correct | 6,873 | 6,886 |
| Common-correct total | 1,337.78s | 1,334.72s |
| Timeout-inclusive total | 2,647.98s | 2,638.97s |
| Pairwise wins | 3,550 | 3,297 |

The candidate added 39 candidate-only solves and lost 26 baseline-only solves,
for a net gain of 13. Common-total speedup was 1.0023x and timeout-inclusive
speedup was 1.0034x. Geometric speedup was 0.9978x, so the optimization is not
claimed as a uniform per-instance win. There were zero wrong answers and zero
execution errors.

## Decision

Accept. The affected route is materially faster, full-corpus coverage rises,
and both aggregate measures improve. The rollback environment setting remains
available, and future optimization gates retain all three metrics rather than
selecting only the favorable one.
