# EUF World-Leader Campaign

The active program is defined by the machine-readable contract
`campaigns/euf-world-leader-2026-07.json`. It expands the performance campaign
into a complete QF_UF scoreboard while keeping evidence from different
revisions, machines, corpora, and timing modes separate.

## Objective

Viper is considered the overall leader only if it has:

- zero wrong, missing, or unchecked decisive results;
- coverage at least equal to every comparator at 2, 60, and 1,200 seconds;
- at least a `1.05x` advantage in PAR-2, common-total, and common-geometric
  wall time;
- independent model and proof checking;
- replication on two CPU classes and sealed data; and
- a closest-prior-art audit and ingredient ablation for differentiated work.

The current broad result does not pass those gates. It uses an older solver
revision, is close to complete at 1,200 seconds, beats Z3 geometrically on
common solves, and remains materially behind Yices2. The current structural
revision leads the local two-second PEQ/SEQ/NEQ discovery panel in coverage and
PAR-2, but still loses common-geometric time to Yices2 and has not completed a
broad fixed campaign.

The generated evidence dashboard is available at
`../dashboard/euf-progress.html`. Its canonical compressed registry contains
186 evidence records rendered as 174 claim-isolated panels, including separate
SAT and UNSAT strata. On the provisional combined PEQ/SEQ/NEQ panel, Viper
solves 148/151 versus 140 for Yices2 and has a `1.816x` PAR-2 factor, while its
common-geometric factor remains `0.751x`; matching Yices2 on those common solves
requires a 24.9% Viper time reduction. The audited broad panels still measure
revision `30828a4`, so they remain separate.

## Metric Model

Every dashboard panel fixes the evidence artifact, solver revision, host class,
corpus, family, expected status, budget, and repetition policy. The primary
dimensions are validity, coverage, latency distribution, PAR-2 and timeout
cost, memory and hardware counters, proof/model quality, robustness, and
feature support.

For lower-is-better quantities the speedup is

\[
  S_{V/C} = \frac{T_C}{T_V}.
\]

Thus `1.20` means Viper is 20% faster in the measured resource, while `0.50`
means Viper currently has half the competitor's throughput. The improvement
required for Viper to tie the leader is reported separately as

\[
  R_V = \frac{T_V}{\min_C T_C} - 1.
\]

Coverage is lexicographically prior to speed. No aggregate score compensates
for a wrong answer, lost solve, missing row, failed proof, or absent holdout.

## Optimization Loop

Each mechanism progresses through:

1. an observe-only opportunity census;
2. bounded differential correctness;
3. same-binary paired micro timing;
4. a lineage-balanced family panel;
5. hot-400 and full two-second campaigns;
6. timeout-only 60/1,200-second continuation; and
7. replication on a second CPU class and sealed data.

Failed mechanisms stop at the cheapest conclusive gate. Passing mechanisms are
still isolated until they independently improve the broad dashboard.

## Technical Order

The campaign executes measurement closure, fast-head profiling, Goel/general
Boolean learning, canonical quotient-frontier caching, proof-system
compilation, native finite/discrete search, repeated semantic symmetry, modern
SAT-backend controls, certification, and finally workflow/API expansion.
Component migration is deferred because its measured fixed-arm oracle headroom
is below the preregistered threshold.

The full design and stop rules are in
`research-vault/02-design/2026-07-26-euf-world-leader-campaign.md`; the current
primary-source map is in
`research-vault/01-literature/2026-07-26-hot-euf-research-map.md`.
