# WMI Full Audit Preemption And Requeue

Date: 2026-07-15

## Classification

Full 60-second continuation audit `147308` was scheduler-preempted, not failed
by the solver or analyzer. Slurm automatically requeued the same immutable job.
The first attempt is administrative provenance only and no output from it may
enter the campaign result.

## Exact Accounting

- First start: `2026-07-15T06:40:33` on `c1n1`.
- Preemption: `2026-07-15T08:49:59` after `02:09:26`.
- Parent state: `PREEMPTED`, exit `0:0`.
- Batch step: `CANCELLED`, exit `0:15`.
- Scheduler message: job cancelled due to preemption.
- The first automatic requeue reported `Requeue=1`, `Restarts=1`, state
  priority-pending.
- Last confirmed metadata later reported `Restarts=2`, state running, and start
  time `2026-07-15T13:03:36`. This remains administrative state, not a partial
  benchmark result.
- First-attempt stdout is empty; stderr is only the 97-byte scheduler message.
- No `full-60.json` and no `*.tmp.147308` artifact exists.

The automatic restart must therefore execute the complete 10,000-replicate
analysis from the immutable inputs and publish a new terminal artifact. Final
acceptance requires duplicate/requeue-aware `sacct`, terminal zero exit, exact
artifact hashes, and the ordinary audit cardinality/status checks.

Subsequent SSH probes to `access.cluster.wmi.amu.edu.pl:22` temporarily timed
out. The outage checkpoint inferred no result. A later live refresh found the
gateway operational and proved that the immutable restart completed `0:0` at
`2026-07-15T15:47:09`. Only that terminal state authorizes the result below.

## Official Array

Official continuation array `147309` subsequently completed all 64 tasks. Every
task, batch step, and extern step is terminal `COMPLETED` with exit `0:0`.
Global audit `147310` then completed `0:0` after `01:54:27`. Its terminal JSON
has SHA-256
`5a02f9bac273e3928231d216c5d3df490ee25b3fe0fd3362415521d1f418e133`
and status `rejected`. The 60-second official solved counts are:

| Solver | Solved / 3,521 |
| --- | ---: |
| euf-viper | 3,508 |
| cvc5 | 3,510 |
| OpenSMT | 3,496 |
| Yices2 | 3,518 |
| Z3 default | 3,514 |
| Z3 `sat.euf` | 3,511 |

The audit rejected promotion against all five comparators after the complete
declared budget/family gates. It confirms that the current solver is close at
60 seconds but is not best overall.

## Terminal Recovery

Full audit `147308` completed `0:0` after its immutable requeues and published
`full-60.json`. Successor dispatcher `147311` then completed `0:0` and submitted
the fresh 1,200-second graph:

- full array/audit `147684`/`147685`;
- official array/audit `147686`/`147687`;
- terminal finalizer `147688`.

Every graph node is terminal `COMPLETED 0:0`. The final index has SHA-256
`2d1c7a3bef5e955efd0709b2b47f42f31957574f23e9f1b66028ac6258b64d15`.
Its full analysis has SHA-256
`82374f6b170313d45a456c30c388f19204391eb4f070c3bbb4dbf043c7d5ec02`;
the official analysis has SHA-256
`cbd9e0b5f2b38c21ae036ebc9cd9b94a9e07d498ed3019622c735091027b8d40`.
Both terminal analyses reject promotion.

| Solver | Full solved / 7,503 | Official solved / 3,521 |
| --- | ---: | ---: |
| euf-viper | 7,502 | 3,520 |
| cvc5 | 7,495 | 3,517 |
| OpenSMT | 7,498 | 3,519 |
| Yices2 | 7,503 | 3,521 |
| Z3 default | 7,500 | 3,520 |
| Z3 `sat.euf` | 7,492 | 3,516 |

Euf-viper's common-wall geometric factor over Z3 default is `1.5522x` full
and `1.5025x` official. Against Yices2 it is only `0.4838x` and `0.4635x`, so
Yices2 remains about `2.07x`/`2.16x` faster geometrically. Common-wall total
factors against Yices2 are `0.2021x`/`0.1721x`, exposing a much larger tail
deficit. The single unsolved source is
`QF_UF_sokoban.2.prop1_ab_br_max.smt2`, SHA-256
`cfe0e5e611139004e7f8a06461c4cbf3066bb604786377db1a94d40e797f3112`.

## Decision

Accept the recovered graph as terminal rejection evidence. Do not rerun or
reinterpret its rows. Coverage is now within one solve of Yices2 and tied with
Z3 on the official set, but the best-overall claim remains false because the
2/60-second coverage gaps and Yices2 timing deficit remain.
