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
- Current job metadata: `Requeue=1`, `Restarts=1`, state priority-pending.
- First-attempt stdout is empty; stderr is only the 97-byte scheduler message.
- No `full-60.json` and no `*.tmp.147308` artifact exists.

The automatic restart must therefore execute the complete 10,000-replicate
analysis from the immutable inputs and publish a new terminal artifact. Final
acceptance requires duplicate/requeue-aware `sacct`, terminal zero exit, exact
artifact hashes, and the ordinary audit cardinality/status checks.

## Official Array

Official continuation array `147309` subsequently completed all 64 tasks. Every
task, batch step, and extern step is terminal `COMPLETED` with exit `0:0`.
This is administrative completeness only. Official benchmark rows remain
sealed until global audit `147310` completes and validates them.

## Decision

Keep jobs `147308` and `147310` unchanged. Do not resubmit selected shards,
alter priorities, reuse the preempted computation, or read partial aggregate
data. Successor dispatcher `147311` remains dependency-held until both audits
complete successfully.
