# T1 Hosted Failure Repair Checkpoint

## Trigger

GitHub Actions run `29389308332` tested exact revision
`7a278b79f3f3038e9ae18f5a218836a6211b4b54`. Both Linux mutate-then-restore
tests failed because the parent treated its own pre-created empty readiness
pathname as evidence that inotify watches were installed. Independent review
also rejected post-monitor script pathname reopens, the hand-written dynamic
loader closure, and the impossible `0-127%32` plus `c1n1` plus per-element
`--exclusive` schedule.

## Repair Contract

- Readiness is canonical nonempty JSON published only after all watches are
  installed. It binds monitor PID, parent PID, root, watch count, and mask; the
  parent parses and validates it before beginning inventories or compilation.
- The common Slurm helper is sourced from a Git-blob-checked descriptor. The
  build guard and timing harness are opened before monitoring and later invoked
  through `/proc/self/fd`; array and audit steps open, hash, and execute the same
  bytes inside the actual step.
- The release uses `+crt-static`. Both build guard and timing harness reject an
  ELF containing `PT_INTERP` or any `DT_NEEDED`; no dynamic-loader closure is
  inferred.
- Full mode is the exact serial array `0-127%1`. Every full element requests
  `c1n1` exclusively and must prove the existing affinity, NUMA, frequency, and
  whole-node controls. Canary remains shard 0 only.
- T1 evidence is permanently nonpromotable. A green hosted run would be a probe,
  not WMI authorization, production authorization, or a performance result.

## Scope

No corpus run, push, hosted rerun, or WMI submission belongs to this repair.
Linux-only mutation and static-release checks must pass in a separately reviewed
hosted execution before any bounded infrastructure canary is reconsidered.
