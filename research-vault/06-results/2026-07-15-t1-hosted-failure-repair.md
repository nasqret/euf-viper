# T1 Hosted Failure Repair Checkpoint

## Trigger

GitHub Actions run `29389308332` tested exact revision
`7a278b79f3f3038e9ae18f5a218836a6211b4b54`. Both Linux mutate-then-restore
tests failed because the parent treated its own pre-created empty readiness
pathname as evidence that inotify watches were installed. Independent review
also rejected post-monitor script pathname reopens, the hand-written dynamic
loader closure, and the impossible `0-127%32` plus `c1n1` plus per-element
`--exclusive` schedule.

The first repair reached `ea28651c16bbe7f57f0675660d9c8c6aea9efaf4`.
Diagnostic hosted run `29392563168` failed only in the guarded release build:
global `+crt-static` reached host compilation and Cargo could not produce the
`partial_ref_derive` proc macro for the Linux target. A second independent review
also found arbitrary canary shard acceptance, pathname-spooled wrappers, a
count-only watch receipt, and an underbound/racy post-submit receipt.

## Repair Contract

- Readiness is canonical nonempty JSON published only after parent-first watches,
  two stable scans, and event reconciliation. It binds monitor PID, parent PID,
  root, exact mask, and a digest over every relative path/device/inode/mode
  directory identity. Both guard and harness require the exact current set,
  setup must have zero events, and close includes a quiescent 200 ms drain.
- The common Slurm helper is sourced from a Git-blob-checked descriptor. The
  build guard and timing harness are opened before monitoring and later invoked
  through `/proc/self/fd`; array and audit steps open, hash, and execute the same
  bytes inside the actual step.
- The release uses an explicit `x86_64-unknown-linux-gnu` target and applies
  `+crt-static` only through target-scoped Cargo flags, leaving host build scripts
  and proc macros executable. Both build guard and timing harness reject an ELF
  containing `PT_INTERP` or any `DT_NEEDED`; no dynamic-loader closure is inferred.
- Full mode is the exact serial array `0-127%1`. Every full element requests
  `c1n1` exclusively and must prove the existing affinity, NUMA, frequency, and
  whole-node controls. Canary is exactly `0-0%1` and shard 0 in submission,
  runtime, worker, resume, and audit contracts; it can never produce a full audit.
- Every exact wrapper is descriptor-spooled under user hold. A canonical receipt
  binds dependencies, wrapper bytes, job identities, array geometry/throttle,
  exclusivity, and tools. Remote and local sides fsync it before receipt-hash job
  naming and release; local publication hard-links the retained inode. Any failure
  cancels only owner/work-directory/job-name-matched jobs.
- T1 evidence is permanently nonpromotable. A green hosted run would be a probe,
  not WMI authorization, production authorization, or a performance result.

## Scope

No corpus run, push, hosted rerun of the second repair, or WMI submission belongs
to this repair.
Linux-only mutation and static-release checks must pass in a separately reviewed
hosted execution before any bounded infrastructure canary is reconsidered.
