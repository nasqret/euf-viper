# T1 ea28651 Review: Hosted Build Failure, WMI No-Go

Date: 2026-07-15

## Decision

Exact commit `ea28651c16bbe7f57f0675660d9c8c6aea9efaf4` is suitable only
for branch preservation and a hosted diagnostic. Independent review did not
authorize a WMI canary, full timing, merge, or promotion. Exact-head hosted run
`29392563168` then failed during the guarded release build, so no conditional
infrastructure probe was submitted.

## Verified Repairs

- Static release-binary checks reject scripts, dynamic ELF executables, and
  non-ELF payloads in the Linux execution lane.
- The timing payload, parser-parity receipt, population dimensions, and
  promotion formulas are substantially more tightly bound than in `7a278b7`.
- Bounded canary and full modes are represented separately in the campaign
  interface.

## Blocking Findings

1. The Python analyzer accepts arbitrary canary shard identifiers. A complete
   128-shard collection labeled as canary can reach `research_only_pass`, and
   full analysis does not prove full-mode submission or placement controls.
2. Local and remote helpers, including Slurm scripts, are still checked and
   later executed or spooled through pathnames rather than the reviewed opened
   bytes.
3. Monitor readiness binds a count rather than the exact watch set, leaving a
   setup window in which a required target can escape monitoring.
4. Runtime evidence underbinds exact array bounds, stride, count, throttle,
   job identity, and observation frequency. The post-submit receipt is not
   consumed by the analyzer, and a local publication failure can leave an
   unowned remote job.

## Hosted Diagnostic

Run `29392563168` reached the guarded Rust release build and exited 101. The
exact failure was:

```text
cannot produce proc-macro for partial_ref_derive v0.3.3 as target
x86_64-unknown-linux-gnu does not support these crate types
```

The workflow's global `+crt-static` target feature leaked into host proc-macro
compilation. No release artifact or timing result was produced.

## Required Repair

Make mode and exact shard population non-substitutable, execute every reviewed
helper from immutable opened bytes, bind readiness to the complete expected
watch set, consume a complete scheduler receipt with cancellation ownership,
and scope static-link flags to the final target executable. Repeat independent
review and exact-head hosted execution before any WMI action.
