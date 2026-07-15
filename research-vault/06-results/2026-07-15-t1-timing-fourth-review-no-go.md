# T1 Timing Fourth Review: Hosted Monitor Failure

Date: 2026-07-15

## Scope

Independent review covered exact commit
`7a278b79f3f3038e9ae18f5a218836a6211b4b54`, sole parent
`26156e3691297c0765a583369d65b3fd62d2d560`. Local syntax, contract, focused
Python, Rust, and object-integrity checks passed. Five Linux-only tests could
not run on macOS.

## Review Findings

1. The prepare and hosted integration paths stop mutation monitors, then reopen
   the build guard and timing harness by pathname. Array bootstrap also hashes
   the common shell helper before sourcing its writable-checkout pathname.
   Checked bytes are therefore not necessarily executed bytes.
2. The recursive ELF inventory manually approximates library search and omits
   loader cache, glibc hardware-capability selection, and full RPATH/RUNPATH
   semantics. The loader later reopens interpreter and dependency pathnames, so
   the inventory is not an immutable execution closure.
3. Full mode requests array `0-127%32`, pins every element to sole node `c1n1`,
   and marks each element exclusive. Separate exclusive array elements cannot
   share that node, so the declared 32-way schedule is impossible.
4. The Linux mutation test's readiness marker was not produced after watches
   were demonstrably installed, leaving a readiness race.

## Hosted Diagnostic

Review allowed branch-only publication and made a one-shard, permanently
nonpromotable WMI infrastructure canary conditional on a green hosted run.
Exact commit `7a278b7` was pushed to `research-typed-parser-timing`. GitHub
Actions run `29389308332` created the Linux job and executed 252 tests, but both
real source-tree and dependency-tree mutate-then-restore cases failed: the
monitor process exited 0 instead of the required semantic exit 3.

## Decision

The hosted gate is red, so no WMI canary is authorized. Full timing remains
NO-GO independently of that failure. Bind every executed script and runtime
byte, replace the manual loader approximation with a verifiable execution
closure or fail closed, require monitor-owned readiness evidence, and use a
truthful exclusive placement schedule. Obtain another independent review and a
green exact-head hosted run before considering even a one-shard canary.
