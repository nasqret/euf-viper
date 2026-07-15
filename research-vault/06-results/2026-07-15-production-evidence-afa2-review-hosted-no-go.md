# Production Evidence afa2a844: Review And Hosted No-Go

Date: 2026-07-15

## Decision

Exact commit `afa2a8444192155ba052e0483a3ef39e9ade18c4` was independently
approved only for non-attesting diagnostic publication and exact-head hosted
Linux execution. It was published to `research-production-evidence-v4` and run
`29395085728` failed in the Python matrix before Rust or any Linux evidence
primitive. No WMI preflight, full shadow, merge, or production-evidence claim
is authorized.

## Independent Review

Local validation was clean: all six explicit `cargo +1.96.0` feature matrices,
424 Python tests with 46 Linux-gated skips, formatting, shell syntax, and Git
integrity passed. Review nevertheless found seven blocking boundaries:

1. The runner hashes an opened source descriptor, then rereads the mutable inode
   into a memfd without rehashing the second read. The shadow runner passes the
   mutable inode after hashing. A mutation at the second read changed executed
   bytes while validation still accepted the original digest.
2. The candidate's own build script creates and publishes the sealed-build
   receipt. The checker validates canonical form and a supplied digest but does
   not independently reconstruct compiler, trace, manifest, and binary claims.
3. Build tracing covers file operations but leaves network, time, randomness,
   and related input channels available. Only trace hashes, not canonical trace
   bytes, enter the published set.
4. Runtime closure probes top-level Python imports only; lazy imports, `dlopen`,
   data files, shell tools, loaders, and descriptor-bound execution remain
   incomplete. Shards still hash helpers and later execute their pathnames.
5. Final `global.json` publication overwrites directly. The immutable index can
   therefore name a concurrently replaced, truncated, or failed analysis.
6. Baseline source is a valid independent ancestor checkout, but candidate and
   baseline share candidate-selected compiler binaries and a candidate-owned
   comparison oracle.
7. The workflow records `HEAD` but does not assert that it equals `GITHUB_SHA`.
   The checkout and setup-python action SHAs themselves match their official
   release tags.

Review found no new unchecked-SAT admission: decisive rows still require
checked SAT production evidence, completed sidecars are rehashed on resume, and
resumed schedules remain exact.

## Hosted Result

- Run: `29395085728`.
- Exact head: `afa2a8444192155ba052e0483a3ef39e9ade18c4`.
- Python result: 424 tests, 12 failures, 5 errors, 4 skips.
- Every Rust, release, comparator, CLI, `strace`, namespace, sealed-memfd,
  procfs, and locked-smoke step was skipped.

The failures expose additional integration regressions:

- Three audit/resume paths call `_checker_command` without its new required
  `prefix` argument.
- Dynamic-loader closure verification rejects the workflow's Python identity.
- Final summary construction requires absent `independent_parser` metadata.
- Seven locked-production tests set a receipt variable newly classified as
  runner-owned and stop before their intended semantics.
- Four production-evidence tests now fail on a missing/mismatched sealed receipt
  before reaching their intended trusted-hash, dirty-build, immutability, or
  symlink checks.

## Required Repair

Execute exactly the bytes that were hashed; add an external build attestation;
deny or bind every build input channel and retain trace bytes; enforce complete
descriptor-bound runtime closure; publish analysis transactionally from a
checked immutable inode; separate baseline compiler/oracle trust; assert hosted
revision identity; and repair all 17 hosted failures without weakening their
intended checks. Repeat independent review and hosted Linux execution. A
one-input WMI preflight remains stopped until both are green.
