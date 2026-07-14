# T1 Timing Review 2: NO-GO

Date: 2026-07-14

Reviewed revision: `20be404ab7386dbe39bfa2fc5ff029a7e4fa1743`

Decision: do not publish the research branch and do not submit the full T1
timing campaign to WMI.

## What Passed

The timed Rust paths themselves are narrow: input handling, semantic hashing,
symbol telemetry, and result hashing are outside the clock. Candidate/baseline
ratios and nearest-rank all-source p95 are oriented correctly, while timeout,
error, result-parity, and baseline-only-loss gates fail closed. The exact commit
was clean; 20 focused Python tests, five shell syntax checks, `git diff --check`,
and `git fsck` passed.

## Blocking Findings

1. Observation and semantic payloads were not bound back to captured stdout.
   The validator checked only the shape of `stdout_sha256` and then trusted a
   separately stored payload. A concrete attack changed every candidate time to
   one nanosecond while retaining zero hashes; all 7,503 rows then passed with
   aggregate ratios `0.01`. Invented semantic hashes and matching counters also
   passed. Shard hashes were first established by the final audit, after rows
   could be changed.
2. The submitter hashed the current remote manifest and adopted that mutable
   value as the expected digest. A replacement remote manifest/corpus containing
   7,503 easy, unique instances would self-certify. The already accepted parity
   manifest digest was available locally but not required.
3. `campaign.repetitions=128` was not a repetition count; the implementation
   used 128 as the shard count and executed one warmup plus five measured ABBA
   rounds. This made the machine contract internally false. The intended design
   must name `shards=128` and `measured_rounds=5` separately, with no repetitions
   alias.
4. Prepare checked source once before a long Cargo build. A transient source
   modification restored after compilation could influence the binary while all
   later checkout checks passed.
5. A caller could choose the partition, and the sub-1% gate lacked a homogeneous
   node constraint plus governor/turbo/frequency, NUMA, allocator/libc, and
   native compiler/linker binding. CPU number and coarse platform metadata are
   insufficient at this threshold.
6. Hosted CI did not build the exact locked release, execute the real release
   through the descriptor harness, test a fresh Cargo environment, or reproduce
   the source-to-binary receipt. Its Python execution fixture was not the Rust
   executable.

## Required Repair

- retain exact raw stdout bytes for every timing and semantic command, rehash
  and reparse only those bytes, and seal each shard receipt before global audit;
- pin the accepted 7,503-source manifest digest locally and reject every remote
  corpus substitution;
- remove the false repetitions field and bind 128 shards independently from
  one warmup plus five measured ABBA rounds;
- build from a private exact snapshot with mutation monitoring plus pre/post
  exact-blob checks and complete toolchain/binary receipt binding;
- lock a homogeneous WMI environment or mark the first campaign nonpromotable
  when sub-1% controls cannot be enforced;
- run the exact release and descriptor-backed evidence path in hosted Linux CI;
- obtain another independent review before publication or WMI.
