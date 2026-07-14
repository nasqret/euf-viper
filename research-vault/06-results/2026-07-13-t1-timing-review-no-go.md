# T1 Timing Review: NO-GO

Date: 2026-07-13

Reviewed revision: `a99d9bf80c7c4e5f74232addfeb0fe2c74dd4205`

Decision: do not publish the research branch and do not submit the 7,503-source
ABBA campaign to WMI.

## What Passed

The candidate supplied a parse-only and end-to-end ABBA harness, an immutable
campaign description, prepare/shard/audit wrappers, and a miniature accepted
campaign. The worker reported 359 Python tests, 18 focused timing tests, shell
and Python syntax checks, formatting, and a successful book build; independent
review also passed the default Rust matrix with 237 tests and three ignored.
These checks do not make the timing boundary promotion-eligible.

## Blocking Findings

1. The p95 miss gate treated an empty miss set as zero overhead, so an all-win
   or too-small population could pass without measuring tail risk.
2. Submission-time environment variables could replace the timing contract or
   corpus manifest. The remote side validated the supplied object but was not
   bound to the exact local contract/manifest digests or the fixed 7,503-source,
   128-order, one-warmup, five-measurement, two-second design.
3. Timed-out observations were excluded from common timing metrics. The audit
   did not require 7,503 common sources, zero timeouts/errors, exact per-source
   result parity, or absence of a baseline-only solve, so censoring could select
   the favorable candidate arm.
4. Timing rows entered metric aggregation before semantic parity was accepted.
   Their payload carried only a 64-bit FNV fingerprint rather than exact
   semantic counters plus a strong canonical digest.
5. The timed parser path cloned symbol names solely for telemetry. This is not
   the production parse/finish path and can dilute or reverse the measured
   effect.
6. The reused remote checkout guard omitted untracked/ignored influences such
   as Cargo configuration, build helpers, or Python shadow modules.

## Required Repair

- bind immutable local and remote contract/manifest hashes and reject every
  altered constant or ambient override;
- require all 7,503 sources, zero timeout/error observations, exact per-source
  result and semantic parity, and no baseline-only solve before metrics exist;
- measure nonnegative overhead over the complete preregistered population so
  the p95 sample is never empty;
- keep semantic extraction and strong digesting outside production-equivalent
  timed regions;
- use a fresh clean remote execution root and reject every tracked, untracked,
  or ignored input that can influence execution;
- obtain a new independent GO before branch publication or WMI submission.
