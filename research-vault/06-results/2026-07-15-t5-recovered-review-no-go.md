# T5 Recovered Review: WMI No-Go

Date: 2026-07-15

## Scope

Reviewed exact valid commit
`0ad84317b5cf714785e6129d8403772c813e7758`, parent
`e930abf2a7fe0e89efbb6a4d73540ef2fe266175`. Full `git fsck`, exact 18-file
delta, 88 focused tests, 369 total tests, shell syntax, and checkout cleanliness
passed locally. Invalid object database/commit `6249393` was not inspected.

## Blocking Findings

1. The runtime contract selects
   `benchmarks/smtcomp-2025/qf_uf_manifest.jsonl`, which has 3,521 rows, while
   enforcing 7,503. The campaign lock names the external full manifest, but the
   Slurm script ignores that path. A bounded command reproduced
   `manifest cardinality mismatch: expected 7503, got 3521`.
2. Publication uses `linkat` with `AT_EMPTY_PATH` and forbids the documented
   `/proc/self/fd` alternative while claiming an unprivileged gate. The route
   must either bind effective capabilities or implement and verify the
   capability-free procfs descriptor path.
3. `sbatch --parsable` cluster identity is discarded. Final verification binds
   only numeric job ID, state, and exit code, not cluster, `SLUID`, submit time,
   job name, user, or work directory.
4. The second projection shares parsing and closely mirrors component union and
   minimum-degree completion. Absence of an import is not an independent oracle.
5. Runtime identity omits Python libraries, kernel/libc, mount/filesystem
   properties, and Slurm cluster/version.
6. Hosted consumer tests mock semantic verification and do not exercise a true
   end-to-end census/finalizer/consumer chain.
7. Failure after held-job submission can leave the job allocated because no
   cancellation trap owns that setup interval.

## Diagnostic Hosted Run

Review allowed exact-SHA publication only to collect Linux diagnostics. Branch
`research-t5-component-quotient-census-recovered` triggered run `29385400195`,
which failed after 88 tests with one failure and one error:

- archive replacement was rejected by inode mismatch before the test's expected
  digest-mismatch diagnostic;
- a receipt-swap test attempted to parse the deliberately substituted empty
  receipt instead of asserting fail-closed behavior.

The hosted one-link test passed, but the workflow did not record effective
capabilities. It therefore does not establish the required capability-free
publication route.

## Decision

No merge, tag, WMI canary, census, or performance interpretation. Repair the
manifest, publication privilege contract, Slurm identity, independent oracle,
runtime closure, and Linux end-to-end tests, then obtain a new independent
review.
