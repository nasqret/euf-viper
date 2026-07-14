# T5 Evidence Review 5: NO-GO

Date: 2026-07-13

Reviewed revision: `55c010121ae735f120b56db043dabbe3347012d1`

Decision: do not publish the research branch and do not submit the T5 census
to WMI.

## What Passed

The branch passed 75 focused evidence tests, all 356 Python tests, shell syntax
checks, and the documentation build used by the worker. The Linux publication
path had moved to descriptor-based staging and the bundle verifier continued to
reconstruct structural counts rather than trust summary booleans.

## Blocking Findings

1. The finalizer compared a staging pathname with a verified descriptor and
   then published through the pathname. Replacing the path after the identity
   check could make publication consume different bytes. The opened descriptor
   and its inode must be the authoritative object; the staging pathname cannot
   be a publication prerequisite.
2. Failure cleanup used `readlink`/`unlink` on `.current` and other paths. A
   concurrent publisher could replace one of those paths between the ownership
   check and deletion, allowing this attempt to remove another attempt's
   artifact. A failed attempt must not perform fallible pathname cleanup after
   the last validation boundary.
3. The remote checkout and result root were revision-keyed and reused. A
   concurrent same-revision submission could run `git clean -ffdx` over another
   campaign's ignored results. Each submission needs a securely created unique
   remote work and result directory bound into its receipt.
4. Generated `__pycache__` files made the post-test checkout guard fail with
   exit 2. The campaign must prevent or remove generated caches deliberately,
   then prove the post-test guard rejects every untracked or ignored Python,
   Cargo, configuration, or build input that could affect execution.

## Required Repair

- publish the already-opened verified descriptor/inode, never bytes reopened
  from a staging pathname;
- make the completed marker the final operation after all validation and avoid
  deletion of any path whose ownership is no longer descriptor-proven;
- allocate a unique remote work/result root for every submission and bind it to
  the receipt;
- add adversarial stage-swap, concurrent-current replacement, same-revision
  submission, cache, and untracked-influence tests;
- obtain a new independent GO before branch publication or WMI submission.
