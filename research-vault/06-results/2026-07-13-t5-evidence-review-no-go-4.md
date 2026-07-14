# T5 Evidence Review: NO-GO 4

Date: 2026-07-13

Reviewed revision: `2080b2680c8bf21c7f363d9c06445f2b6028d54f`

Decision: do not publish the branch or submit the component-quotient census.

## What Passed

The Linux FD-bound publication design uses atomic no-replace linking of the
descriptor-checked inode, rechecks destination inode, mode, and digest, and
invalidates `.current` before failure-prone preflight. The repair worker passed
74 focused tests and all 355 Python tests; the independent reviewer reran a
27-test publication subset plus syntax and diff checks on the clean commit.

## Blocking Findings

1. The non-Linux fallback checks a staging pathname and later links that
   pathname. A replacement between those operations can publish a different
   inode. The WMI wrapper is Linux-only, but the reusable finalizer API must not
   retain an unsafe fallback.
2. Staging cleanup checks pathname identity and then unlinks by pathname. A
   replacement in that interval can cause cleanup to delete a foreign inode.
   Leaving an owned stale staging path is safer than deleting an unproven path.
3. The Linux source-swap regression requires successful relinking after the
   verified inode loses its staging pathname. The correct contract permits and
   prefers a fail-closed error; a path replacement must never be published.

## Required Repair

- reject publication when FD-bound same-inode no-replace linking is unavailable;
- remove pathname check-then-unlink cleanup, or make ownership atomic and
  descriptor-bound; never delete an unproven replacement;
- change source-replacement tests to require either publication of the original
  verified inode or fail-closed non-publication, never relinking by pathname;
- rerun fresh independent review before branch publication or WMI submission.
