# T5 Evidence Review: NO-GO 2

Date: 2026-07-13

Reviewed revision: `ea8dee53780be7183e307ef874baf1df160a3d82`

Decision: do not submit the component-quotient source census to WMI.

## What Passed

The repaired branch captures and reconstructs source, manifest, campaign lock,
records, targets, aggregate, decoder, and gate evidence. The finalizer repeats
semantic verification, requires equality with the standalone receipt, removes
stale verifier receipts, and consistently pins the canonical Python executable,
version, digest, and isolated environment. All 68 focused tests passed from a
fresh archive of the exact revision.

## Blocking Findings

1. A tracked imported module marked `skip-worktree` remained modified after the
   submitter's checkout/reset/clean sequence. Porcelain status was empty and the
   checkout guard passed. Revision identity therefore did not prove imported
   file bytes.
2. The finalizer hashed the staged archive and then published it by pathname.
   A deterministic mutation in that final interval produced a successful
   publication whose digest differed and whose tar stream was invalid.
3. A failed rerun with the same fixed job identifier refused to replace the old
   bundle but left that old archive reporting `completed`. The result namespace
   did not distinguish the current failed attempt from an earlier completion.

## Required Repair

- reject or clear `skip-worktree` and `assume-unchanged`, then compare every
  imported project file with its exact `HEAD` blob;
- publish the already checked inode with atomic no-replace semantics and test a
  mutation after the final digest;
- use attempt-scoped immutable bundles plus an atomic current-completion marker,
  invalidated before every attempt.

The branch remains isolated. A fresh independent review is required before any
public branch promotion or WMI submission.
