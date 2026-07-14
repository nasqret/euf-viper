# T5 Evidence Review 6: NO-GO

Date: 2026-07-13

Reviewed revision: `cf1aa3e56f7af11cec3098afd4e8b4dac239532e`

Decision: do not publish the research branch and do not submit the T5 census
to WMI.

## What Passed

The repair introduced private attempt-specific remote checkouts, removed
finalizer/sbatch unlink cleanup, used a descriptor to select the archive inode,
and hardened several checkout checks. The exact commit was clean; 32 focused
publication tests and 83 semantic/parser/taxonomy tests passed, as did the
checkout guard, `git diff --check`, and `git fsck`.

## Blocking Findings

1. The named staging file remained as a second hard link to the completed
   archive. A concrete probe changed its mode and wrote through that alias,
   changing the bundle after `.current` while the recorded digest stayed stale.
   Another probe changed the final path after its last verification but before
   marker creation.
2. `.current` was only a symlink plus directory `fsync`, without descriptor
   identity or content verification. Swapping it during the fsync window made
   publication return success for a foreign target. A failed fsync also left a
   marker that consumers could mistake for completion.
3. Git checks remained environment-sensitive, inherited `ALL`, and omitted the
   campaign lock from exact blob checks. An alternate `GIT_WORK_TREE` let a
   modified execution lock pass. The lock loader also accepted values far
   outside the preregistered selector, threshold, lineage, and ratio contract.
4. The archive/marker omitted the submission nonce and remote namespace
   identity, while the local receipt never acquired the final archive digest.
   Renaming the parent directory could make returned pathnames address a
   replacement namespace even though publication used the displaced directory.
5. Pathname cleanup races remained in analyzer atomic writes and verifier
   receipt handling. A probe made cleanup remove a foreign replacement.
6. macOS tests emulated the central Linux operation with a pathname scan and
   `os.link`; they did not test real unprivileged `AT_EMPTY_PATH`, `/proc` fd
   fallback, unsupported filesystems, errno behavior, or a pathless source.
7. The separate verifier imported the analyzer and called the same
   `analyze_source` implementation. It detects artifact tampering but is not an
   independent implementation of the projection mathematics.

## Required Repair

- use a genuinely unnamed Linux inode and publish it once with no mutable
  staging alias; require a one-link final inode and reject unsupported hosts;
- publish a descriptor-bound canonical completion receipt containing target,
  digests, nonce, revision, contract, and namespace identity, then require a
  fresh no-follow consumer recheck plus successful job status;
- whitelist the environment and compare the lock plus every executable/import
  directly with exact revision blobs under sanitized Git;
- remove all pathname cleanup, bind final digests into the completed receipt,
  and test parent/destination/marker races and fsync failures on real Linux;
- independently recompute every promotion-relevant T5 projection/gate rather
  than importing the candidate analyzer;
- obtain another independent review before publication or WMI.
