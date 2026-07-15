# WMI Quota Failure And Recovery

Date: 2026-07-15

## Decision

The original 1,200-second continuation and replacement certificate-shadow
graphs are infrastructure failures, not scientific results. No completed
partial row may enter a comparison, certificate claim, or promotion decision.

## Exact Failure

- Long timeout: arrays `145785` and `145787`; cancelled audits `145786` and
  `145788`; cancelled finalizer `145789`.
- Certificates: completed prepares `146076` and `146079`; failed arrays
  `146077` and `146080`; cancelled audits `146078` and `146081`.
- Representative stderr:

  ```text
  OSError: [Errno 122] Disk quota exceeded
  ```

  The exception occurred while creating a locked stdout temporary below
  `/home/bnaskrecki/euf-viper-campaigns/30828a4f0c1e`.
- Later tasks failed in three to nine seconds with signal 53 because Slurm could
  no longer create or open the required output paths.

Quota at the live refresh:

| Root | Bytes | Files |
| --- | ---: | ---: |
| `/home/bnaskrecki` | 174.49 GiB / 200 GiB | 1,838,881 / 2,000,000 |
| `/work/bnaskrecki` | 561.09 GiB / 1 TiB | 3,687,608 / 10,000,000 |
| `/projects/fundus` | 75.57 GiB / 100 GiB | 42,992 / 1,000,000 |

## Recovery Contract

1. Do not delete, repair, append to, or interpret the failed `/home` trees.
2. Create an attempt-private exact-revision checkout under `/work`.
3. Copy the complete hash-bound P0 base, never selected successful shards.
4. Revalidate revision, clean tracked state, P0 audit status, corpus identities,
   solver identities, lock hashes, and every referenced artifact digest.
5. Submit a wholly new continuation graph. Require full and official terminal
   audits plus finalization before reading aggregate data.
6. Submit certificate shadows from a fresh exact `8f78543` root. Require every
   shard and both global audits.
7. Record task-level `sacct`, not only parent-array state; a parent marked
   `COMPLETED` cannot mask a failed requeued child.
8. Run `quota` before prepare, before array release, and in every final audit.

T6 job `146075` remains isolated at revision `9833ec3`. Its expected output is
small, so it stays queued unless its own task accounting or storage preflight
fails.

## Live Replacement Graph

- Exact P0 worktree: `/work/bnaskrecki/euf-viper-campaigns/30828a4f0c1e`.
- Complete copied base: `results/p0-144990`, 357 MiB; checksum dry-run against
  the immutable source returned no difference.
- Scheduler barrier: `147305`, complete. Original audit identity remains
  `144993`.
- Continuation: dispatcher `147306`; full array/audit `147307`/`147308`;
  official array/audit `147309`/`147310`; successor dispatcher `147311`.
- Certificate full: prepare/array/audit `147315`/`147316`/`147317`.
- Certificate official: prepare/array/audit `147318`/`147319`/`147320`.

The certificate submitter's empty optional-dependency expansion was fixed at
`026f283`. The interrupted pre-fix attempt created no Slurm job and is not part
of either replacement chain.
