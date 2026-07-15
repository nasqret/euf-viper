# T1 Timing Third Review: WMI No-Go

Date: 2026-07-15

## Scope

Reviewed exact commit
`26156e3691297c0765a583369d65b3fd62d2d560`, whose sole parent is
`20be404ab7386dbe39bfa2fc5ff029a7e4fa1743`. The checkout and object graph are
valid. Review covered all 16 changed files and reran the focused tests without
editing the branch.

## Closed Boundaries

- Captured stdout and stderr are retained losslessly, hash-bound, reparsed, and
  compared with stored timing and semantic payloads before metrics.
- Every shard has a sealed receipt and the analyzer closes the exact 128-shard
  set before analysis.
- The accepted parity receipt binds 7,503 sources, 988,035,549 bytes, and
  manifest digest `32aba287...a2d4`; an independent read-only WMI rehash matched
  every source row.
- The dimensions are 128 shards, maximum parallelism 32, one warmup, and five
  measured ABBA rounds. Compilation is locked and offline after explicit
  vendoring.

## Blocking Findings

1. The submitter still accepts ambient remote host, published ref, remote root,
   and campaign tag values. Slurm wrappers enter `SLURM_SUBMIT_DIR` and source
   code there before rejecting ambient state.
2. Either public stop sentinel can terminate a mutation monitor after readiness
   but before Cargo. A source or vendor mutation can then occur and be restored
   between inventories while the monitor emits a zero-event receipt.
3. The final executable is first checked after monitoring stops. Evidence does
   not validate complete ELF identity, interpreter, recursive `DT_NEEDED`
   closure, linker output, or every executed native dependency.
4. CPU governor and exclusivity are observed rather than enforced. Honest
   `research_only_pass` labeling does not make this adequate for a sub-1%
   performance inference. The submitter also has no bounded-canary mode and
   would schedule all 128 shards.

## Hosted Diagnostic

Review permitted publication of the exact SHA only to
`research-typed-parser-timing`. Run `29386186960` failed during workflow
evaluation and created zero jobs. The branch added `${{ runner.temp }}` to
`jobs.validate.env`; GitHub's
[context availability table](https://docs.github.com/en/actions/reference/workflows-and-actions/contexts#context-availability)
does not make `runner` available at that key. Therefore no Linux release,
mutation, ELF, or solver test ran.

## Decision

No WMI canary, full array, merge, tag, timing interpretation, or promotion.
Replace sentinel shutdown with descriptor-owned monitor lifecycle, bind an
immutable exact-ref execution root, check complete ELF/runtime/toolchain
closure, add a true bounded canary and enforceable placement contract, repair
the hosted workflow, and obtain a new independent review.
