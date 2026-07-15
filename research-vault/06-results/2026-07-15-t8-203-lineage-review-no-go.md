# T8 203158c Lineage Review: Semantic Census No-Go

Date: 2026-07-15

## Decision

Exact commit `203158c3a00a88a8de2041e2c5e0e87a1fec595b` is published on
`research-t8-assertion-lineage` only as a failed-review reproducer. It does not
authorize a 7,503-source lineage census, scalar frontier implementation, SIMD,
WMI execution, merge, or performance claim.

## Confirmed

- Zero-based half-open byte spans survive comments, CRLF, whitespace, repeated
  assertions, quoted identifiers, and valid UTF-8; malformed UTF-8 and final
  symlinks fail without output.
- Deterministic typed lineage covers the tested nested `let`, macro shadowing,
  transitive ownership, repeated roots, term ITEs, and two-parent materialized
  objects.
- Canonical JSON, duplicate-key and non-finite rejection, source/build hashes,
  typed ranges, sorted origins, and empty-origin rejection pass.
- Rust passed 240 lineage-feature, 234 default, 228 no-default, and 246
  all-feature tests. Four Python modules passed 38 tests. Forty-two default CLI
  cases matched the parent after excluding `elapsed_ns`.

## Blocking Findings

1. Generic verification checks shape and commitment but performs semantic
   reconstruction only under an optional fixture-subset mode. Recommitted
   arbitrary object hashes, deleted auxiliaries, injected duplicates, and
   diagnostic text assigned to the wrong command passed ordinary verification.
2. Final audit does not load the frozen manifest or compare sequence, path,
   size, and source hash per row. Canonical per-source ledgers are deleted, so
   final records cannot replay exact lineage or diagnostics.
3. Build revision is ambient Git metadata. The WMI wrapper accepts caller-chosen
   revision, binary, manifest, source root, Python, and repository; repeated
   pathname execution and final artifacts lack an external immutable receipt.
4. `push` and `pop` are unsupported diagnostics while assertions from popped
   scopes remain ordinary roots. This is not active-stack lineage.
5. No-follow readers do not recheck pathname identity after final descriptor
   replay, leaving a replacement race. Feature-off builds still run an
   unbounded `git status --untracked-files=all` in `build.rs`.

## Required Repair

Reconstruct every typed object and diagnostic in the independent verifier, bind
all records to the frozen manifest, retain replayable canonical ledgers, derive
provenance externally, implement active-stack semantics or fail closed, recheck
path identity after replay, and remove ambient feature-off build work. Repeat
review before any census or frontier code.

## Hosted Diagnostic

Exact-head run `29398694222` passed campaign validation, shell checks, and the
generic Rust solver step. It did not execute a provisioned 7,503-source lineage
census or independently close any blocking finding. It is branch-health
evidence only.
