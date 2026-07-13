# Production Evidence Schema V2: No-Go

Date: 2026-07-13

Reviewed revision: `e3add515cb0bcce9d0ebfd32d11ffb9c3aed6c51`

Decision: reject integration; schema v3 repair required

## Blocking Findings

1. **Congruence-closure downgrade.** The checker trusted sidecar-controlled
   `model.origin`. Changing genuine Kissat evidence to `congruence_closure` and
   deleting clauses, variables, assignment, and atoms still validated as
   decisive SAT because backend/config identity was not required.
2. **Clause, variable, and atom completeness.** The checker validated declared
   hashes/counts and assignment satisfaction but did not independently
   reconstruct the exact production CNF/namespace/map. Removing or adding a
   satisfied clause, adding an unreferenced auxiliary variable, inventing an
   equality for an auxiliary, or duplicating a source atom onto another
   variable passed when the sidecar was self-consistent.
3. **Analyzer bypass.** The primary analyzer required only a model object with
   no limitations. A forged origin was classified as SAT; only the optional
   later shadow rejected it.
4. **Premature complete summary.** Shadow wrote `status: complete` before its
   final sidecar rehash. A final mutation could leave a complete summary even
   though finalization then failed.
5. **Parent-directory symlinks.** Lexical containment plus final-component
   `O_NOFOLLOW` allowed a symlinked `production-evidence` parent to escape the
   output root.
6. **Journal truncation.** Incomplete trailing frames were silently removed and
   resumed, contrary to the promotional evidence contract.
7. **Permissive preparation JSON.** Several campaign preparation readers
   accepted duplicate keys and Boolean schema versions.

## Confirmed Properties

- UNSAT remains unsupported and fail-closed.
- The audited production backend call sites capture base, generated, and
  API-learned clauses.
- Rust solving and the independent checker consume captured source bytes rather
  than reopening the source for semantic evaluation.
- Reviewer verification passed 230 Rust tests and 111 relevant Python tests.

## Required Schema V3 Boundary

- Derive evidence mode from hash-bound backend/config; keep direct
  congruence-closure SAT unsupported until independently specified.
- Independently reconstruct initial CNF, variable namespace, and exact
  atom/auxiliary map from source and config. Replay a deterministic event
  transcript for every dynamic API clause and final solve assignment.
- Require exact maps: no extra, duplicate, invented, or relabelled identities
  and no unreferenced variables.
- Make the primary analyzer call the checker before any SAT classification.
- Rehash before atomic final summary publication.
- Walk artifact paths through no-symlink directory descriptors.
- Reject incomplete journal frames and ambiguous JSON.
- Rebase or reconstruct the full feature on current main; the reviewed repair
  commit depended on absent parent `6095e29` and conflicted with current files.

No production evidence has been integrated and no superiority claim depends on
this branch.

Related: [[2026-07-13-t1-evidence-review-no-go]],
[[2026-07-13-t5-evidence-review-no-go]], and
[[2026-07-13-t3-m0-telemetry-contract]].
