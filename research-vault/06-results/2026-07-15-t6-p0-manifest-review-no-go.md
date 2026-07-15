# T6 P0 Manifest Review: Promotion No-Go

Date: 2026-07-15

## Decision

Exact commit `b71a4913aca0ab23f3a8cf7550527b6e8b473c91` is preserved
only as a nonpromotable research checkpoint on `research-t6-theory-dag`. It
correctly reconstructs the current 12-source P0 deficit set, but its generator
does not meet the evidence boundary required for a T6 census. No merge, WMI
submission, promotion, or hardened-evidence claim is authorized.

## Independently Reproduced Facts

- Sole parent: T6 implementation commit
  `9833ec3a9219`.
- P0 audit SHA-256:
  `2458b018...e72686a`.
- Physical 7,503-row manifest SHA-256:
  `9c509b0f...a08db`.
- Generated artifact SHA-256:
  `f0367bdbaa0719be4fb8d36933221731554224a3aef353d0a88fcf7c0bb7260a`.
- Canonical 12-path digest:
  `1fd24c2c5fa8eafd07a39f28c96d828e0e0aa1072fd032db413c60f34270b6fa`.
- Independent reconstruction found exactly 90,036 current observation keys and
  exactly 12 selected qg7 UNSAT sources. All 12 current source sizes, hashes,
  statuses, and parenthesis thresholds match their records.
- Regeneration is byte-identical and atomic output is deterministic.

## Blocking Findings

1. Audit and manifest paths are hashed, then reopened for parsing. A reviewer
   replaced the manifest between those operations; the command succeeded while
   claiming the frozen digest and consumed forged source metadata.
2. Observation validation checks total count and unique keys, but does not prove
   equality with the exact corpus-by-budget-by-solver matrix or bind the
   declared observation provenance. Omission/replacement and semantic
   tampering can pass when the expected audit hash is overridden.
3. `DOMAIN7_HUGE` is inferred from qg7 pathname and byte size. The generator
   does not open the physical source and prove domain size 7, closed table
   functions, binary table applications, zero guarded-disequality clauses, and
   at least 80,000 parentheses.
4. The 10-of-12 gate is a natural scaling of the old 8-of-10 requirement, but
   is not mechanically derived from a frozen population ratio. Configurable
   small populations can still claim `10 of 12`.
5. Path checks reject obvious traversal but accept aliases such as repeated
   separators and `.` components, allowing multiple record identities for one
   physical source.

## Required Repair

Consume hash-bound immutable bytes, verify the exact observation matrix and its
provenance, parse and hash every physical source to establish the complete
structural class, canonicalize paths, and derive the qualifying count as
`ceil(4N/5)` from the actual frozen population. Obtain another independent
review before any source-only census.

Existing job `146075` was neither inspected nor changed by this review. It
remains tied to old commit `9833ec3` and is not evidence for the new manifest.
