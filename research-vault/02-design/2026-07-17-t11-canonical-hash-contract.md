# T11 Canonical Hash Contract

Date: 2026-07-17

Status: implementation clarification; no selector, proof rule, cap, or gate is
changed

This file freezes the byte encodings needed to satisfy the preregistered T11
identity and materialization gates. The compiler and checker implement these
encodings independently and may share only the immutable record schema. They
must not call a common encoder or hash helper.

## Primitive Encoding

- `u8` is one byte.
- `u32`, signed `i32`, and `u64` use big-endian bytes.
- Every `usize` is checked to fit and encoded as big-endian `u64`.
- A byte string is its encoded `usize` length followed by its bytes.
- A clause sequence is its encoded clause count followed, for every clause in
  order, by its encoded width and signed literals.
- Every structured domain below includes the listed ASCII domain bytes,
  including the terminal NUL, before its payload.

## Raw Identities

`source_sha256` is ordinary SHA-256 of the exact source bytes. This is required
to compare directly with the frozen target SHA-256.

`root_cnf_mode_sha256` is ordinary SHA-256 of the exact root-mode bytes
`direct-root;negated-root=false;v1`.

## Term DAG

`term_dag_sha256` uses domain `euf-viper-t11-term-dag-v1\0` and encodes:

1. sort-name count and each length-prefixed sort name in numeric sort order;
2. the `(symbol u32, sort u32)` map sorted lexicographically;
3. declaration-slot count and, for every slot, a presence byte followed by
   result sort, argument-sort count, and argument sorts when present;
4. term count and, for every term in term-ID order, the term ID, function ID,
   result sort, argument count, and argument term IDs; and
5. ordered-application count and the existing application term IDs.

## Preserved T10 Baseline Identities

These three fields deliberately use the exact T10 domains and payloads. A T11
projection over the same in-memory direct-root baseline must equal the hashes
in the T10 target preflight record.

- `atom_map_sha256`: domain `euf-viper-t10-baseline-atom-map-v1\0`, then the
  T10 atom-map payload.
- `baseline_cnf_sha256`: domain `euf-viper-t10-baseline-cnf-v1\0`, then the
  T10 flat-clause payload.
- `baseline_problem_sha256`: domain
  `euf-viper-t10-baseline-problem-v1\0`, then the T10 flat-clause payload
  followed by the T10 atom-map payload.

The flat-clause payload is the end-offset count and all `u32` end offsets,
followed by the literal count and all signed literals. The atom-map payload is
the variable-atom slot count and each slot's presence byte and atom, including
the reverse-map presence/value for mapped slots; then the reverse-map count,
the optional true literal, and the two finite-completeness bytes. Equality atom
tag is `1`, Boolean-term atom tag is `2`.

## Accepted Trace

`trace_sha256` uses domain `euf-viper-t11-trace-v1\0`, followed by trace count
and topological records. Equality record tag is `1`; Conflict record tag is
`2`. IDs, depth, normalized conclusion, side/conflict clause, rule rank, and
all rule-specific references are encoded in record-field order. A clause
reference is clause ID followed by origin (`0` baseline, `1` derived), then a
pivot's literal offset. Congruence argument associations remain in increasing
argument-index order.

## Lemmas And Materialization

Both `lemma_sequence_sha256` and `materialized_lemmas_sha256` use domain
`euf-viper-t11-lemma-clause-sequence-v1\0` and the same ordered clause-sequence
encoding. The first is computed from exported `EmittedLemma` clauses. The
second is computed after independently materializing those clauses into a flat
store and iterating that store. Source clause IDs and outcome tags are metadata
and are not part of emitted SAT clause bytes.

Consequently the two hashes must be equal for every accepted result. One empty
clause encodes count `1`, width `0`; `no_lemmas` encodes count `0`, so the two
outcomes remain distinct.

`materialized_candidate_sha256` uses domain
`euf-viper-t11-materialized-candidate-v1\0`, followed by the exact T10 flat
baseline payload, the common emitted-clause sequence, and the exact T10
atom-map payload. It adds no variable or atom.

## External Bindings

Candidate binary, revision, corpus manifest, projection record, checker
record, observation record, DIMACS, invocation, and DRAT hashes remain all-zero
inside source-only projection until the corresponding external artifact is
created. A later receipt replaces and validates those bindings; zero is never
accepted as evidence that an external artifact was checked.

## Required Regressions

Before target inspection:

1. compiler and checker must agree on every internal hash for a typed synthetic
   proof containing missing-equality Congruence;
2. raw source hashing must match standard SHA-256 vectors;
3. T11 baseline hashes must equal T10's canonical functions on the same
   synthetic in-memory baseline;
4. mutating any encoded field must be rejected by the checker; and
5. lemma-plan and independently materialized hashes must be equal for ordinary,
   one-empty-clause, and zero-clause outputs.
