# T11 External Scheduling Audit Receipt

Date: 2026-07-17

Status: implementation contract; frozen target remains unopened

## Process boundary

`project-t11` performs parsing, baseline construction, compilation, logical
checker replay, and immutable lemma materialization. A selected projection that
passes every in-process check exits with code `4`, meaning that an external
scheduling audit is still required. It never exits successfully on internal
acceptance alone.

The separate command is:

```text
euf-viper audit-t11 FILE|- --bundle PATH --receipt-out PATH
```

It reparses the source and rebuilds the pinned direct-root baseline, but it does
not call the T11 compiler, logical checker, or SAT. It exits `0` only when both
the immutable projection gate and the independent scheduling auditor accept.
Rejected evidence exits `3`; malformed or aliased artifacts are errors.

## Exact input bytes

The bundle reader holds one regular-file descriptor, rejects files above 256
MiB before allocation, detects truncation or growth, and accepts exactly one
compact JSON record followed by one newline. Deserializing and serializing the
record must reproduce every body byte. This rejects whitespace variants,
unknown fields, noncanonical digest text, and multiple records.

The source, bundle, and fresh receipt paths must not alias. The receipt binds
ordinary SHA-256 of the complete bundle file, including its single terminal
newline.

## Independent reconstruction

The auditor owns separate validation, canonicalization, scheduling,
subsumption, arithmetic, cap, materialization, and SHA-256 code. It regenerates:

1. static input counts and cap precedence;
2. base scan, reflexivity initialization, and the global event worklist;
3. antichain admission and removal;
4. globally ordered transitivity joins and congruence tuples;
5. ablation suppression before allocation or accounting;
6. negative registrations, conflicts, and derived-clause indexing;
7. proof-work and logical-memory charges at every mutation boundary;
8. terminal-empty behavior and final forward subsumption; and
9. trace, lemma, materialized-lemma, and materialized-candidate hashes.

It compares the reconstructed trace, output, counters, cap attempt, materialized
flat bytes, and hashes against compiler, checker, and report records.

## Receipt acceptance

The schema-v1 receipt contains the exact bundle digest, source and baseline
problem digests, trace digest, lemma and materialization digests, reconstructed
counters, reconstructed cap attempt, and the ordered audit status or failures.
Acceptance requires every bound digest to be nonzero and equal across receipt,
compiler, checker, report, and auditor. Counters and cap decisions must also be
identical.

The checked materialized store has private storage and read-only accessors.
After checker replay it cannot be edited or replaced inside an assembled
bundle. Stage 1 SAT loading must consume that same sealed store through its
read-only view.

No receipt authorizes target inspection until the compiler, checker, auditor,
CLI, and exact-snapshot reviews all pass locally. A receipt from a rejected or
nonselected source is evidence of rejection, not a Stage 0A pass.

## Authorization boundary

The receipt proves only the independent semantic reconstruction recorded in its
fields. It does not establish which executable produced the bundle, which
runner invoked the commands, whether the source or tools changed between
checks, or whether the process and scheduler exit records belong to the same
attempt. Consequently neither a standalone receipt nor a direct successful
Python validation authorizes Stage 0B.

Stage 0A authorization requires one complete immutable run root: the reviewed
launch manifest and clean Git revision; exact runner, execution helper,
validator, Cargo and Rust tools, candidate binary, source, bundle, receipt,
contracts, logs, metadata, and exit records; and the successful scheduler
record for that same attempt. Inputs consumed by project, audit, and validation
are sealed descriptor snapshots. Outputs are anonymously staged, atomically
published without replacement, directory-synced, and rebound to exact bytes and
identities. The manifest-pinned validator and an independent exact-revision
reviewer must verify both layers before the target-only result can authorize a
7,503-row Stage 0B census.

Infrastructure failure, scientific rejection, and successful authorization are
distinct terminal states. A rejected or incomplete run root remains evidence
of that failure and must not be upgraded by copying out its receipt.
