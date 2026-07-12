# Phase-Zero Evidence Foundation

Date: 2026-07-12

Status: implemented locally; WMI baseline pending

## Frozen Inputs

- Official SMT-COMP 2025 QF_UF selection: 3,521 rows.
- Selection source commit: `82b2c91eb186a846dff0109bf96bf8fe71d2ded5`.
- Selection manifest SHA-256:
  `ed00b0e2105ec9579b02448d161e7f04ceceaf816919535b48734c6525a2aaa6`.
- Official result archive SHA-256:
  `d79dd5d693e9cc645817ecbcad8ccc3cb92fba97418dbe011be3f181a6dd4a1e`.
- Full development corpus: 7,503 SMT-LIB 2025 QF_UF files.
- Comparator configurations: euf-viper, Z3 default, Z3 `sat.euf=true`, cvc5,
  Yices2, and OpenSMT.

`campaigns/solver-releases-2026-07.json` binds official release assets and
source commits. The WMI preparation job records hashes of the exact executable
bytes before it freezes any run lock.

## Trust Boundary

Campaign locks bind the Git revision and cleanliness, campaign contract,
release lock, manifest and taxonomy bytes, every input and solver binary,
child environment, timeout budget, memory bound, CPU assignment, execution
order, and output paths. Runtime shard locks derive exactly from one parent and
record the allocated CPU.

Each solver invocation is a cold process. The runner records wall and child CPU
time, maximum RSS, termination cause, stdout/stderr hashes, and a chained record
hash. Resume accepts only an exact immutable schedule prefix.

The global analyzer validates each shard lock/raw pair independently, rebuilds
the prepared shard from the parent lock, requires the complete disjoint shard
partition, and only then combines observations. McNemar, PAR-2, family macro,
family-cluster bootstrap, Holm correction, and promotion decisions operate on
the complete corpus rather than on shard-local samples.

## Independent Certificates

The Python checker has its own typed SMT-LIB lexer/parser and does not import
Rust parser or CNF code. It reconstructs canonical terms, theory atoms, and the
base Tseitin CNF from source. SAT certificates carry a total assignment and are
evaluated against the source. UNSAT certificates carry only source-replayable
EUF lemmas beyond that base and a DRAT refutation.

Local smoke passes five UNSAT fixtures and `chain1000_sat` with 1,002 Boolean
variables. This is not corpus coverage; batch shadowing of returned WMI rows is
still required before phase zero closes.

## Decision

No speed or superiority claim follows from this implementation. The first
admissible new evidence is the immutable WMI two-second full/official campaign.
Only its timeout rows may enter the 60- and 1,200-second continuations. Novelty
tracks remain blocked from promotion until this evidence chain passes.
