# Phase-Zero Evidence Foundation

Date: 2026-07-12

Status: published foundation; replacement WMI baseline pending

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

## Published Execution

- Fixed revision: `70f0a60671a90c78f4e6014bd23439f14c1f5adb`.
- Hosted CI run `29199707319`: successful.
- Prepare: `144767`.
- Full-library array: `144768`.
- Official-selection array: `144769`.
- Global audit: `144770`.

The first submission at `c2ed5d8` exposed a non-hermetic test that read ignored
`results/cert-smoke` files. No benchmark job started. Jobs `144763`–`144766`
were cancelled, the Rust-produced base prefixes were moved to tracked golden
fixtures, and the exact hosted Python command plus Rust suite passed before the
replacement chain was submitted.

The replacement chain was subsequently cancelled on the requested project
pause before producing a campaign lock or benchmark row. The resumed contract
work adds timeout-only schema-v2 stages and independent certificate coverage;
those artifacts remain implementation evidence only until a new fixed revision
passes hosted CI and the full WMI dependency graph completes.
