# Family-Disjoint Rust PGO Campaign

Date: 2026-07-23

Status: implemented locally, WMI submission blocked

## Question

Can ordinary LLVM profile-guided optimization improve the accepted Viper
Fabric binary on a completely unseen QF_UF source family without changing its
answers or reducing coverage?

This is a build optimization experiment, not a claim that PGO is a novel SMT
algorithm. Its research value is diagnostic: a positive result would show that
the current Rust implementation leaves systematic low-level performance on the
table, while a negative result would prevent further profile tuning from
displacing algorithmic work.

## Leakage Boundary

The only target family is `2018-Goel-hwbench`. Every one of its 302 official
SMT-COMP 2025 QF_UF sources is holdout-only. Training uses 101 sources selected
deterministically from the other seven official source families:

| Training family | Rows |
| --- | ---: |
| `20170829-Rodin` | 7 |
| `20190906-CLEARSY` | 16 |
| `NEQ` | 16 |
| `PEQ` | 16 |
| `QG-classification` | 16 |
| `SEQ` | 14 |
| `eq_diamond` | 16 |

The maximum is 16 rows per family and 2,000,000 bytes per source. The selected
training bytes total 8,157,654; the largest source is 1,144,489 bytes. Selection
is over the official 3,521-row manifest with SHA-256
`ed00b0e2105ec9579b02448d161e7f04ceceaf816919535b48734c6525a2aaa6`.

`scripts/bench/build_pgo_split.py` rejects noncanonical JSONL, duplicate IDs or
paths, non-QF_UF paths, malformed statuses or hashes, invalid rebasing, and any
source-family overlap. The PGO builder then verifies every selected training
file's physical identity, size, and SHA-256; the Williams runner independently
verifies the holdout files before timing and again against the recorded run
rows. Training and holdout manifests are staged before the split report, which
is the completion marker.

## Build Contract

`scripts/bench/build_rust_pgo.py` applies the following contract:

1. Require a clean Git revision for a promotable build. `--allow-dirty` exists
   only for local plumbing tests and marks the output non-promotable.
2. Reject ambient `RUSTFLAGS`, Cargo target/profile overrides, incremental
   compilation, and tool aliases that cannot be resolved and hashed.
3. Pin and report Cargo, Rust, the Rust-sysroot `llvm-profdata`, repository
   inputs, every training source, every raw profile, merged profile data, and
   both binaries.
   The numeric LLVM version reported by Rust and `llvm-profdata` must match
   exactly; an arbitrary system fallback is rejected before compilation.
4. Build generation and profile-use binaries in separate Cargo target trees.
5. Execute `fabric-solve --engine cadical-up` as a fresh process for every
   source and repeat.
6. Abort on a wrong decisive answer, timeout, malformed output, process error,
   missing profile, or empty profile.
7. Permit `unknown` as profile data only with `--allow-unknown-training`.
   Record it as `unknown`, never as a correct solve, and require the optimized
   binary to replay exactly `unknown` on that source.
8. Install the optimized binary first and publish the canonical report last.

The accepted solver environment is an explicit ordered campaign input:

```text
EUF_VIPER_FABRIC_DISEQUALITY_PROPAGATION=0
EUF_VIPER_FABRIC_PROPAGATION_BATCH_UPDATES=4
EUF_VIPER_FABRIC_LAZY_REASONS=1
EUF_VIPER_FABRIC_INDEXED_CLASS_MEMBERS=1
EUF_VIPER_FABRIC_PAIR_FILTERED_IMPACT=1
EUF_VIPER_FABRIC_DEMAND_FLUSH=1
EUF_VIPER_FABRIC_NARROW_MERGE_FRONTIER=1
EUF_VIPER_FABRIC_SPARSE_ROOT=0
EUF_VIPER_FABRIC_CONSTRUCTION_VALIDATION=0
EUF_VIPER_FABRIC_ALLOCATION_FREE_ASSIGNMENTS=0
```

Profile generation, optimized replay, the standard measured arm, and the PGO
measured arm must all record this exact map. Z3, Yices2, and cvc5 must record
no Viper overrides. This condition is checked again before `campaign.json` is
published.

## Comparator Contract

The WMI bundle contains static official release artifacts:

| Solver | Version | Binary SHA-256 |
| --- | --- | --- |
| Yices2 | 2.7.0 | `eab7efbff2a6f0cce2fcd2c25cb4a94e0e048c902d8ef9e6fd7d7989aa54c501` |
| cvc5 | 1.3.4 | `7562a8b0b835e3eaad5f1a7b4616cd762350cf567b6be03d7e8ee24fa5ced5ee` |

Their archives, extraction trees, modes, versions, and binary hashes are bound
by `scripts/wmi/install_pinned_competitors.py`. The receipt records `ldd` as
`not a dynamic executable` for both binaries and has SHA-256
`2eb96f2868de7e661855b33a41f0213f51251a694669812c25839c52cbd8525a`.
The submitter and job bind that receipt as well as both binary hashes. Z3,
Cargo, Rust, Python, and `llvm-profdata` are resolved and hashed by the
submitter before `sbatch`; the job verifies all seven executable hashes and the
bundle receipt again before touching the corpus.

## Measurement Design

`scripts/wmi/euf_viper_pgo_holdout.sbatch` is default-off and requires one
allocated CPU, a fresh `/work` run directory, a read-only rebased corpus, and a
clean detached checkout of the exact public revision. It builds one standard
binary and one PGO binary from that revision.

The measured arms are, in fixed reference order:

1. Viper standard;
2. Viper PGO;
3. Z3;
4. Yices2;
5. cvc5.

`scripts/bench/compare_multiarm_williams.py` executes one complete Williams
block, which balances order and first-order carryover for all five arms. Every
run is a cold process, parser-inclusive, limited to two seconds, and checked
against the manifest status. Raw rows are written before the summary. The
campaign report is written only after the summary is complete and has zero
wrong answers and execution errors.

`scripts/bench/adjudicate_pgo_holdout.py` then applies the preregistered rule to
the complete summary and atomically writes `pgo-decision.json`. It has fixed
20,000-replicate, seed-zero, 99% paired instance bootstrap settings. It exits
successfully for either a scientifically valid `promote` or `reject`; malformed
or incomplete evidence aborts the campaign. The final campaign marker binds
the decision report to the exact Williams summary hash.

## Promotion Rule

The PGO binary can replace the standard binary only when all conditions hold:

- zero wrong answers, malformed results, execution errors, missing rows, source
  drift, hash drift, or environment drift;
- no source solved only by the standard binary;
- no increase in Viper timeouts;
- common-correct geometric and aggregate point estimates both exceed `1.00x`;
- the 99% instance-bootstrap lower bound for the paired common-correct timing
  factor exceeds `1.00x`;
- no material p95 regression on common-correct holdout sources;
- exact reproduction from a clean public revision.

PGO promotion is not solver superiority. A promoted build must still pass the
full and official 2, 60, and 1,200 second campaigns on two CPU models, with
independent SAT-model and UNSAT-proof checking, before any best-overall claim.

## Local Evidence

The local `eq_diamond24` integration smoke intentionally exercised the opt-in
`unknown` path. The generation binary returned `unknown`, emitted one nonempty
profile, the profile merger succeeded, and the optimized binary replayed
`unknown`. The latest control-flow binary SHA-256 is
`719a421db0cfdb4ba94e4256a8f8c10a7f03317e37319458437b3687055639f0`.
Because the source tree was dirty, the report sets `promotable=false`.
Subsequent provenance inspection showed that the Mac fallback was Apple LLVM
17 while Rust 1.93 reports LLVM 21.1.8. This invalidates the local binary as PGO
build-performance evidence. The repaired builder rejects the mismatch before
compilation. WMI's explicitly pinned Rust and profile tool both report 21.1.8.

The rebuilt standard release binary has SHA-256
`96d502f60f95a5e4ded5c2ba0fcf422120431e1833be808b35cdf6509dc46626`,
identical to the accepted local performance artifact. An attempted two-second
run without the ten settings timed out on both identical arms. Restoring the
contract returned `sat` immediately. The empty-environment artifact is retained
as a rejected configuration and caused the WMI wrapper repair.

## Current Blockers

- Frozen no-solve WMI smoke `169653` remains `PENDING (Priority)` with zero
  runtime and must pass its independent audit first.
- The continuation worktree is dirty and therefore cannot produce a promotable
  PGO artifact.
- The PGO holdout job has not been submitted and has no timing result.
- No current evidence shows Viper beating Yices2 or Z3 overall.

## Exact Handoff

- Work root: `/work/bnaskrecki/euf-viper-fabric`
- Corpus root: `/home/bnaskrecki/euf-viper-finite-max-candidate/benchmarks/smtlib-2025/QF_UF`
- Comparator bundle: `/work/bnaskrecki/euf-viper-fabric/tools/competitors-yices-2.7.0-cvc5-1.3.4`
- Submitter: `scripts/wmi/submit_pgo_holdout.sh`
- Job: `scripts/wmi/euf_viper_pgo_holdout.sbatch`
- Final completion marker: `artifacts/campaign.json`
- Frozen PGO decision: `artifacts/pgo-decision.json`

Submission remains an explicit user-controlled action after clean freeze,
publication, hosted CI, and the F0 smoke audit.
