# Journal

## 2026-07-08

- Created `euf-viper` as a Rust package.
- Verified WMI cluster reachability and queue state before designing cluster
  scripts.
- Checked LTS and WMI default shells for Rust, Z3, and CAS tools.
- Read current web sources for SMT-LIB QF_UF, SMT-LIB benchmarks, SMT-COMP
  tooling, LLM2SMT, and congruence-closure proof literature.
- Implemented the first EUF verifier milestone:
  - SMT-LIB S-expression tokenizer/parser.
  - Declarations and assertions.
  - `and`, `not`, equality, `distinct`, and `let`.
  - Hash-consed term arena.
  - Union-find and congruence closure over function applications.
  - CLI commands: `solve`, `stats`, `gen`, and `bench`.
  - Unit tests for direct contradictions, congruence, lets, generated chains,
    and unsupported disjunctions.
- Installed Z3 4.16.0 locally and ran comparator canaries.
- Added a safe common-consequence preprocessor for positive `or`; it can prove
  equational-diamond contradictions but still reports unsupported when no
  contradiction follows.
- Recorded local canary results under
  `research-vault/06-results/2026-07-08-local-canary.md`.
- Built the Jupyter Book HTML successfully.
- Ran local SageMath, Singular, and Julia/Oscar-style quotient sanity artifacts;
  Magma was skipped because it was not on the local PATH.
- Found Magma on LTS at `/opt/magma/V2.28-3/magma` and ran the Magma artifact
  remotely with `-n` to bypass quota-broken startup logging.
- Submitted WMI job `139145`; it completed successfully and produced the first
  cluster synthetic benchmark log.
- Continued improving against Z3:
  - made positive `or` preprocessing branch-aware;
  - added all-branch pruning against surrounding disequalities;
  - added `diamond`, `pruned-or`, and `bench-or` generators;
  - added repeated median Z3 comparator;
  - measured 18.8x to 64.4x local median speedups on diamond canaries;
  - submitted WMI job `139146`, which completed the OR bench successfully.
- Added full SMT-LIB 2025 QF_UF corpus ingestion:
  - downloaded and verified `QF_UF.tar.zst` from Zenodo record
    `10.5281/zenodo.16740866`;
  - generated a 7503-file manifest and deterministic sample manifests;
  - added cvc5 1.3.4 setup from official release assets;
  - added a Z3Py fallback wrapper for WMI glibc compatibility;
  - submitted WMI corpus job `139149`, which completed successfully.
- Replaced the conjunction-only frontend with a Boolean QF_UF pipeline:
  - parses Boolean constants, predicates, `and`, `or`, `not`, implication,
    equivalence, `xor`, `ite`, annotations, and zero-arity Boolean macros;
  - Tseitin-encodes Boolean structure;
  - validates SAT assignments with congruence closure and falls back to lazy
    theory-lemma refinement when an eager first pass is incomplete;
  - integrates CaDiCaL, Varisat, and a namespaced Kissat backend.
- Ran the complete 7,503-instance corpus as WMI job `139158` with a two-second
  per-solver budget:
  - `euf-viper`: 6,276 correct, 1,147 timeouts, 80 unsupported, zero wrong;
  - Z3 4.16.0: 6,910 correct, 593 timeouts, zero wrong;
  - cvc5 1.3.4: 6,513 correct, 990 timeouts, zero wrong;
  - `euf-viper` had the best median latency at 0.1126s, but lower coverage.
- Added result analysis, same-instance run comparison, manifest filtering,
  checkpoint/resume support, and WMI A/B profiling scripts.
- Iterated parser gating, canonical congruence routing, finite-domain first
  passes, and direct finite equality channeling. Accepted WMI smoke `139229`:
  37/40 correct, zero wrong, 1.0848x aggregate and 1.0990x geometric speedup
  over `139211` on common correct instances, with one additional solve.
- Rejected two measured alternatives as defaults:
  - routing Linux finite-predicate instances to CaDiCaL (`139215`) reduced
    coverage;
  - finite predicate-table channeling and Kissat 4 did not improve the WMI
    hard tail (`139240`, `139242`, `139244`, `139245`).
- Restored the accepted Linux Kissat 0.1 route and passed WMI build/smoke job
  `139375` after the rollback.
- Next experimental order is fixed: add pinned Yices 2.7.0, run full-corpus
  60-second and competition-budget campaigns, then add checked SAT proof
  artifacts plus EUF explanation metadata.
- Added Yices 2.7.0 as the fourth benchmark solver using official release
  assets and GitHub-provided SHA-256 digests. WMI smoke `139380` solved both
  instances correctly with all four solvers; Yices had the lowest smoke median
  at 0.0324s. The official Apple arm64 binary requires an external CUDD dylib,
  so local setup warns and omits Yices when that dependency is absent, while
  Linux/WMI setup treats Yices as mandatory.
- Submitted the first full four-solver two-second campaign as WMI job `139381`.
- Added a long-timeout campaign pipeline with one immutable sampled or full
  manifest, modulo SLURM array shards, per-shard checkpoint/resume files, and a
  merge gate that rejects duplicate, missing, unexpected, wrong, or disagreeing
  rows. Local validation partitioned all 7,503 paths exactly once and exercised
  both successful and intentionally invalid merges.
- Made the sharded submitter honor `EUF_VIPER_REMOTE` for synchronization,
  submission, and metadata so concurrent campaigns can use isolated checkouts.
- WMI sharded smoke `139382`/`139383`/`139384` completed the full
  prepare-array-merge chain on eight sampled instances. Every solver produced
  eight rows, all had 7/8 coverage and zero wrong answers, and the strict merge
  reported no missing rows, execution errors, or disagreements.
- Added proof-producing certification mode:
  - emits exact DIMACS, an ASCII DRAT proof from a fresh CaDiCaL run, and a
    SHA-256-linked term/atom/clause manifest;
  - omits finite-domain shortcuts, then learns replayable EUF conflict clauses
    until the CNF is UNSAT;
  - independently checks DRAT with pinned `drat-trim` and replays every theory
    clause by falsifying it and deriving an EUF congruence contradiction;
  - passed conjunction, transitivity, function congruence, predicate
    congruence, equational-diamond, and 1,000-edge explanation canaries;
  - correctly refused to issue an UNSAT certificate for a SAT chain.
- Kept certificate dependencies behind the opt-in `certificates` Cargo feature.
  The default release binary remained 2,294,560 bytes and its Mach-O text
  section was byte-identical to pre-certificate commit `0bb34c2`; paired
  1,000-process startup loops were 1.71s versus 1.73s after warm-up.
- Full four-solver WMI campaign `139381` completed all 7,503 instances at two
  seconds with zero wrong answers, disagreements, or execution errors:
  `euf-viper` 6,471 correct at 0.0886s median; Z3 6,911 at 0.1705s; cvc5 6,505
  at 0.2956s; Yices2 7,394 at 0.0450s. On 6,463 jointly correct
  `euf-viper`/Yices instances, Yices won 6,166 and used 456.60s versus
  1,577.97s. This rejects any broad faster-than-Yices claim.
- Extended result analysis with per-family and QG-versus-non-QG coverage,
  median, correct-median, total, and correct-total timing. QG-classification is
  6,396/7,503 instances (85.24%); Yices leads both that stratum and non-QG.
- Full 60-second campaign `139420`/`139421`/`139422` completed 30,012 rows with
  zero wrong answers, disagreements, or execution errors. Coverage was
  `euf-viper` 7,434, Z3 7,486, cvc5 7,471, and Yices2 7,500. `euf-viper` beat
  Z3 on 5,581/7,433 common cases at a 1.585x geometric speedup, but its
  5,915.88s common-case total lost to Z3's 3,685.61s because of the tail.
- The four-solver oracle covered 7,500/7,503; the shared gaps are
  `PEQ014_size10`, `PEQ014_size11`, and `PEQ018_size7`. Added restartable
  continuation by result and solver identity. A new `euf-viper` revision must
  rerun all 7,503 of its rows; only unchanged comparator rows may be retained.
- Extended certificate validation to official SMT-LIB corpus inputs. Rodin
  `smt3166111930664231918` verified an 8-clause base refutation, and TypeSafe
  `z3.1184163` verified a 5-clause refutation with one independently replayed
  EUF theory clause.
- Accepted the post-invalid-model CaDiCaL refinement route after three gates.
  Job `139433` measured 2.36x on the affected peg-solitaire case; job `139477`
  kept control coverage at 39/40; full-corpus paired job `139497` plus strict
  merge `139498` improved coverage from 6,873 to 6,886 and timeout-inclusive
  total time from 2,647.98s to 2,638.97s. Common-correct aggregate speed was
  1.0023x, geometric speed was 0.9978x, and there were zero wrong answers or
  execution errors.

## Next Entry Template

- Benchmark corpus:
- Solver revisions:
- Command:
- Result:
- Discrepancies:
- Next action:
