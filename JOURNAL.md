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
- Rejected increasing the finite-domain eager cap from 8 to 11. WMI array
  `139766` tested four PEQ size 9-11 gaps at 120 seconds; both configurations
  solved 0/4 and totals were 480.50s versus 480.77s. The experimental knob was
  removed rather than retained without a win.
- Rejected bypassing finite-domain routing on the 69-case hard tail. WMI array
  `139710` and merge `139711` measured 12/69 correct for automatic routing
  versus 8/69 when disabled, with five baseline-only and one candidate-only
  solve. The favorable common-solved speed was survivor bias and did not pass
  the coverage gate.
- Rejected a root-propagated finite pigeonhole clique shortcut. Initial tail
  array `139798` preserved coverage at 9/69 with only a 1.0007x
  timeout-inclusive movement. Corrected profile `139875` found no clique on
  four eligible hard instances while adding 63-486ms of preprocessing, so the
  experimental implementation was removed.
- Rejected Sinz sequential at-most-one clauses as a replacement for pairwise
  finite-domain clauses. Target array `139894` and merge `139898` solved 0/4
  hard instances for both encodings at 120 seconds; totals were 480.4604s and
  480.4609s. The exhaustively unit-tested opt-in path was removed.
- Rejected direct CaDiCaL routing on the same finite-tail target. Array
  `139900` and merge `139904` solved 0/4 for both auto/Kissat and CaDiCaL at
  120 seconds, with 480.4649s and 480.4643s totals. No router was added.
- Completed the revision-aware 1,200-second campaign `139688`/`139689`/`139690`.
  Strict merge validated all 30,012 rows with no wrong answers, disagreements,
  or execution errors. Coverage was `euf-viper` 7,478, Z3 7,500, cvc5 7,491,
  and Yices2 7,503. `euf-viper` retained a 1.069x geometric edge over Z3 on
  7,478 common solves but lost common aggregate time 20,668.55s to 5,365.05s;
  Yices achieved full coverage and dominated both speed measures.
- Added an explicit structural Yices portfolio after content-hash
  cross-validation found a coverage-preserving router candidate. Target gate
  `139907`/`139912` kept 65/65 coverage and improved aggregate time 2.482x;
  overhead gate `139925`/`139930` measured about 2.96ms per Yices-routed case.
  Prototype full gate `139942`/`139947` kept 7,503/7,503 coverage and improved
  aggregate time 1.0290x. Exact-source confirmation `140030`/`140035` improved
  direct Yices 1,241.01s to 1,186.49s, a 1.0460x aggregate win, with zero wrong
  answers or errors. Geometric speed was 0.8788x, so this is opt-in and not a
  uniform speed claim.
- Rejected streaming router input after `140012`/`140017` worsened the
  200-case overhead aggregate from 0.9486x to 0.9416x versus direct Yices.
  Restored the full-read binary measured by the full-corpus gate.
- Hardened benchmark checkpointing to consume worker results in completion
  order and made A/B summary formatting total when no common-correct speedup
  exists.
- Revalidated the CAS artifact collection. Sage and Singular passed locally;
  the Julia fallback passed while Oscar remained unavailable; Magma V2.28-3
  passed on `lts-faculty` in 0.010s. The local wrapper now isolates writable
  Sage and Julia state under temporary homes while exposing installed Julia
  packages through a read-through depot.

## 2026-07-09

- Revisited eager EUF after identifying the five unsolved Goel cases as sparse
  transitivity/congruence instances rather than finite-domain pigeonholes.
  Forced full Ackermannization solved all five in `140140`/`140144`, but still
  lost to Z3 and Yices on that slice and was therefore treated only as a route
  candidate.
- Implemented full function and predicate Ackermann axioms plus minimum-degree
  chordal fill of the equality graph. SAT remains accepted only after full EUF
  validation; every added clause is a theory consequence, so eager UNSAT
  remains sound. A bounded fill may abstain but cannot make SAT unsound.
- Rejected unconditional up-front completion. Hard-35 gate `140191`/`140196`
  raised coverage from 11 to 17 but regressed common aggregate and geometric
  speed. Replaced it with a post-invalid-model route restricted to non-finite
  inputs with at least 100,000 base clauses and at most 256 applications.
- Dynamic gate `140413`/`140418` raised hard-35 coverage from 12 to 19 and
  passed aggregate speed. Goel-773 gate `140673`/`140693` added six solves and
  passed all speed metrics, but the pre-Fx full gate `140803`/`140808` lost six
  solves and regressed all speed metrics, so that revision was rejected.
- Rejected cold-code-only and thin-LTO-only variants after `141116`/`141121`,
  `141708`/`141713`, and `141872`/`141877` failed at least one controlled speed
  or coverage criterion. Retained cold annotations and thin LTO only in the
  later combined candidate that passed the complete gate.
- Switched internal hash tables to deterministic `FxHashMap`/`FxHashSet` and
  built release binaries with one codegen unit plus thin LTO. Stable hot-path
  gate `141883`/`141888` improved coverage 396 to 397, common aggregate speed
  1.0419x, and geometric speed 1.0837x. Sorted-order hard gate
  `141902`/`141907` recovered all original five Goel gaps and improved
  timeout-inclusive total time 1.1746x.
- Accepted exact-binary full-corpus array `141911` and strict merge `141916`.
  Across 7,503 instances and 15,006 observations at two seconds, coverage
  improved 6,993 to 7,002. Timeout-inclusive total speedup was 1.0169x,
  common-correct aggregate speedup 1.0336x, and geometric speedup 1.0961x;
  candidate wins were 5,356 versus 1,610. There were zero wrong answers and
  zero execution errors. Candidate SHA-256 is
  `f45b51ec65c36ca3df63397ba22a078c0e8490041c5e504f68ff9c2982a77a2d`.
- Archived merged CSV/JSON and build/SLURM logs under ignored
  `results/wmi/dynamic-ack-fx-full-141911/`. The result is accepted as an
  improvement over the preceding standalone binary, not as a fresh claim over
  Z3 or Yices; 60-second and 1,200-second reruns remain pending.
- Added verified finite-domain symmetry breaking and parser string-ownership
  cleanup. The portable `x86-64-v3` candidate passed hot gate
  `142401`/`142405` and finite-tail gate `142406`/`142410`. Full paired array
  `142412` and merge `142417` then improved coverage `6,891 -> 6,898`,
  timeout-charged total `1.0059x`, common total `1.0078x`, and geometric speed
  `1.0220x`, with zero wrong answers or execution errors.
- Repeated the nine coverage-changing cases seven times on both WMI CPU
  architectures. AMD job `142478` gave `3/9 -> 9/9` and `3.506x` all-total;
  Intel job `142479` gave `1/9 -> 8/9` and `1.321x` all-total. Neither retained
  the single apparent baseline-only timeout from the full one-repeat gate.
- Added deterministic A/B opportunity analysis with exact coverage-only sets,
  timeout neighborhoods, largest deltas, per-family aggregates, and experiment
  selection. Seven focused tests and the real 7,503-instance schema passed.
- Completed the fresh hash-pinned four-solver campaign `142480`/`142481`/
  `142482`. All 30,012 rows completed with no wrong answers, disagreements,
  errors, or failed shards. Coverage was euf-viper 6,874, Z3 7,123, cvc5
  6,831, and Yices2 7,420. Euf-viper beat Z3 on 6,833 common solves by
  `1.111x` aggregate and `2.035x` geometric speed, and beat cvc5 overall. It
  remained `3.584x` slower than Yices2 on common aggregate time and had 555
  pairwise coverage losses versus nine unique solves.
- Audited current Yices2 and Kissat source plus recent Biere/SAT, finite-model,
  symmetry, proof-complexity, and user-propagator literature. The research
  program now separates low-risk head removal, native finite Hall/PB and orbit
  reasoning, and an IPASIR-UP rollback e-graph.
- Added a default-off same-binary `EUF_VIPER_DIRECT_ROOT_CNF=0|1` experiment.
  Exhaustive three-atom assignment tests cover nested Boolean connectives and
  atom-free constants; the release suite now has 38 passing Rust tests.
- Separated long-campaign retry-by-result from retry-by-solver. An explicit
  empty retry-result set with `euf-viper` now reruns exactly euf-viper and
  preserves all comparator rows; 14 Python harness tests pass.

## 2026-07-10

- Added read-only finite-domain telemetry and a deterministic corpus analyzer.
  All 151 NEQ/PEQ/SEQ instances produced complete structural records with zero
  failures; 40 have a guarded clique at least as large as the domain.
- Implemented the missing injection-to-permutation consequence: for every
  verified domain-sized disequality clique, emit one implied support clause per
  value. Yices2 2.7.0 source has range and symmetry logic but no corresponding
  injection, Hall, or dual-support recognizer.
- Rejected uniform activation after it lost `PEQ013_size7` despite a net
  coverage gain. Seven-repeat boundaries confirmed large NEQ gains and stable
  multi-table PEQ regressions.
- Added a formula-structural focused policy. Repeated gate `142578` gave
  `1.821x` all-total and `1.334x` geometric speed. Complete finite gate
  `142581` improved coverage `126 -> 128`, all-total `1.043x`, common-total
  `1.047x`, and geometric speed `1.070x`, with no baseline-only cases, wrong
  answers, or execution errors.
- Direct-root CNF passed hot-400 but failed its clean 20-case finite-tail speed
  gate (`0.993x` aggregate, `0.983x` geometric). It remains experimental while
  full-corpus gate `142591` decides the global tradeoff.
- Added default-off model-directed CaDiCaL refinement. It preserves one solver
  instance and adds only deduplicated clauses from rejected complete EUF
  models; the all-feature suite now has 52 passing Rust tests.
- Explicit CaDiCaL-refine gate `142586` kept hard-Goel coverage `12/35` and
  improved common/geometric speed `1.013x`/`1.016x`. The actual auto-routing
  gate `142628` then lost four solves and regressed all speed metrics, so
  replacing dynamic Ackermannization was rejected. Model cuts remain
  default-off as a reference strategy for future partial-trail propagation.

## Next Entry Template

- Benchmark corpus:
- Solver revisions:
- Command:
- Result:
- Discrepancies:
- Next action:
