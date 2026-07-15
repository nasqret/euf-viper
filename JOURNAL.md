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
- Completed focused finite-support hot gate `142597`, full gate `142610`, and
  cross-architecture boundary `142702`. The full corpus gained five solves and
  improved total/common time, but geometric speed was `0.997x`; the original
  route is not promoted. Full telemetry showed it selected 6,156 QG instances,
  so a necessary clique-core prefilter now removes provably empty searches.
- Accepted full direct-root gate `142591`/`142596`: coverage `6,825 -> 6,843`,
  all-total `1.006x`, common-total `1.010x`, geometric `1.026x`, zero wrong
  answers and zero execution errors. Commit `50edc7d` makes it default while
  preserving `EUF_VIPER_DIRECT_ROOT_CNF=0` as rollback.
- Added bounded Yices-style equality abstraction with independent meet/join,
  Iff, Ite, cap-rollback, randomized, and Z3 implication checks. Unrouted facts
  gate `142742` kept 40/40 coverage but regressed total/geometric speed to
  `0.990x`/`0.933x`; facts remain default-off while shadow telemetry and
  associative flattening identify a narrow route.
- Replaced cloned nested-`let` environments with scoped in-place bindings.
  Seven-repeat gate `142743` improved `NEQ027_size10/11` by `5.63x` aggregate
  at unchanged coverage. The 40-case control was flat but slightly below the
  strict speed threshold. Full gate `142745`/`142750` then lost one net solve
  and measured `0.996x` geometric speed, so unconditional activation is
  rejected; a predeclared lexical-depth route at 512 lets is under test.
- Passed the repeated 151-case clique-core finite-support gate
  `142796`/`142800`: coverage stayed 130/130, all-total improved `1.0017x`,
  common-total `1.0035x`, and geometric speed `1.0085x`, with zero wrong
  answers or errors. Hot-400 gate `142867`/`142871` is the next promotion
  boundary.
- Completed corrected equality-shadow telemetry on all 7,503 instances in
  `142801`/`142803`. The abstraction applied to 7,401 inputs, found useful
  star edges on 4,610, and consumed 1.46% of successful solver time in
  aggregate; hardened same-binary facts gates now use explicit fresh-atom and
  quota settings.
- Found that the WMI A/B harness still forced the obsolete `varisat`
  invalid-model fallback although the promoted Linux solver defaults to
  `cadical-refine`. Commit `94c86c0` aligns the harness with production;
  historical exact-environment results remain valid, but all live promotion
  candidates are being rerun under the corrected default.
- Rejected the clique-core finite-support revision after hot-400
  `142867`/`142871` lost two solves and regressed all-total to `0.980x`,
  common-total to `0.961x`, and geometric speed to `0.973x`.
- Added `off|auto|on` scoped-let routing at the predeclared 512-let threshold.
  Production-config deep gate `142892` added one solve and sample gate `142895`
  held 37/37 while passing all three speed criteria. Hot-400 is running.
- Scoped-let auto then passed hot-400 `142918`/`142926` and complete corpus
  `142952`/`142996`. The full gate improved coverage `7,219 -> 7,249`,
  all-total `1.0337x`, common-total `1.0165x`, and geometric speed `1.0072x`,
  with no losses or errors. All 30 gains are being repeated on c2n1 and c3n1.
- Seven-repeat confirmations completed: c2n1 `143029`/`143033` recovered 29
  additional solves and improved all-total `2.598x`; c3n1
  `143034`/`143039` recovered 15 and improved all-total `1.272x`. Neither had
  a baseline-only case. Scoped-let `auto` is promoted.
- Deferred typed-sort diagnostics to parse-error paths in commit `991d700`.
  Sample gate `143080` recovered all-total/common speed to `1.0023x`/`1.0038x`
  but geometric speed remained `0.9971x`; typed parsing is not promoted yet.
- Completed fresh exact-binary four-solver campaign
  `143049`/`143051`/`143052`. Coverage was euf-viper 6,948, Z3 7,176, cvc5
  6,926, and Yices2 7,434, with no wrong answers, disagreements, or errors.
  Against Z3 on 6,907 common solves, euf-viper was `1.119x` faster by total and
  `2.083x` geometrically, but Z3 added 228 net solves. Yices added 486 net
  solves and remained about `3.46x` faster by common aggregate time.
- Broad equality facts remained rejected, but the frozen
  `guarded_disequality_clauses > 0` selector covered only 55/7,503 instances.
  Five-repeat gate `142947`/`142951` improved coverage `18 -> 29`, all-total
  `1.2086x`, common-total `1.4738x`, and geometric speed `1.4191x`, with no
  losses or errors. An explicit non-default routed mode is being implemented.
- Added compact typed-sort tracking for terms and full function signatures as
  the soundness prerequisite for definitional substitution. Cross-sort
  equality and application errors are rejected; 90 all-feature release tests
  pass. The typed parser remains unpromoted until its own speed gates pass.
- Implemented exact non-default equality mode `guarded-facts` in `cce247b` and
  froze WMI binary
  `d26631dec1cd5c6df2c5f145e7d5597ac630cdf427e0eb80ca7ba7508eb31881`.
  Five-repeat sample `143160` passed at 37/37 with all-total `1.0006x`,
  common-total `1.0012x`, and geometric `1.0018x`.
- Rejected `guarded-facts` after selected-population gate `143161` stayed
  29/29 and regressed all-total/common/geometric speed to
  `0.9960x`/`0.9852x`/`0.9816x`. All 11 historical fact-only gains are now
  baseline solves due to the promoted scoped-let parser, so hot-400 and full
  gates were intentionally not launched.
- Replaced typed function-declaration hash lookups with dense indexed storage
  in `1820fef`. Isolated sample `143178` kept 37/37 and passed all speed gates:
  all-total `1.0102x`, common-total `1.0203x`, geometric `1.0129x`.
- Direct typed+dense versus accepted pre-typed gate `143188` kept 37/37 but
  failed all speed gates at `0.9962x`/`0.9923x`/`0.9835x`. Dense lookup stays
  in the research branch, while the accepted production binary remains
  `58efe9d`; next optimize only redundant checks for already interned terms.
- Tested exact-term reuse with a borrowed per-function interning index in
  `f7b52fb`. Isolated sample `143202` stayed 37/37 and was effectively flat:
  all-total `0.99995x`, common-total `0.99987x`, geometric `1.00003x`. The
  strict gate failed, so `d69792a` reverted it before broader campaigns.
- QG phase profile `143209` found typed+dense parse medians faster on all four
  completed controls. Removing the rejected guarded-facts finite context in
  `93e2d90` nevertheless failed isolated sample `143220`: all-total `0.9992x`,
  common-total `0.9985x`, geometric `1.0036x`. `92a7a8f` restored the code.
- Seven-repeat c2n1 gate `143228` confirmed typed+dense remains slower than
  accepted `58efe9d`: 39/39 coverage, all-total `0.9997x`, common-total
  `0.9995x`, geometric `0.9876x`.
- Worst-loss profile `143224` measured the typed branch at 0.9860x geometric
  parse speed. A global-interner `HashMap::entry` fast path in `d5a0e14`
  worsened aggregate timing and failed isolated sample `143232` at
  `0.9935x`/`0.9873x` despite 1.0032x geometric speed. `aaffae3` reverted it.
- Global-get fast path `4a0ff44` improved worst-10 parse/end-to-end profile
  `143241` by `1.0337x`/`1.0167x`. Seven-repeat sample `143239` still failed
  geometric speed at `0.9955x` while aggregate metrics passed
  `1.0011x`/`1.0021x`; `6973ed4` reverted it.
- Unique-term post-parse validation `5f67b6f` preserved strict diagnostics and
  improved worst-10 profile `143246` by `1.0127x` parse and `1.0159x`
  end-to-end. Seven-repeat sample `143244` stayed 37/37 and measured 1.0017x
  geometric speed, but all-total/common-total regressed to
  `0.9931x`/`0.9865x`; reject before broader gates.
- Built a profile-guided binary from accepted source `58efe9d`. It passed the
  40-case control but failed the disjoint 512-case holdout: coverage
  `480 -> 476`, all-total `0.9964x`, common-total `0.9945x`, geometric
  `1.0203x`. Global PGO is rejected.
- Added deterministic structural binary-router training and independent
  evaluation with median aggregation, source-SHA folds, forbidden-feature
  enforcement, and hard coverage/speed gates. All 43 repository Python tests
  passed after the initial implementation; the focused router suite has six
  tests.
- Five-fold routing on the PGO holdout preserved 480 baseline solves, routed
  74/512 held-out cases, and projected `1.00040x` all-total, `1.00075x`
  common-total, and `1.00407x` geometric speed. Its frozen
  `equalities <= 579` rule passed the independent 40-case control but improved
  all-total by only `1.00010x`. Reject an external launcher because its
  overhead would dominate the measured margin.
- Completed exact 60-second campaign `143248`/`143249`/`143254`. Coverage is
  euf-viper 7,478, Z3 7,490, cvc5 7,473, and Yices2 7,500, with zero wrong
  answers, disagreements, errors, or failed shards. Viper beats Z3 on 5,811
  of 7,466 common solves and is `1.888x` faster geometrically, but loses
  common aggregate time at `0.723x`; Yices leads both speed and coverage.
- Archived the complete 60-second run and exact manifest under
  `results/wmi/four-solver-60s-143248/`. Submitted the hash-pinned
  1,200-second timeout-only continuation as prep `143382`, array `143383`, and
  merge `143384`; it is running and no final result is claimed.
- Reconsidered the rejected focused-permutation technique as a conjunction
  with the promoted lexical-let selector. The exact selector population is 17
  NEQ files with at least 512 `(let` forms. Historical two-second rows
  projected 1.145x all-total and two added solves on that population.
- Current exact-binary job `143412` confirmed the interaction at three repeats
  and 60 seconds: coverage 17/17 -> 17/17, all/common-total 1.6475x, geometric
  1.8109x, 13 candidate wins, four baseline wins, zero wrong answers or
  errors. `NEQ027_size11` improved from 56.39s to 1.16s median. Proceed to an
  automatic deep-let route only after restoring the accepted source lineage.
- Five-repeat two-second boundary `143438` then improved coverage `9 -> 12`,
  all-total `1.2357x`, common-total `1.1934x`, and geometric speed `1.1670x`.
  `NEQ027_size10`, `NEQ027_size11`, and `NEQ031_size10` were candidate-only in
  all five repeats; there were no baseline-only cases, wrong answers, or
  errors.
- Confirmed a critical Boolean-as-data soundness defect in both the current
  local build and exact accepted WMI binary. The formula with `p,q,r : Bool`,
  `f : Bool -> U`, and three distinct values `f(p),f(q),f(r)` is UNSAT, but
  euf-viper returns SAT while Z3 and cvc5 return UNSAT. Added the permanent
  fixture and incident record. Broad soundness claims are revoked.
- Audited lazy-first refinement. Its model-cut logic is viable only after
  atomizing all Boolean data terms and rejecting or safely completing
  theory-relevant CaDiCaL `DontCare` assignments. Finite preprocessing remains
  loaded, fallback must expose its reason, and current certificates are
  independent eager reconstructions rather than exact lazy-path proofs.
- Completed the hard-tail mechanism audit. The next measured mechanisms after
  correctness are verified domain-7 orbit breaking over 261 exact one-table
  cases, Boolean-DAG hash-consing over 174 large closed-table cases, and a
  conflict-only partial-trail rollback e-graph over the 39 large non-table
  equality graphs. Each has a strict targeted gate before broader testing.
- Completed and fetched the exact 1,200-second continuation
  `143382`/`143383`/`143384`. Coverage is 7,502 euf-viper, 7,500 Z3, 7,495
  cvc5, and 7,503 Yices2, with zero wrong answers or errors. Euf-viper narrowly
  beats Z3 by full timeout-charged total, 8,575.78s versus 8,676.80s, but loses
  common-solve aggregate time at `0.6939x`. Yices2 totals 2,010.00s and remains
  the overall target.
- Reverted rejected source commit `5f67b6f` as `bb07f2e`, then committed the
  global Boolean-data and total-model repair as `56c56f6`. The same repair was
  ported onto exact accepted source `58efe9d` as branch
  `soundness/accepted-58efe`, commit `53c12f7`. The exact branch passes 91
  all-feature tests and returns UNSAT on the counterexample through all four
  local backend routes.
- Launched the no-compromise novelty program with six independent agent
  audits. The primary-source exclusion map rejects fifteen false novelty
  claims; the Z3/Yices source audit confirms that another rollback e-graph,
  dynamic Ackermannizer, or symmetry-clause pass would reproduce occupied
  design space.
- Froze six distinct mechanism tracks: pre-CNF complete-model scouts,
  theory-conditioned Boolean quotient compilation, certified multi-table
  orbit quotienting, bit-sliced quotient swarms, SAT-native quotient-state
  search, and proof-complexity-triggered component migration. Initial WMI job
  `143674` failed before computation because of a submit-directory mistake;
  its blocked dependents were cancelled. Corrected soundness `143680`,
  sample-40 A/B `143681`, and 10,000-case differential `143682` now guard the
  baseline.

## 2026-07-11 Sound Candidate And Novelty Gates

- Repaired the WMI differential harness after job `143682` exposed quota and
  launcher failures. Corrected canary `143696` agreed with Z3 and cvc5 on 169
  formulas. Full job `143698` ran 10,041 formulas: 3,729 SAT, 6,311 UNSAT, zero
  euf-viper discrepancies, and one common timeout. Hash-pinned retry `143728`
  returned UNSAT in all three solvers.
- Exact sound-repair sample `143697` preserved 39/40 coverage and had zero
  wrong answers or errors, but the repaired candidate was slightly slower:
  `0.9940x` common-total and `0.9828x` geometric speed. The paired statistical
  gate rejects it as an optimization; it remains a mandatory repair.
- Full repair array `143700` and merge `143701` are running with 64 shards,
  three measured repeats, one warmup, and identical environments.
- Independent review found two additional parser soundness failures: quoted
  reserved identifiers were dispatched as built-ins, and assertions after an
  early `check-sat` were silently included. Commit `ad1a3ae` preserves quoted
  tokens and rejects unsupported multi-query mutation. Release fixtures return
  SAT for quoted `|true|` and `|not|`, and exit 2 for post-query assertion.
- Added a fail-closed paired promotion gate and made four-solver WMI scripts
  relocatable across source, solver, corpus, and binary roots. Local gates now
  pass 198 Rust tests and 86 Python tests.
- The domain-seven `iso_icl_nogen001` probe extracted 5,040 unique complete
  binary operation tables. Exact enumeration proved all are the one free
  `S_7` orbit, with no missing, malformed, or foreign table. The Boolean census
  found 497,474 occurrences, 11,370 syntactic nodes, and only 42 additional
  unconditional-theory quotient reductions.
- Added test-only reference implementations for complete SAT model scouts,
  Boolean DAG telemetry, exact table canonization, forbidden-orbit extraction,
  bounded quotient CSP with Hall propagation, and exact base-invariance/orbit
  certificates through degree eight.
- Added a fail-closed multi-valued decision-diagram oracle for forbidden
  operation tables. Its exhaustive checker covers every binary two-cell
  forbidden subset under two orders, ternary singleton subsets, and the full
  19,683-table degree-three space; it remains test-only until corpus telemetry
  demonstrates a clause or propagation advantage over one-hot CNF.
- Added default-off `EUF_VIPER_DIRECT_NEGATED_ROOT`. It emits one clause for a
  root `not(and(...))` instead of a Tseitin support variable and clauses. The
  implementation has exhaustive truth-table, edge-case, Bool-as-data, and
  dynamic-Ackermann rebuild tests.
- Synced exact source commit `b39706e7243c97d3950fceef636ea56a1f8b04c6`
  to WMI. Soundness build `143747` uses node-local Cargo storage and persists
  only the tested binary. Same-binary qg7 A/B `143751`, profile `143758`, full
  four-solver array `143752`, and merge `143753` depend on that gate.
- Literature and source-boundary review ranks canonical forbidden-table
  quotienting, stabilizer-aware MDDs, EUF-structured BVA, certifying Hall/PB
  escalation, and theory-aware vivification above another generic lazy
  e-graph. Each mechanism has a falsifiable paired gate in the vault.
- Full mandatory-repair A/B `143700`/`143701` completed with zero wrong answers
  and 7,273 common correct instances. The repair is measurably slower and loses
  two boundary solves: total `0.9974x`, geometric `0.9940x`, median `0.9963x`.
  The statistical gate correctly rejects it as an optimization while the
  correctness change remains mandatory.
- Research-main soundness `143747` passed. Same-binary direct-negated-root
  rerun `143792` then timed out in both arms on all 14 qg7 targets. Profile
  `143758` shows 734,066 to 718,946 CNF items and 51.52ms to 46.98ms CNF time
  on `iso_icl_nogen001`, but no proof or coverage change; reject the mechanism
  for this tail rather than broadening it.
- Parser metamorphic job `143765` gave euf-viper zero anomalies on 1,620 cases.
  Its strict failure records comparator behavior separately: cvc5 rejected 18
  quoted-reserved groups, Yices2 rejected 21, and Z3 contradicted two generated
  expectations. Candidate gating now preserves all comparator anomalies but
  fails the job only on euf-viper's generator-known or metamorphic obligations.
- Created the fastest sound exact lineage `soundness/exact-parser-negroot`.
  Commit `ebf8e27` contains the Boolean-data repair, quote/query-order repair,
  default-off negated-root experiment, a self-contained counterexample
  fixture, and no compile-disabled typed-parser residue. WMI soundness
  `143794`, differential `143796`, parser `143797`, full array `143798`, and
  merge `143799` are hash-pinned to this lineage.
- Exact soundness `143794` passed: 100 branch tests, the Boolean-data UNSAT and
  quoted SAT fixtures through `auto`, `varisat`, `cadical`, and
  `cadical-refine`, plus exact query-order rejection. Persisted binary SHA-256
  is `38421e03b51fae69c354258614f25d507409a689e7fb70981b51328f23e4412a`.
- Exact parser gate `143811` passed candidate policy on all 1,620 cases and 550
  groups with zero euf-viper failures. Generated cases now live on node scratch
  and are persisted as one compressed source archive plus manifest, results,
  and summary, preventing WMI file-quota failures without losing replayability.
- Integrated four new test-only research references: exact multi-valued table
  MDDs, globally checked stabilizer-aware cell ordering within caps,
  certificate-replayable quotient-state search, and table-aware semantic BVA.
  The integrated suite passes 220 Rust and 107 Python tests.

## 2026-07-11 Measured Novelty Gates, Round 2

- Repaired the exact Boolean differential artifact contract in `7929e87`.
  Computation `143810` covered 10,041 formulas with zero reference failures
  and zero euf-viper discrepancies; the old wrapper failure was solely missing
  persisted manifest/results files.
- Full novelty census `143814` parsed 7,503/7,503 formulas. The current two
  complete-model scouts hit only 4/3,142 SAT cases and are rejected. The
  unconditional quotient affects 4,058 formulas and removes 668,507 unique
  Boolean nodes, 3.8935% globally and 7.4559% among affected formulas.
- Rejected isolated Kissat loading, borrowed atoms, and `x86-64-v3` after
  soundness gates: none produced a statistically supported end-to-end win.
  Borrowed atoms still cut parser phase medians by 1.26--1.36x and therefore
  motivate a whole-tree elimination rather than another ownership tweak.
- SmallVec clause storage `0a37b0f` passed hot-80 `143825` and disjoint
  hot-320 `143826`. The holdout has 320/320 correctness, 244 wins, 1.0160x
  total, 1.0376x geometric, 1.0326x median, all lower confidence bounds above
  one, and p=`0.00009999`.
- Resource gate `143861` adds 1,920 paired observations. Candidate summed
  median RSS is 0.9847 of baseline and geometric RSS is 0.9917, with both 95%
  intervals below parity; maximum RSS is unchanged. Full array `143842` and
  merge/gate `143843` now decide promotion.
- Automatic deep-let candidate `3426e63` passed soundness. At two seconds it
  improves coverage 9 -> 13 and common total by 1.3146x. At 60 seconds
  `143851` solves all 17 in both arms and improves total/geometric speed by
  1.6357x/1.8593x, but its median lower bound is 0.9984. The gate remains
  rejected without changing thresholds.
- Pre-registered refinement `88bcede` enables automatic focused permutation
  support only for verified domain size at least six while preserving explicit
  overrides. Soundness `143876`, exact A/B `143877`, and causal A/B `143878`
  are running.
- Leaf quotient `414b109` passed soundness `143829`, 2,041-case Boolean-data
  differential `143832`, and parser differential `143866` with zero candidate
  failures. Target-90 `143830` adds two Goel solves but loses median speed at
  0.9854x and has p=`0.3657`; reject it as a general route. Exploratory Goel-20
  60-second job `143865` tests tail value only.
- Qg7 census `143840` persisted all 418 cases: 174 exact first-orbit covers,
  122 partial width-49 patterns, and 122 without exact patterns. Exact cases
  split into 120 width-6, 52 width-49, and 2 width-5 formulas.
- Added test-only degree-7 right-translation Algorithm-X shadow search in
  `a1749dc`: deterministic MRV, flat pattern bitsets, explicit caps, and
  independent SAT-witness replay. SAT/UNSAT refer only to the Latin
  pattern-avoidance abstraction and cannot answer the SMT formula.
- Added a hashed GNU-time peak-resource comparator and WMI wrapper in
  `bc27b33`/`dcd9bf5`. Main now passes 113 Python tests.
- Started exact-lineage one-pass parser branch `perf-exact-stream-parser`.
  The design keeps the tree parser as oracle/fallback and requires semantic
  snapshot parity in `shadow` mode before any timing run.
- Full SmallVec array `143842` and merge `143843` completed 45,018 observations
  over all 7,503 instances. Every timing check passed: 1.0089x total, 1.0380x
  geometric, 1.0328x median, all 95% lower bounds above one, and paired
  p=`0.00009999`. The strict quality gate still rejects global promotion:
  `PEQ019_size7` is baseline-only correct, there are 11 baseline-only versus
  10 candidate-only samples, and sample coverage is -1. A path-independent
  depth-two router preserves coverage but retains only 1.00006x all-total and
  1.0010x geometric speed, so routing this representation is also rejected.
- Domain-six deep-let refinement `88bcede` passed soundness `143876`. Exact
  gate `143877` improved coverage 14 -> 15, but the causal comparison
  `143878` against the original deep-let candidate lost all 15 common cases
  and measured 0.9825x total. Reject the refinement; retain the original
  deep-let mechanism as default-off, unpromoted research.
- Leaf quotient Goel-20 `143865` solved 20/20 versus 18/20 and improved common
  total/geometric time by 2.8368x/3.4791x. The broader 773-case Goel run
  `143887` solved 760 versus 752 with no baseline-only result, but regressed
  median speed to 0.9852x; reject uniform activation.
- A frozen, path-independent structural rule, canonical unique Boolean-node
  reduction at least 1,000, selected 32 formulas. At 60 seconds and three
  repeats, `143923` improved coverage 30 -> 32 and common total/geometric/
  median speed by 2.6275x/2.2127x/1.4464x, with all lower bounds above one.
  Commit `d2f3946` adds a fail-closed promotion policy that accepts only
  baseline-timeout to candidate-correct gains and still rejects every reverse
  transition; the structural route passes that policy.
- Four-solver structural-slice job `143950` prevents an inflated claim. Forced
  leaf quotient solves 31/32, versus Z3 29/32 and cvc5 26/32, but Yices2 solves
  32/32. On 31 common euf-viper/Yices2 solves, Yices2 wins every instance and
  is 23.11x faster geometrically; total correct time is 5.96s versus 97.58s.
  The route is a coverage mechanism against Z3/cvc5, not a Yices2 timing win.
- Hardened RTXC census `143938` analyzed all 418 qg7 records. Exactly 164 pass
  the final structural eligibility checks, and every one of the 164 abstract
  searches is SAT; there are zero abstract UNSAT or ABSTAIN outcomes. The weak
  Latin pattern-avoidance abstraction is rejected as an UNSAT engine.
- Source audit of those 164 cases found 146 source-SAT `brn` formulas and 18
  source-UNSAT `icl` formulas. The shadow search omits `R_y^3=id`, diagonal,
  left-fixed-point, absorption, involution, implication, and 314 Skolem-symbol
  obligations. In anti-idempotent cases, checked local cycle constraints reduce
  each right-translation domain from 5,040 to 240 candidates. The next RTXC
  version must consume every source assertion or abstain.
- Stream-parser commit `86b1266` passed WMI soundness `143952` with 122 tests
  and all backend fixtures. Independent review closed internal-symbol,
  speculative-mutation, token-boundary, and deep-nesting blockers. Timing is
  still blocked on a parse-only full-corpus shadow gate.
- Auto leaf-route commit `1cd9ec4` implements the exact reduction-at-least-1000
  rule with fail-closed caps, profile telemetry, and dynamic-Ackermann plan
  reuse. Its 121 default and all-feature tests pass; independent review and WMI
  soundness precede any timing campaign.

## 2026-07-12 Broad Clause-Store Promotion And Guarded Eager Follow-Up

- Flat persistent clause storage `2274c75` passed WMI soundness `144006`, a
  320-instance timing/resource gate, and full 7,503-instance array `144072`.
  The full merge contains 45,018 observations with zero wrong answers or
  execution errors. Coverage improves `7,418 -> 7,419`; common-total,
  geometric, and median speedups are `1.0071x`, `1.0309x`, and `1.0314x`.
  Their 95% lower bounds are `1.0065x`, `1.0303x`, and `1.0304x`, with paired
  p=`0.00009999`. The one-way timeout policy records seven candidate-only
  repeat conversions and no reverse loss. This mechanism is promoted.
- Cherry-pick `3c178dc` integrates flat clauses onto current main. Local
  integration passes 228 Rust tests (four ignored research probes) and 122
  Python tests plus 203 subtests. WMI soundness jobs `144213` and `144214`
  passed for candidate and pre-integration baseline. Current-lineage full
  array/merge `144224`/`144225` improves coverage `7,418 -> 7,421`, common
  total `1.0094x`, all total `1.0073x`, geometric `1.0320x`, and median
  `1.0323x`; every confidence bound passes. The strict merge mechanically
  rejects one reverse timeout sample on `PEQ014_size9`, despite zero
  baseline-only instances and eight candidate-only samples. Pinned same-node
  31-repeat adjudication `144309` solves 31/31 in both arms and favors flat
  clauses by `1.0225x`; retain the promotion and preserve the raw reject.
- Auto quotient `1cd9ec4` passed soundness, a 2,041-case Boolean-data
  differential, and its frozen 32-case gate. Full array/merge `144056`/`144061`
  rejects default activation: coverage is `7,271 -> 7,272`, but common-total,
  all-total, geometric, and median speed are `0.9970x`, `0.9995x`, `0.9940x`,
  and `0.9974x`. There are two baseline-only and three candidate-only correct
  instances, ten reverse timeout samples, and every speed confidence lower
  bound is below parity. Preserve the selected-slice evidence only.
- Successor `550853b` moves the exact 696-root-equality prefilter ahead of
  quotient-plan allocation. It passes 122 all-feature tests and WMI soundness
  `144205`. Causal hot-320 rerun `144222` preserves 320/320 coverage but is
  neutral at `0.9998x` total and `1.0004x` geometric speed. Independent review
  also finds that the term-count cap moved after the scan and the new test does
  not demonstrate allocation avoidance. Do not launch a full successor gate
  before both defects are repaired and a causal allocation result exists.
- Forced leaf quotient plus full Ackermann is a real but unsafe interaction.
  Six Goel profiles improve by `19.27x` geometrically, while a 32-case mixed
  run loses `NEQ033_size6` to OOM and slows every PEQ/SEQ control. Profile
  `144074` records 8,137 applications, 10,136,258 Ackermann clauses, and
  341,413 fill edges before the OOM. A path-independent guard separates the
  measured sets at 256 applications, but commit `17256eb` remains blocked by
  review until base-CNF, arity, fill-work, and backend-routing bounds are
  complete.
- Polarity-aware component-local class labels project 2.57--6.79x fewer
  completion watches than triangle transitivity on six Goel profiles. Even a
  zero-cost triangle stage would leave the measured route about 3.07x behind
  Yices2, and exact sort metadata is currently missing. Treat this as a
  bounded engineering experiment, not an algorithmic novelty claim.
- Parser and qg research campaigns remain fail-closed. Parser commit
  `19c9a4d` closed initial hash/count/fallback defects but a second audit
  requires expected manifest hashes, exact opened-byte execution, and atomic
  checkpoint generations. Qg commit `fdf9dee` now builds from a clean pinned
  `git archive` and atomically publishes validated source-bound JSONL. Final
  wrapper audit still blocks WMI because early preflight failure can preserve a
  stale final JSONL and the containing directory is not fsynced after rename.

## 2026-07-12 Fresh Comparator And Source-Bound QG Census

- Exact current-main four-solver campaign `144328`/`144329`/`144330` ran all
  7,503 SMT-LIB 2025 QF_UF inputs at two seconds. The euf-viper binary is
  `3c178dced8eb44e13a6381bdc43290c71658ac40`, SHA-256
  `808c59ceef559062bb61befea2030b16b890bd18b8936a98d1ea3bc3172903ff`;
  the campaign manifest SHA-256 is
  `32aba287e33c5665847f0a0a71311da6214feb5e69f458877ba02ef96976a2d4`.
- Coverage/median/timeout-charged total are euf-viper
  `7,408`/`0.00939s`/`885.69s`, Z3 4.16.0
  `7,450`/`0.02199s`/`639.66s`, cvc5 1.3.4
  `7,373`/`0.03061s`/`976.53s`, and Yices2 2.7.0
  `7,490`/`0.00504s`/`228.56s`. All 30,012 observations are present with zero
  wrong answers or execution errors.
- On common solves, euf-viper versus Z3 has `1.5666x` geometric but `0.7467x`
  aggregate speed, with 33 euf-viper-only and 75 Z3-only instances. Against
  cvc5 the ratios are `2.1886x` geometric and `1.0823x` aggregate. Against
  Yices2 they are `0.3543x` geometric and `0.2374x` aggregate, with four
  euf-viper-only versus 86 Yices-only instances. No overall Z3/Yices win.
- A first submission chain `144321`/`144322`/`144323` was cancelled after an
  incorrect expanded revision label was detected. Its rows are invalid and
  unused; the replacement chain above records the exact revision and binary.
- Source-bound qg7 census `144349` ran from clean Git-backed commit `9fc09e8`,
  with source archive SHA-256 `9fc95dc7...a13d2` and output SHA-256
  `854360a5...63950`. It publishes exactly one provenance plus 418 unique case
  records; all source/problem bindings verify. Only 31 cases remain eligible:
  12 produce a shadow witness and 19 abstain on a remaining source predicate.
  The other 387 fail closed. There are zero shadow refutations, so this route
  remains test-only and adds no production coverage.
- Bounded Ackermann commit `7bf410b` passes Linux soundness `144317` with 138
  tests and binary SHA-256 `c6d6080d...5605a`. Timing job `144371` is invalid
  because its old harness omitted quotient and leaf-budget child environments;
  corrected causal rerun `144631` uses the newer recorded-environment harness.
- Corrected causal gate `144631` ran 32 instances, three repeats, and a 60-second
  timeout with quotient `auto` in both arms. Baseline full Ackermann `auto`
  solves 32; candidate `leaf-budget` solves 31 and loses
  `frogs.4.prop1_ab_br_max`. On 31 common solves the candidate is `1.8056x`
  faster by aggregate and `2.2359x` geometrically, but timeout-charged all-case
  speed is `0.9894x` (`130.1600s` versus `131.5499s`). There are zero wrong
  answers or execution errors. The candidate is rejected and remains off.
- Archived the corrected JSON/CSV and logs under ignored directory
  `results/live-2026-07-12/ack-144631/`; JSON SHA-256 is
  `207f54690201516a8650070c310c04e49db12e8d90748e638874fe179f8f6c83`.
- Preserved the paired exact-byte parser harness at research commit `58f015b`
  after 49 tests and 45 subtests passed. Preserved the mode-gated quotient
  census at `eae27d0` after all 136 Rust tests passed. Neither candidate is
  merged: the parser has no corpus performance gate, and the quotient follow-up
  did not demonstrate an off-mode speed win.
- Cancelled eleven superseded pending `euf-viper` WMI jobs from earlier failed
  or replaced chains. The final queue contains no `euf-viper` job; unrelated
  `sg-lean` and `echo-exp1` workloads were left untouched.

## 2026-07-12 Best-Overall Campaign Design

- Reconciled every unchecked historical `PLAN.md` item against current source
  and WMI evidence. Base-CNF reconstruction, independent result validation, and
  a class-code prototype remain genuinely open. Typed-sort optimization,
  deep-let permutation, old exact-lineage jobs, qg ledger, flat clauses, orbit
  recognizer, one-pass parser promotion, and automatic leaf quotient were
  completed, superseded, rejected, or explicitly parked.
- Corrected the primary benchmark scope. SMT-COMP 2025 QF_Equality includes
  3,521 selected QF_UF cases; Yices2 solved the complete division and OpenSMT
  ranked second. The next campaign adds exact selection ingestion and OpenSMT
  rather than relying only on the 7,503-file library sweep.
- Audited current solver dependencies and found that production Linux still
  embeds a SAT Competition 2021 Kissat wrapper. Modern Kissat 4.0.4 plus
  congruence, sweeping, factor/BVA, vivification, and phase ablations is now the
  first performance control. Z3 default and `sat.euf=true` are separate controls.
- Defined the primary architecture as proof-complexity-triggered per-component
  migration among eager clauses, rollback EUF, quotient/class coding, and
  adequate-range Hall/PB. Supporting tracks cover a staged typed formula
  machine, theory-conditioned Boolean DAG factoring, SAT-aware explanations,
  and conditional canonical frontier/bit-sliced quotient search.
- Added machine-readable preregistration
  `campaigns/best-overall-qf-uf-2026-07.json`, its validator and tests, the full
  vault design, a primary-source refresh, and a Jupyter Book chapter. Phase P0
  blocks heavy submission until comparator/corpus hashes, grouped holdouts,
  normalized resource controls, campaign locks, and independent proof/model
  paths are complete.
- Added `.github/workflows/campaign-contract.yml` so pull requests and pushes
  validate the exact comparator/corpus/budget/track/promotion contract and its
  negative tests before campaign changes can land.

## 2026-07-12 Phase P0 Implementation

- Reconstructed the exact 3,521-instance SMT-COMP 2025 QF_UF selection from
  official single-query results at source commit `82b2c91e`. The portable
  selected manifest SHA-256 is `ed00b0e2...2aaa6`; its source result archive is
  pinned as `d79dd5d6...4a1e`.
- Added OpenSMT 2.9.2 to the installer and legacy comparator path. Official
  platform archives for Z3, cvc5, Yices2, and OpenSMT plus source commits for
  all controls and Kissat 4.0.4 are bound by
  `campaigns/solver-releases-2026-07.json`. The WMI Z3 fallback now uses the
  official hash-pinned manylinux 2.27 wheel rather than an index-resolved pip
  installation.
- Implemented deterministic source-family and generator-lineage taxonomy,
  token-level SMT-LIB normalization, near-duplicate closure, and sealed family
  holdouts. A path-only audit recognizes all 7,503 files across nine source
  families and 5,796 lineages; the full 957 MB fingerprint pass is delegated
  to WMI.
- Implemented immutable campaign freezing, exact child shard locks, runtime
  binding to the first SLURM-allowed CPU, cold sequential process execution,
  process-group timeout cleanup, affinity/RLIMIT enforcement reporting,
  CPU/RSS accounting, balanced solver order, chained journals, atomic resume,
  and strict artifact drift checks.
- Implemented exact paired analysis with wrong-answer fail-closed behavior,
  PAR-2, common totals/geometric ratios, SAT/UNSAT and family macro summaries,
  exact McNemar, deterministic family-cluster bootstrap, Holm correction, and
  promotion adjudication.
- Replaced the certificate trust boundary. `certify` now uses only base
  canonical Tseitin clauses plus lazy EUF lemmas, emits total SAT assignments,
  and emits DRAT for UNSAT. A separate Python parser reconstructs typed QF_UF,
  base CNF, terms, and atoms from the original source. Five UNSAT fixtures and
  a 1,002-variable SAT fixture pass independent reconstruction/model/lemma
  checks; every UNSAT proof also passes DRAT-trim.
- Added a durable WMI P0 prepare/full/official/audit dependency chain. It
  verifies the committed selection, computes family taxonomies, records six
  exact solver configurations including Z3 `sat.euf=true`, freezes only the
  two-second budget, derives 64 shards, binds each allocated CPU, and audits
  every shard. The audit reconstructs each bound shard from the parent lock,
  requires a complete disjoint partition, and computes one global analysis per
  corpus rather than treating shard-local samples as promotion evidence. No new
  performance claim is made before those rows return.
- Verification at this checkpoint: 217 Python tests pass; Rust all-feature
  suite passes 228 tests with four environment-dependent tests ignored; the
  independent certificate smoke passes; campaign JSON and all new shell
  scripts validate.
- Published implementation commit `c2ed5d8`. Hosted run `29199552439` then
  exposed four certificate-prefix tests that depended on ignored local
  `results/cert-smoke` output. Replaced that dependency with tracked,
  source-hash-bound Rust prefix goldens in `70f0a60`; hosted run `29199707319`
  passes all campaign, Python, shell, and Rust steps.
- Cancelled still-pending superseded chain `144763`–`144766` without consuming
  benchmark time. Submitted fixed revision `70f0a60` as prepare `144767`, full
  array `144768`, official array `144769`, and global audit `144770`. The
  dependency chain was durable and initially pending WMI capacity.
- On the requested project pause, cancelled `144767`-`144770`; prepare had not
  produced a campaign lock or benchmark row. Resumed from the preserved local
  checkpoint the next day.
- Added schema-v2 timeout-only continuation locks, exact sparse sharding,
  runner/source hash lineage, adjacent 2/60/1,200-second assembly, and a
  per-observation ledger back to physical lock/raw/run hashes.
- Added fail-closed certificate-shadow execution with hash-chained resumable
  journals, explicit zero-work shards, global journal/artifact replay, generic
  physical-stage WMI campaigns, and a staged union audit matching certificates
  to each final solve's origin budget. No superiority result follows yet.
- Release gate: 261 Python tests and 228 Rust tests pass; four Rust probes remain
  intentionally environment-gated. All campaign shell scripts parse, Python
  entrypoints compile, Rust formatting is clean, and the independent SAT plus
  five-UNSAT DRAT certificate smoke passes.
- Published `1308be8` and obtained green hosted run `29212534371`. Initial WMI
  chain `144817`/`144818`/`144819`/`144821` exposed that P0 still built the
  benchmark binary without the opt-in `certificates` feature. Cancelled it 38
  seconds into preparation, before any array ran, and changed preparation to
  lock one certificate-capable binary for both timing and proof emission.

## 2026-07-13 Resume And T0 Control

- Published corrected certificate-capable baseline revision `b46b137`; hosted
  run `29212660080` passed. Submitted immutable P0 prepare/full/official/audit
  jobs `144823`/`144824`/`144825`/`144826`, continuation dispatcher `144827`,
  and base full/official certificate chains `144828`-`144833`. At this entry,
  prepare is still computing the 957 MB taxonomy and no benchmark row exists.
- Three source audits separated the next mechanisms. The broad Goel loss is
  dominated by repeated complete-model validation (`frogs.3`: 25.66s
  validation versus 2.41s SAT); the finite track needs source-certified
  non-uniform ranges and Hall evidence; production Linux still embeds Kissat
  SC2021 and ignores `EUF_VIPER_KISSAT_MODE`.
- Cheap same-binary CaDiCaL congruence control on
  `QG-classification/loops6/iso_icl053.smt2` reduced conflicts `62 -> 51` and
  decisions `69 -> 59`, but a 20-pair local ABBA regressed median end-to-end
  time from `8.055` to `9.737` ms (`1.209x` slower; mean `1.204x` slower).
  Reject unconditional CaDiCaL congruence as a broad route; do not promote
  from solver-internal counts.
- Added a separate pinned Kissat 4.0.4 backend while retaining SC2021 as the
  default control on public branch `research-modern-kissat`. Final validation
  commit `d7c14da` exposes fail-closed mode/option ablations, records the linked
  backend in `--version`, fully namespaces Kitten against CaDiCaL, and keeps
  Linux `--all-features` valid by selecting Kissat 4.0.4. Hosted run
  `29213778114` passed on the solver commit and final hosted run `29214335958`
  passed on `d7c14da`.
- WMI paired artifact job `144945` completed in 74 seconds from cache. Default
  SC2021 tests passed `222` with three environment probes ignored; modern
  all-feature tests passed `228` with four ignored. Both binaries pass shared
  SAT/UNSAT fixtures, and modern certificate smoke passes against pinned
  `drat-trim` SHA `58a121de...943e5`. Exact release hashes are SC2021
  `d7321602...c70362` and Kissat 4.0.4 `ecbcfebb...ea6b6`. No timing result or
  performance promotion follows yet.
- P0 prepare `144823` finished the expensive full and official taxonomy passes
  but then failed before campaign-lock creation. The old-glibc Z3 C-API runner
  accepted only one filename while the frozen `z3-sat-euf` control correctly
  invoked `z3 sat.euf=true FILE`. Full taxonomy/split hashes are
  `ecab4f1f...c80b`/`14cf3582...f7e7`; official hashes are
  `ec3daa08...deda`/`d7aa7720...f013`. These partial artifacts contain no
  benchmark row and are not evidence.
- Commit `30828a4` adds fail-closed support for `sat.euf=true|false`, applies
  the module option before solver creation through `Z3_global_param_set`, and
  runs SAT, UNSAT, and unsupported-option smoke tests whenever the pinned wheel
  fallback is installed. Local verification passed all 228 all-feature Rust
  tests and the complete Python suite; hosted campaign-contract run
  `29215009504` passed.
- Cancelled dependency-dead jobs `144824`-`144833` and submitted replacement
  exact-revision graph `144990`/`144991`/`144992`/`144993` from
  `30828a4f0c1e7e478a9c6f406ccb245eeefc4961`. Prepare is pending WMI priority;
  the corrected native-runner smoke executes before taxonomy work. No new
  performance claim exists.
- Prepare `144990` then completed successfully in `01:09:16` with peak RSS
  `1,214,384 KiB`. It reproduced full taxonomy/split hashes
  `ecab4f1f...c80b`/`14cf3582...f7e7` and official hashes
  `ec3daa08...deda`/`d7aa7720...f013`, wrote promotion-eligible full/official
  parent locks `58e6cbdf...cd886ad`/`6ba7f60a...9410f9`, bound solver config
  `490e959e...a2570`, and froze euf-viper binary
  `edcf8d1a...ba576` with Z3 4.16.0, cvc5 1.3.4, Yices2 2.7.0, and OpenSMT
  2.9.2. Full shards `144991_0` and `_1` completed cleanly in `03:15` and
  `03:04`; the array is advancing under current node availability. Official
  array `144992` and audit `144993` remain open, so no aggregate comparison or
  promotion claim exists.
- Pinned the first rollback pilot in
  `research-vault/02-design/2026-07-13-validation-pressure-rollback.md` after a
  source audit confirmed that current Kissat exposes no trail, LBD, conflict,
  or learned-clause state. The honest automatic trigger is therefore first
  model validation time `>= max(2ms, first SAT time)`. The pilot preserves the
  first checked assignment/conflicts and moves to conflict-only IPASIR-UP; it
  remains default-off and is explicitly not a novelty claim. A safe local
  RustSAT/CaDiCaL callback bridge is the active isolated prerequisite.
- Completed that isolated prerequisite on public branch
  `research-cadical-external-propagator` at `81e0c36`. Review found and fixed
  three boundary hazards in the first checkpoint: cached `SAT` could bypass
  callbacks, unrestricted closure access could replace and drop a connected
  solver, and teardown callback failures were sampled before disconnect. The
  final API exposes only a scoped solve/status/abort session, keeps decisions
  and propagation disabled, validates conflict clauses against observed current
  assignments, catches callback panics before FFI return, and records vendoring
  provenance. Vendored tests pass `19` unit, `11` integration, and `2` doc
  cases; root tests pass `222` default and `228` all-feature cases; hosted Linux
  run `29217315701` passes. No rollback closure, EUF explanation, production
  route, or performance result exists yet.
- Added the solver-independent rollback closure on public branch
  `research-rollback-euf-core` at `0d9ec50`. It uses deterministic union by size
  without path compression; rollback logs cover equality forests, application
  parent incidence, active SAT variables, and per-class disequality incidence.
  Derived congruence edges retain causal argument equalities, conflict clauses
  are capped and canonical, and a separate fresh full-closure replay rejects
  missing, duplicate, reordered, or tampered evidence. The first cap test found
  and fixed an undo-order bug before checkpointing. The randomized differential
  gate executes `10,240` assignment/level/backtrack transitions and compares
  every term pair after each transition; focused cap/type/rollback tests pass.
  Root matrices pass `230` default and `234` all-feature cases; hosted Linux run
  `29217833901` passes. The core is not connected to CaDiCaL and has no timing
  evidence.
- Added the source-only guard-conditioned adequate-range/Hall census in
  `012c963`, then bound the independent parser hash and durable exact-revision
  WMI runner/submitter in `02b68d5`/`86d76fc`. All 33 focused census/parser
  tests and the 274-test Python suite pass; hosted run `29215823607` passes.
  Full-corpus census `145027` is dependency-bound to P0 prepare `144990` and
  cannot emit SAT/UNSAT. No Hall/PB solver route is justified before its
  returned population and value-cell savings are audited.
- Published the causal SC2021-versus-Kissat-4 campaign on isolated revision
  `e67c688`; hosted run `29216075206` passes after 228 all-feature Rust tests.
  It validates the two job-`144945` binary hashes/backend identities, fixes
  every solver environment key identically, verifies all 7,503 source hashes,
  binds one CPU, and rejects incomplete/duplicate shard evidence. Queued sample
  `145029`, broad array `145030`, and merge `145031` behind P0 audit `144993`.
  No T0 timing begins before the baseline audit and no promotion follows from
  validation or queue state.

## 2026-07-13 Audited Campaign And Novelty Checkpoint

- Exact P0 revision `30828a4` completed the two-second full 7,503-source and
  official 3,521-source matrices. Euf-viper solved `7,269`/`3,400`, versus
  Yices2 `7,445`/`3,490` and Z3 default `7,412`/`3,474`. At 60 seconds it solved
  `7,480`/`3,508`, versus Yices2 `7,500`/`3,518` and Z3 default
  `7,489`/`3,514`. All four full/official two/60-second promotion audits reject
  overall superiority. The full 60-second common-wall geometric factor versus
  Z3 is `1.5685x`, but common aggregate speed is only `0.5873x`; against Yices2
  the geometric factor is `0.4910x`.
- The corrected SC2021-versus-Kissat-4 sample `145905` is valid and rejects the
  backend replacement. Both solved 53/64 with zero wrong/error rows; Kissat 4
  won 16 and lost 37 paired instances. Baseline/candidate geometric speed is
  `0.928694`, common-total speed is `0.963416`, and the sign-flip p-value is
  `0.999500`. Broad job `145906` and merge `145907` were dependency-cancelled.
- Hardened source-only range census `145883` runs at exact main `628dabf` and
  must return exactly 7,503 rows with zero parser errors. Full certificate chain
  `145892`/`145893`/`145894` and official chain
  `145897`/`145898`/`145899` remain dependency-held behind that gate. These
  canonical reruns can prove source-level witness/proof existence but do not yet
  bind the literal timed production model, proof, or production CNF trace.
- Rollback control `145900`/`145901`/`145902` was stopped after two shards
  exposed 40/48 candidate `unsupported` outcomes. The adapter had marked a
  pending conflict emitted before CaDiCaL requested `external_clause`; an
  internal SAT conflict could preempt handoff and make a valid recurrence look
  duplicate. Commit `01be0a9` moves deduplication and telemetry to actual
  handoff and adds the recurrence regression. Commit `2dc4bf7` adds a strict
  four-observation anti-target ABBA prepare canary. Tests pass `242` default,
  `248` all-feature, and `302` Python cases; hosted run `29275599640` passes.
  WMI chain `145916`/`145917`/`145918` then rejected before the canary because
  nested `srun` could not resolve bare `python3`; both dependents cancelled.
  This is infrastructure-only. Commit `835d134` resolves and validates one
  absolute interpreter for all prepare stages; 11 focused and all 302 Python
  tests pass. Exact head `dcc7263` passed hosted run `29276687808`; fresh
  prepare/array/audit chain `145923`/`145924`/`145925` was submitted with run
  root `/home/bnaskrecki/euf-viper-campaigns/dcc7263eb4d3/results/rollback-control-20260713T190109Z-dcc7263eb4d3`.
  Prepare reached the exact canary and rejected with baseline `correct:2` and
  candidate `coverage_miss:2`; both candidate rows aborted during
  `notify_assignment` after an already persistent lemma recurred. Dependents
  cancelled automatically. Commit `8e26569` suppresses only bounded
  assignment-time recurrences already covered by a delivered persistent clause
  and records them as telemetry. Complete-model and duplicate-handoff cases
  remain fail-closed. Seven focused, `242` default, and `248` all-feature tests
  pass. Exact branch head `6e402f0` passed hosted run `29277510106`. Fresh
  prepare `145927` completed in `00:06:06` and passed its four-row ABBA canary:
  baseline `correct:2`, candidate `correct:2`, with four bounded assignment-
  time persistent-lemma recurrences recorded by the new telemetry. The locked
  binary SHA-256 is `0cff30a189d464231dabf6a893a31dc23f9a44a7d115c65ee784508597cdb4ad`,
  manifest SHA-256 is `85c18f76bc4908477e906eb0706cb06724ef23ef0536112651fe75e86ff18390`,
  preflight journal SHA-256 is `e223befc265ee95e20510fdce5a85cd9ade66c618b1e766a643b0ff49ef57734`,
  and preflight-summary file SHA-256 is
  `2809e913e30b5bb77cb7abb7f78841f8601165cb294b76110d632caf4c9f2e73`.
  Slurm released array `145928` automatically; final audit `145929` remains
  dependency-held, so no timing or promotion conclusion exists yet.
- Full/official 1,200-second arrays `145785` and `145787` remain scheduler
  pending with 10 GiB, one-core requests; their dependent audits/finalizer
  `145786`/`145788`/`145789` remain held. The full array has a scheduler estimate
  of `2026-07-13T21:36:47` on `c3n1`; the official array is waiting on priority
  without an estimated start. No evidence graph was changed.
- T5 remains census-gated. Its next artifact must deterministically project
  typed component class codes, restricted-growth constraints, bitonic record
  sorting, eager Ackermann/triangle controls, exact clause/literal/watch costs,
  and decoder work over every source. Broad QG and Goel savings, variable-growth
  control, complete provenance, and decoder caps must all pass before any solver
  implementation.
- Refreshed the tail opportunity atlas from the authoritative post-fix full
  60-second audit, SHA-256
  `2458b01872a290c89f715a277dfd41e2c28091fc649925c9acbfefeb6e72686a`.
  Z3 default and Yices2 share exactly 22 solves that euf-viper misses: nine
  Goel, `PEQ012_size6`, and twelve `qg7` isomorphism instances. Euf-viper has
  13 Z3-only but only two Yices-only solves, so it needs ten additional solves
  to lead Z3 and 21 to lead Yices without regression. The Yices common-set gap
  is broad: about `2.04x` geometric and `4.89x` aggregate improvement. This
  supersedes old `58efe9d` scoreboard numbers while preserving their frozen
  structural selectors as discovery artifacts.
- Full 1,200-second continuation task `145785_0` began on `c3n1`; remaining
  full tasks and official array `145787` stay scheduler-bound. The existing
  dependency graph and evidence origins remain unchanged.

## 2026-07-13 Corrected Opportunity And Evidence Gates

- Guarded-range census `145883` terminated `FAILED 2:0` after `01:52:20`, but
  wrote exactly 7,503 source records with SHA-256
  `d806be064546ce18465d7cd451592479d0df44564ad2d1b2826ee77a64b3a3b6`.
  Seventeen deeply nested NEQ sources reported `SMT-LIB expression nesting is
  too deep`. The parsed projection had 91,895 uniform and 91,895 non-uniform
  cells, zero cell savings, 151 certified uniform domains, 14,311 effective
  ranges, 24 checked Hall subsets, and zero Hall conflicts. This cannot reject
  T4 because its preregistered zero-parser-error gate failed.
- Reproduced the deepest omitted case, `NEQ033_size4`, and replaced recursive
  `let` expansion in the independent Python parser with an iterative frame
  machine that preserves simultaneous binding scope. It now parses that source
  as 5,676 variables, 13,984 clauses, and 2,733 terms; all 282 Python tests
  pass. Published `6b51b39`. Commit `8f78543` additionally records and pins the
  census wall limit, defaulting to four hours.
- Submitted corrected census `146071` from exact public revision `8f78543`.
  Replacement certificate-shadow chains are full
  `146076`/`146077`/`146078` and official
  `146079`/`146080`/`146081`, all dependency-held behind the corrected census.
  The old `145892`-`145894` and `145897`-`145899` chains were cancelled rather
  than allowed to inherit a failed source gate.
- Rollback array `145928` has six completed and two active shards at this
  checkpoint; audit `145929` remains dependency-held. No partial timing was
  interpreted. Full 1,200-second array `145785` has two completed and one
  active shard; official `145787` remains priority-bound and the original
  audits/finalizer `145786`/`145788`/`145789` remain intact.
- T1 branch `research-typed-stream-parity` reached `47d7b0a`, pinning Cargo and
  parser semantics after prepare `145940` failed before testing on an absent
  bare `cargo`; its dependents cancelled. A final semantic-snapshot repair is
  in progress before resubmission.
- T5 branch `research-t5-component-quotient-census` at `b51c75e` now includes a
  bounded executable 316-assignment decoder oracle, complete parser-symbol
  accounting, and weighted plus p95 literal/watch no-regression gates. A
  second independent review is pending; no WMI submission exists.
- T6 branch `research-t6-theory-dag` at `9833ec3` pins Cargo and provenance.
  Census `146075` is priority-pending. Historical hard-10 rows are explicitly
  pre-fix development evidence, and promotion is disabled until the frozen P0
  audit mechanically supplies a current 12-source manifest.
- Production-evidence branch `research-production-evidence` at `6095e29`
  remains under adversarial review. Integration requires more than a
  source-valid model: the independent checker must reject dirty builds and
  replay the production assignment against every exact production CNF clause
  with a complete atom map.
- T1 revision `8952dcb` completed WMI prepare/array/audit
  `146214`/`146215`/`146216`. All 128 shards completed, and the exact audit has
  7,503 matches with zero fallback, mismatch, or error. Records SHA-256 is
  `593e7e9b...c82ede`; audit SHA-256 is `1a0e0d67...b93b26`. The tested
  fail-closed nesting cap is 8,192, above the measured corpus maximum of 4,244.
  This is parser parity only and is under independent review before integration
  or timing.
- Independent T5 review rejected `b51c75e` for evidence-integrity defects. WMI
  completion trusted summary booleans instead of replaying the bundle,
  contradictory oracle feature/counter receipts passed, and correctly rehashed
  rows could contain impossible count relations. No census was submitted; a
  strict bundle verifier and attack regressions are being implemented.
- Independent production-evidence review rejected schema v1 `6095e29`.
  Auxiliary assignment flips that falsified production CNF, complete atom-map
  omission, dirty standalone builds, same-size source TOCTOU, incoherent status,
  and deleted-sidecar resume all crossed the advertised checker boundary.
  UNSAT remained fail-closed. Schema v2 repair must bind every production
  clause and variable, trusted executable bytes, same-opened source/evidence
  bytes, and resume/finalization rechecks.
- Refreshed unresolved T0/T3/T7/T8 ordering against the frozen 22-source
  deficit: nine Goel are six SAT/three UNSAT, PEQ is UNSAT, and all twelve qg7
  are UNSAT. T3 M0 pressure telemetry is first if two fixed representations
  survive with at least 10% oracle headroom. Otherwise stop migration and run a
  scalar source-exact qg7 frontier census. Explanation economics and
  EUF-conditioned vivification remain Goel-specific controlled backups.
- Rollback array `145928` completed all 12 shards and final audit `145929`
  returned `status: reject` with no internal audit errors. Across 576
  observations, every current/dynamic/model-cuts comparison had zero wrong or
  execution-error rows, no baseline-only solve, coverage `15 -> 23`, and eight
  candidate-only solves. Target geometric speedups were
  `7.6029x`/`9.0741x`/`7.3178x`, but anti-target p95 overhead was
  `11.1689x`/`32.7545x`/`23.3462x` against a `1.10x` maximum. Reject
  whole-instance rollback as a default. Preserve the frozen arm only as input
  to M0 selector telemetry; it does not authorize migration.
- Preserved final audit SHA-256 `fffb152c...e3831ff`, prepare, stdout, stderr,
  and a compact decision receipt under
  `results/wmi/rollback-control-145929/`. Slurm reports the audit job as failed
  because the auditor intentionally exits one on a scientific rejection.
- Froze T3 M0 in `campaigns/t3-m0-component-pressure-v1.json` and
  `research-vault/02-design/2026-07-13-t3-m0-telemetry-contract.md`. The
  24-source rollback panel is perfectly family-confounded and provides only
  `3.74%` coverage-aware PAR-2 oracle headroom (`223.453` best fixed versus
  `215.403` oracle), below the `10%` gate. It is retained only to test schemas
  and labels. M0 now has representation-neutral S0 and bounded eager-prefix S1
  checkpoints, an explicit semantic allowlist and leakage denylist,
  duplicate-closure group splits, Williams labels, a fixed depth-four tree,
  and confidence-bounded accuracy/overhead/headroom gates. Migration remains
  forbidden until at least two independently accepted fixed arms pass.
- Added `scripts/bench/validate_t3_m0_contract.py`, nine mutation regressions,
  and hosted-CI enforcement. The executable boundary rejects weakened
  headroom/accuracy thresholds, removed leakage denials, S1 post-checkpoint
  admission, weaker trace equivalence, Boolean/integer type confusion, and
  inconsistent frozen PAR-2 arithmetic. Duplicate JSON keys and non-finite
  constants also fail during loading; exact evidence totals, component-ID rule,
  and Williams arm order cannot drift. Local validator and unit tests pass.
- Froze T8 M0 in `campaigns/t8-scalar-frontier-census-v1.json` and
  `research-vault/02-design/2026-07-13-t8-source-exact-scalar-contract.md`.
  Existing right-translation/orbit code is not source-complete and has `0/12`
  source-exact UNSAT coverage on the frozen qg7 deficit. The replacement is a
  deterministic no-forget typed partial-algebra transducer with command-level
  assertion/auxiliary lineage, complete residual source state, checked
  automorphisms, an independent domain-1--3 total-model-set oracle, and checked
  SAT interpretations or UNSAT cube-cover DAGs. It stops before implementation
  until T1 review, the missing assertion ledger, and corrected T4 evidence
  complete.
- Independent T5 review rejected `e930abf` despite 57 passing focused tests and
  hosted CI. The full verifier is strong, but the finalizer trusted a mutable
  receipt instead of repeating semantic reconstruction. Coordinated record,
  target, gate, and decoder mutations reached `completed`; an aggregate change
  at the final publication boundary raced the receipt; a failed rerun retained
  old completed metadata; and untracked importable Python files were excluded
  from revision cleanliness. No WMI job was submitted. A captured-byte,
  immutable atomic bundle repair with failure cleanup is active.
- T1 revision `7214d63` completed fresh WMI chain
  `146374`/`146375`/`146376` with 7,503 matches and zero fallback, mismatch, or
  error. Records SHA-256 was `ea41a7b3...b6ebb` and audit SHA-256 was
  `fea1b2ec...d355`. Independent review nevertheless rejected integration: the
  binary was hashed then reopened by pathname and could be replaced to forge a
  match, `/usr/bin/python3` was recorded as an alias rather than canonical
  realpath, and shard `exit_code: NaN` survived artifact audit. The same-source-
  buffer repair is confirmed correct. Descriptor-bound execution, realpath
  identity, strict JSON, and a fresh full chain are active; old evidence is
  superseded for promotion.
- Independent production-evidence review rejected schema v2 `e3add515`.
  Sidecar-controlled `congruence_closure` downgraded genuine backend evidence
  past CNF/assignment checks; self-consistent clause/variable/atom omissions or
  additions passed because the checker did not independently reconstruct the
  exact namespace and stream; and the primary analyzer accepted unchecked SAT.
  Final shadow publication raced rehash, parent symlinks escaped lexical
  containment, incomplete journal tails were truncated, and preparation JSON
  accepted ambiguity. UNSAT remained fail-closed. Schema v3 repair now requires
  source/config CNF reconstruction, replayed dynamic-clause transcripts, exact
  maps, checker-gated classification, no-symlink traversal, and strict frames.
- Corrected guarded-range census `146071` completed at exact revision `8f78543`
  in `01:53:20`, exit `0:0`. It covered 7,503/7,503 sources with zero structured
  parse errors, but projected 124,698 uniform and 124,698 non-uniform value
  cells: exactly zero savings. It found 157 certified uniform domains, 25,760
  effective ranges, 24 Hall subsets, zero Hall conflicts, and zero eligible
  sources. This definitively rejects T4 before Hall/PB implementation against
  the 30% gate. Aggregate SHA-256 is `b37b9550...c4e42`; records SHA-256 is
  `4cfb2d1d...ff961c`. Full/official certificate prepares `146076`/`146079`
  released automatically and remain separate evidence chains.
- Inspected the exact 12 P12 qg7 rows inside T4 records
  `4cfb2d1d...ff961c`. Every row has empty domains, zero proven range facts, and
  `no_proven_non_bool_range`. T4 cannot discharge T8's domain-seven
  prerequisite. Added a source-bound P12 summary; T8 now requires a separate
  checked finite-domain certificate in addition to T1 review and assertion
  lineage.
- Added `validate_t8_scalar_contract.py`, hosted-CI enforcement, and 26 combined
  T3/T8 contract tests. T8 validation now binds strict JSON types and keys, the
  exact preregistration, the raw P12 summary and T4 receipt SHA-256 values, all
  12 source paths, the T4 records hash, and every zero-range field. The CLI and
  Python API require both evidence paths. Successful output explicitly keeps
  both implementation and SIMD unauthorized.
- Independent T8 control review is GO at `14754f8` after the raw receipt and
  mandatory-API repairs. Receipt status/hash mutations fail, omitted summary,
  omitted receipt, and omitted-both API calls all raise `TypeError`, and hosted
  run `29290493620` passed. This is permission to retain the freeze only, not to
  implement scalar search or SIMD.
- Independent T5 review rejected `ea8dee5` despite 68 passing focused tests and
  correct captured-byte semantic reconstruction. A tracked imported module with
  `skip-worktree` could differ from `HEAD` while the checkout guard passed; a
  mutation after the final staged-archive digest but before pathname linking was
  published; and a failed same-job rerun left the old completed archive visible.
  No WMI census was submitted. Exact Git-blob verification, fd-bound publication,
  and attempt-scoped current markers are active repairs.
- T1 revision `e77846d` completed WMI `146510`/`146511`/`146512` and independent
  reconstruction `146652`. All 128 shards completed; both reconstructions report
  7,503 matches and zero fallback, mismatch, error, or other status. Independent
  review confirmed descriptor-bound execution, canonical Python identity,
  strict JSON, all source and artifact hashes, and public/remote revision
  equality. T1 evidence machinery landed on main at `84b4c8e`; the omitted
  reviewed parser source and fixtures were restored exactly at `00c11a5` after
  blob-identity checks, both Rust feature matrices, release build, and file/stdin
  CLI smoke tests. The result authorizes parity only: 98 matching rows carry 4,851
  unsupported diagnostics, and no timing or parser-completeness claim exists.
- Source-complete main head `afeeb5e` passed hosted campaign run `29293318151`:
  campaign specification, Python validators, shell checks, and the Rust solver
  all passed. The Jupyter Book also rebuilt successfully. Live WMI refresh
  still shows certificate prepares `146076`/`146079` complete while arrays
  `146077`/`146080`, T6 `146075`, and long-timeout jobs `145785`/`145787` remain
  pending; their dependent audits remain held and no partial data were read.
- Independent T5 review rejected `64770d8` despite 71 passing focused tests and
  exact Git-blob/runtime verification. The checked staging inode was not the
  inode published, so a zero-length destination could become visible; early
  preflight failures could retain an old `.current`; and cleanup could delete a
  destination created by a racing publisher. No branch push or WMI submission
  occurred. The next repair must publish the checked inode atomically with
  no-replace semantics and establish cleanup ownership only after publication.
- Local production-evidence schema-v3 review at `578deb8` passed the exact CNF,
  namespace, transcript, model, analyzer, no-follow path, and hash-journal unit
  boundaries: 230 Rust tests (four ignored), 28 focused tests, and all 330
  Python tests passed. Merge is still NO-GO. The branch predates current main,
  adds evidence to default features without timing, and its mode disables
  several fast routes while making every UNSAT result nondecisive. It must be
  reconstructed on current main as opt-in and pass full-corpus shadow plus
  paired off-mode timing. Two attempted independent agent reviews were blocked
  by a platform content filter and were not counted as technical decisions.
- Independent T5 review rejected `2080b26` after its Linux same-inode/no-replace
  probe and 74 focused tests passed. A non-Linux pathname fallback could still
  publish a replacement inode; staging cleanup retained a check-then-unlink
  race; and one Linux source-swap test demanded relinking where fail-closed
  behavior is correct. No push or WMI submission occurred. The next revision
  must reject unsupported publication and prefer a leaked owned temporary over
  deletion of any path whose inode ownership is no longer descriptor-proven.
- Current-main production-evidence reconstruction `d47e1c6` is review NO-GO.
  The semantic v3 checker and opt-in Cargo boundary pass, but locked WMI prepare
  compiles certificates without the separately required evidence feature while
  its recorder always requests a sidecar. More importantly, ordinary solver
  paths still build transcript vectors and duplicate backend clauses with
  evidence disabled, violating the zero off-mode performance requirement.
  Ordinary solve argument compatibility also changed without approval. No branch
  push, hosted matrix, or corpus job occurred; all three issues are under repair.
- Hosted campaign-contract run `29296046483` passed on current main
  `403b6b7`. A fresh WMI control-plane audit preserved every fixed graph and
  command lineage: continuation jobs still execute from the immutable
  `30828a4f0c1e` checkout; T6 still executes from `9833ec3a9219`; certificate
  arrays still execute from `8f785437830e`. Certificate prepares
  `146076`/`146079` are complete, arrays `146077`/`146080` and T6 `146075` are
  priority-pending, and their audits are dependency-held. Full 1,200-second
  range `[2-63]` and the official array are pending, with no continuation shard
  currently active. No partial benchmark or certificate output was inspected.
- Independent T5 review rejected revision `55c0101` before publication or WMI.
  The opened stage descriptor was not the sole publication authority; pathname
  cleanup could remove a concurrent replacement; same-revision submissions
  reused a checkout/result root; and generated Python caches violated the
  provenance guard. The worker's 75 focused and 356 Python passes do not
  override these evidence-boundary defects.
- Independent T1 timing review rejected revision `a99d9bf` before publication
  or WMI. Empty miss populations passed, timeout censoring could arm-select the
  common timing set, ambient contract/manifest replacements were not hash-bound
  to submission, semantic parity followed metric admission, telemetry-only
  symbol cloning polluted the timed path, and untracked remote inputs escaped
  provenance checks. The repaired campaign must fail closed over all 7,503
  sources before producing any timing decision.
- Second independent production-evidence review rejected `939bc60`. The repair
  correctly requests both Cargo features and guards reviewed happy-path
  evidence allocations, but WMI provenance still permits ambient/untracked
  build influence; ordinary help/error output differs from `f8d9205`;
  exceptional solver exits lack zero-work assertions; and no exact combined-
  release binary traverses recorder, checker, runner, and analyzer. All 78
  focused review tests passed, but no Rust matrix or campaign was accepted.
- Sixth independent T5 review rejected `cf1aa3e`. A retained staging hard link
  allowed a concrete write to mutate the completed archive after `.current`;
  the symlink marker was swappable and unverified; Git and the campaign lock
  remained ambient-environment sensitive; final nonce/digests were absent from
  the completed receipt; pathname cleanup races survived below the finalizer;
  and the verifier reused the candidate projection implementation. No branch
  push or WMI submission occurred despite 32 focused and 83 semantic test
  passes. The replacement design uses an unnamed one-link Linux inode and an
  independently checked content-bearing completion receipt.
- Second independent T1 timing review rejected `20be404`. The reviewer changed
  every candidate elapsed time to one nanosecond while retaining unbound hashes;
  all 7,503 rows and every speed gate passed. Semantic counters were similarly
  forgeable. The submitter also adopted the mutable remote manifest hash, the
  contract mislabeled 128 shards as repetitions, transient source changes could
  influence Cargo, the sub-1% machine identity was incomplete, and CI never ran
  the exact release path. No branch push or WMI submission occurred despite 20
  focused test passes. Exact raw stdout, the accepted corpus digest, sealed
  shard receipts, mutation-monitored builds, and real Linux execution are under
  repair.
- Live WMI accounting on 2026-07-15 invalidated the pending-state description.
  The 1,200-second full/official arrays `145785`/`145787` eventually ran, but
  three ordinary shards failed and subsequent tasks exited with signal 53.
  Exact stderr records `OSError: [Errno 122] Disk quota exceeded` while creating
  a locked stdout file under the `/home/bnaskrecki/euf-viper-campaigns/30828a4f0c1e`
  campaign. Audits `145786`/`145788` and finalizer `145789` were cancelled.
  Certificate prepares `146076`/`146079` completed, but arrays
  `146077`/`146080` then failed with the same signal-53 storage condition and
  audits `146078`/`146081` were cancelled. No partial benchmark or certificate
  row is evidence. Current quota is 174.49 GiB/200 GiB and
  1,838,881/2,000,000 files in `/home`, versus 561.09 GiB/1 TiB and
  3,687,608/10,000,000 files in `/work`. Recovery is a fresh immutable root in
  `/work`, complete reruns, and new terminal audits; failed trees stay intact.
- T5 repair commit `6249393` is invalid and non-publishable because its isolated
  clone lost required Git objects and failed `git fsck`. The intact physical
  source files were copied without the corrupt `.git` directory into fresh
  clone `/private/tmp/euf-viper-t5-recovered`, whose object database passes
  `git fsck`. Review and any future commit proceed only from that recovered
  clone; `6249393` is never cited as evidence.
- Created `/work/bnaskrecki/euf-viper-campaigns/30828a4f0c1e` at exact revision
  `30828a4f0c1e7e478a9c6f406ccb245eeefc4961` and copied the complete 357 MiB
  `p0-144990` base. An `rsync -ainc --delete` checksum dry-run returned no
  difference. Slurm had aged completed audit `144993` out of the dependency
  controller, so commit `b99bff3` separated immutable base-audit identity from
  a fresh scheduler barrier. Barrier `147305` completed; dispatcher `147306`
  revalidated the base and submitted fresh 60-second full/official arrays
  `147307`/`147309`, audits `147308`/`147310`, and successor dispatcher `147311`.
  The first full shard completed successfully from the `/work` command and
  output paths. No result is read before both audits and finalization.
- The first `/work` certificate submission exposed an empty-array expansion in
  the optional-dependency path under Bash `set -u` and stopped before any job.
  Commit `026f283` replaced it with a scalar option and added a regression
  contract. Fresh exact-`8f78543` chains are full
  `147315`/`147316`/`147317` and official `147318`/`147319`/`147320`; their P0
  inputs and pinned `drat-trim` now reside under `/work`. Both audits remain
  mandatory and no prior partial certificate artifact is reused.
- Independent production-evidence review gave exact `e838c1f` a narrow GO only
  for research-branch publication and hosted Ubuntu execution. It remained
  WMI NO-GO because dependent jobs accept a mutable self-certified prepare
  receipt; pre/post source and executable hashing does not bind bytes consumed
  by Cargo or `exec`; final artifact paths can be replaced after checking; the
  loader/shared-library/native-toolchain/Cargo-registry closure is incomplete;
  and the `f8d9205` CLI oracle lives inside the candidate. The reviewer also
  confirmed strong but test-only off-mode instrumentation. No WMI action used
  this branch.
- Hosted run `29384179332` at `e838c1f` passed every matrix through the exact
  release build, then failed because its negative smoke expected exit 2 while
  semantic evidence rejection correctly returned exit 1. Commit `b9da60b`
  now requires exit 1 and the exact status-mismatch diagnostic. Exact-head run
  `29384633378` passed in `5m43s`, including default, no-default, certificate,
  production-evidence, combined, all-feature, real comparator, CLI, and locked
  release-smoke steps. This is hosted smoke evidence only, not provenance or
  merge acceptance. Production-evidence v4 repair is isolated and active.
- Independent review rejected valid recovered T5 commit `0ad8431` for WMI. The
  fixed contract selects tracked SMT-COMP manifest bytes with 3,521 rows while
  requiring 7,503, so the exact WMI command deterministically aborts before
  source processing. The publication route requires
  `linkat(..., AT_EMPTY_PATH)` while declaring an unprivileged gate; Slurm
  terminal evidence drops the `sbatch --parsable` cluster and binds only a
  numeric job ID; the projection verifier closely mirrors the candidate; and
  Python/OS/filesystem/Slurm runtime closure is incomplete. Review allowed only
  diagnostic branch publication, never merge or WMI.
- Pushed exact `0ad84317b5cf714785e6129d8403772c813e7758` to
  `research-t5-component-quotient-census-recovered`. Hosted Linux run
  `29385400195` failed in 28 seconds after 88 tests: an archive replacement was
  rejected earlier by inode mismatch than the test's expected digest mismatch,
  and another swap test tried to parse a deliberately replaced empty receipt.
  The real one-link test passed on that runner, so the repair must inventory
  effective capabilities rather than infer an unprivileged environment. No WMI
  job was submitted; a manifest/procfs/Slurm/oracle repair is active locally.
- Independent T1 review accepted exact commit `26156e3` only for diagnostic
  publication. It verified lossless raw output, strict payload replay, sealed
  128-shard closure, accepted 7,503-source binding, warmup-one/ABBA-five
  dimensions, and offline locked compilation. It rejected WMI because ambient
  values still select submit and execution roots, a forgeable stop file can end
  mutation monitoring before Cargo, the output ELF lacks complete recursive
  runtime/toolchain closure, and placement is observed rather than enforceable.
- Pushed exact `26156e3691297c0765a583369d65b3fd62d2d560` to
  `research-typed-parser-timing`; no WMI action followed. Hosted run
  `29386186960` failed at workflow evaluation with zero jobs. The new workflow
  placed `${{ runner.temp }}` in `jobs.validate.env`, but GitHub permits no
  `runner` context at that key. A fresh isolated repair now owns the monitor,
  ELF closure, immutable roots, bounded-canary placement, and valid Linux CI.
- Refreshed the local-search boundary against Pollitt, Fleury, Schidler, Biere,
  et al., *Improving Local Search and adding DDFW to CaDiCaL* (PoS 2026).
  DDFW and target-phase exchange strengthen the required Boolean control but
  do not justify a new track here: only six of the frozen 22 common misses are
  SAT, so perfect SAT discovery cannot meet either rank threshold, and the
  Yices2 common-time deficit is predominantly UNSAT. Retain only a charged
  no-phase/shuffled-phase/perfect-EUF-phase oracle as a reopen condition; no
  implementation or job was launched.
- Froze the minimal T7 falsifier after a current-main code audit. Eager and
  model-cut explanations have no SAT decision levels or alternative reasons;
  the experiment must therefore remain a sidecar on rollback head `6e402f0`.
  Both arms construct the same bounded, replay-valid minimum-width candidate
  pool. Only the tie-break changes from lexical to
  LBD/current-level/second-level/reuse/lexical. A three-source opportunity pass
  precedes every timing run, then a 32-observation canary precedes the frozen
  192-observation panel. The isolated branch
  `research-t7-sat-impact-explanations` is under implementation; no WMI job is
  authorized. The audit also found that T2 retained only a conflict count, not
  the claimed first eager assignment and clauses, so offline replay is invalid.
- T5 repair `446b424` bound the external 7,503-row manifest, added procfs
  `O_TMPFILE` one-link publication, full Slurm identity, runtime inventory, an
  independent projection implementation, and held-job cleanup. Independent
  review nevertheless found a common lexical-scope defect in both SMT-LIB
  parsers and found that the submitter releases the held job before the local
  receipt is durably parsed and persisted. It also corrected the CI claim: the
  7,503-source test skips without a provisioned corpus and uses synthetic
  scheduler evidence when enabled.
- Published exact `446b424ae270735f1296a40d3d8c21286de0d611` only to
  `research-t5-component-quotient-census-recovered`. Hosted run `29388947138`
  passed the Linux publication diagnostics and root test matrix. This is useful
  procfs/filesystem smoke only; it does not authorize T5, merge, or WMI. A new
  parser/release-order/CI-label repair is isolated and active.
- Independent T1 review allowed exact `7a278b7` only as a hosted probe and made
  a one-shard nonpromotable canary conditional on a green run. It rejected full
  timing: scripts are reopened by pathname after mutation monitoring, the
  recursive ELF inventory is not the loader's actual closure, and exclusive
  array elements pinned to sole node `c1n1` cannot realize 32-way concurrency.
- Published `7a278b79f3f3038e9ae18f5a218836a6211b4b54` to
  `research-typed-parser-timing`. Exact run `29389308332` created a Linux job
  but failed both source and dependency mutate-then-restore tests: the monitor
  returned success instead of semantic exit 3. The conditional WMI canary was
  not submitted. A fifth isolated repair now owns monitor readiness, executed
  byte binding, runtime closure, and truthful exclusive placement.
- Published production-evidence v4 diagnostic commit `cd62e3c` to
  `research-production-evidence-v4`. Exact run `29389748725` failed in the
  414-test Python gate with three failures, four errors, and four skips. The
  exact regressions are an undefined `_require_hash`, missing `plan["python"]`,
  attacker source bytes reaching a supposedly bound execution, timeout values
  replacing source paths during resume, and the resulting audit/resume
  failures. Rust, exact-release, comparator, CLI, and locked-smoke steps never
  ran. Review independently rejects forgeable embedded build metadata,
  unenforced compiler identity, incomplete runtime closure, and
  nontransactional publication. The conditional one-input WMI preflight was
  not submitted; repair remains isolated.
- Built exact T7 commit `6269084` in a clean detached checkout and mechanically
  reconstructed its verified M3/T9/A12 manifest from the 7,503-row source
  manifest. SHA-256 `bea69013...a657` exactly matches independent
  reconstruction. The permitted local M3 pass timed out on the first frozen
  `peg_solitaire.2` source at 60 seconds, produced no transcript, and exited 2.
  Thus no qualifying conflict or policy disagreement was established and no
  canary or WMI timing was authorized. Independent campaign review also found
  incorrect median aggregation, self-hashed empty-report admission, incomplete
  selector-cost accounting, timing contamination, a lexical parser defect, and
  self-attested forest identity; all remain repair requirements.
- Live WMI refresh found replacement full array `147307` complete with terminal
  zero exit codes while global audit `147308` was still running. Official array
  `147309` was still advancing and audit `147310`, 1,200-second dispatcher
  `147311`, and certificate arrays/audits `147315`-`147320` remained pending or
  dependency-held. No partial audit, benchmark row, or certificate row was
  interpreted.
- Independent review reproduced T6 P0 target-manifest commit `b71a491`: all
  90,036 current observation keys were present, exactly 12 qg7 UNSAT deficits
  were selected, source size/hash/status/parenthesis checks matched, generated
  artifact SHA-256 was `f0367bdb...7260a`, and regeneration was byte-identical.
  It nevertheless rejected promotion because inputs are hashed then reopened,
  exact observation-matrix semantics and provenance are not enforced under hash
  overrides, full `DOMAIN7_HUGE` structure is inferred rather than proved,
  `10/12` is not mechanically population-bound, and alias paths pass. The exact
  checkpoint was pushed only to `research-t6-theory-dag`; a separate repair is
  active and job `146075` remains untouched. Exact-head hosted contract run
  `29390630178` passed, which records branch health but changes no gate.
- T1 repair `ea28651` was published only after review allowed an exact-SHA
  hosted diagnostic. The review still found substitutable canary shard IDs,
  pathname-reopened helpers, count-only monitor readiness, and underbound array
  plus cancellation evidence. Hosted run `29392563168` failed at guarded Rust
  release compilation because global `+crt-static` flags leaked into host
  proc-macro compilation. No release, canary, or WMI row exists; a sixth repair
  is isolated and active.
- T5 repair `48f3cec` passed hosted run `29392694401` for mandatory Linux
  publication/procfs and root tests; its provisioned 7,503-source job skipped
  honestly without the corpus. Independent review rejected transitive
  free-global scanning, scheduler ownership at release/cancel, namespace
  closure, unique physical source and unsupported-form accounting, canary
  identity, and hosted revision/action pinning. No corpus scan or WMI action
  followed; repair remains isolated.
- Independent review accepts only T6 repair `b587847`'s exact 12-source artifact
  `1b3f4e52...05c21`. It reproduced the full 90,036-observation matrix,
  provenance, all physical structure, and the derived 10-of-12 threshold. The
  branch remains no-go because digest overrides can redefine frozen inputs,
  non-finite JSON passes, regeneration is path-dependent, and the Rust/Slurm
  census still hardcodes v1 hard-10/8-of-10. Job `146075` remains historical
  development provenance only.

- 2026-07-15: Implemented the bounded T8 assertion-lineage prerequisite on the
  isolated `research-t8-assertion-lineage` branch. The `lineage` feature uses
  the authoritative typed tree parser and no-follow, expected-hash source
  snapshots; ordinary parses construct no recorder. Canonical ledgers bind
  source/build/parser identities, exact assertion spans and raw ASTs, all typed
  Boolean/EUF auxiliaries, macro ancestry, and current unsupported diagnostics.
  A separate Python parser/reconstructor passes the adversarial macro-shadow,
  nested-let, repeated-span, Bool-as-data, and term-ITE fixture. The frozen
  64-shard WMI contract requires exactly 7,503 unique physical sources and zero
  parse/hash/lineage/verifier/unsupported-accounting errors without solving.
  It has not been submitted; frontier/SIMD work remains blocked.

## Next Entry Template

- Benchmark corpus:
- Solver revisions:
- Command:
- Result:
- Discrepancies:
- Next action:
