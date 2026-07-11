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
  pass 165 Rust tests and 72 Python tests.
- The domain-seven `iso_icl_nogen001` probe extracted 5,040 unique complete
  binary operation tables. Exact enumeration proved all are the one free
  `S_7` orbit, with no missing, malformed, or foreign table. The Boolean census
  found 497,474 occurrences, 11,370 syntactic nodes, and only 42 additional
  unconditional-theory quotient reductions.
- Added test-only reference implementations for complete SAT model scouts,
  Boolean DAG telemetry, exact table canonization, forbidden-orbit extraction,
  bounded quotient CSP with Hall propagation, and exact base-invariance/orbit
  certificates through degree eight.
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

## Next Entry Template

- Benchmark corpus:
- Solver revisions:
- Command:
- Result:
- Discrepancies:
- Next action:
