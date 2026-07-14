# Project Memory

## 2026-07-08 Bootstrap

- Workspace started empty at `/Users/airbartek/codex/z3`; it was not a Z3
  checkout.
- WMI preflight succeeded through `wmicluster`; VPN route used `utun21`,
  SLURM controllers were up, and CPU/GPU nodes were visible.
- Two unrelated WMI jobs were already running: `139140` and `139142`, both named
  `sg-c-lean-targets`.
- Local Rust toolchain exists: `rustc 1.96.0`, `cargo 1.96.0`.
- Local `z3` binary was not found.
- Default WMI login shell did not expose `z3`, `cargo`, or `rustc`.
- Default LTS login shell exposed `/usr/bin/julia` but not Magma, Sage,
  Singular, Z3, Cargo, or Rust through `command -v`.
- GitHub CLI auth was valid for account `nasqret` with repo scope.
- Installed local Z3 4.16.0 via Homebrew to enable comparator checks.

## Design Decisions

- The current solver supports arbitrary ground Boolean QF_UF structure through
  Tseitin CNF plus SAT backends. Unsupported syntax is still reported rather
  than approximated.
- UNSAT from a sound eager encoding is accepted; SAT assignments are checked
  with full EUF congruence closure, and invalid assignments trigger lazy
  theory-lemma refinement. This is the core soundness boundary.
- Linux uses a namespaced Kissat 0.1 backend because Kissat 4 was slower on the
  measured WMI hard tail. CaDiCaL and Varisat remain available as alternate
  routes.
- On Linux x86_64, an eager Kissat SAT assignment that fails full EUF model
  validation now falls back to incremental CaDiCaL refinement. Full-corpus A/B
  job `139497` improved coverage by 13 and timeout-inclusive total time by
  0.34%. `EUF_VIPER_INVALID_MODEL_FALLBACK=varisat` is the rollback control.
- Finite predicate-table channeling is retained behind environment flags but is
  not enabled by default because WMI jobs `139240` and `139242` showed no hard
  tail gain.
- Z3 superiority claims are blocked until a reproducible benchmark campaign is
  completed.
- Long-timeout campaigns use a prepare job, bounded-concurrency SLURM array,
  and dependent merge job. The prepare job creates
  `qf_uf_campaign_<run-id>.jsonl`; every shard and the merge read that exact
  manifest. The merge must see one row per manifest-path and solver pair.
- Certificate format `euf-viper-euf-cnf-v1` links source, DIMACS, and ASCII DRAT
  files by SHA-256. The Python checker invokes independent `drat-trim` and
  validates each non-base clause by an EUF congruence replay. Format v1 does
  not include finite-domain axioms and still trusts the SMT-to-base-CNF encoder.
- Certificate code is behind the non-default `certificates` Cargo feature. The
  default release text section is byte-identical to pre-certificate commit
  `0bb34c2`, preserving the measured solver executable path.
- Official-corpus certificate smoke passed on Rodin
  `smt3166111930664231918` and TypeSafe `z3.1184163`; the latter required one
  replayed EUF clause. Both exact DIMACS files and DRAT traces were accepted by
  the independent checker.

## 2026-07-09 Dynamic Ackermann Iteration

- The accepted standalone candidate keeps the ordinary Tseitin/Kissat path
  unchanged until a SAT assignment fails full EUF validation. For non-finite
  shapes with at least 100,000 base clauses and at most 256 applications, it
  then rebuilds direct assertion roots, emits full function and predicate
  Ackermann axioms, adds bounded minimum-degree chordal fill, and retries
  Kissat once before the existing CaDiCaL fallback.
- `EUF_VIPER_FULL_ACKERMANN=on` forces completion and `off` disables the
  dynamic route. `EUF_VIPER_CHORDAL_MAX_FILL` defaults to 1,000,000. These are
  experiment and rollback controls; the default gate is structural.
- Full paired WMI array `141911` and strict merge `141916` are the acceptance
  evidence: 7,503 instances, 15,006 observations, two-second timeout, coverage
  6,993 to 7,002, timeout-inclusive speedup 1.0169x, common aggregate speedup
  1.0336x, geometric speedup 1.0961x, zero wrong answers, zero execution
  errors. Candidate wins were 5,356 versus 1,610.
- The exact accepted binary SHA-256 is
  `f45b51ec65c36ca3df63397ba22a078c0e8490041c5e504f68ff9c2982a77a2d`.
  The previous accepted baseline binary remains
  `2f2b90b94fd05e1b45e4067834a6045f39f2c1b7ddd80b79575ff61f3ffe6ea5`.
- Unconditional completion, cold-code-only, thin-LTO-only, and the pre-Fx full
  candidate were rejected by controlled gates. Do not infer acceptance from a
  targeted family win; preserve the full-corpus coverage plus all-speed gate.
- The new two-second result is not a 60-second or 1,200-second comparator run.
  The published competition-budget boundary remains 7,478 standalone solves
  versus Z3 7,500 and Yices 7,503 until those campaigns are rerun.

## 2026-07-10 Controlled Routing Checkpoint

- Direct-root CNF is promoted by commit `50edc7d`. Full paired gate
  `142591`/`142596` improved coverage 6,825 to 6,843, all-total 1.0060x,
  common-total 1.0098x, and geometric speed 1.0264x. Keep
  `EUF_VIPER_DIRECT_ROOT_CNF=0` as rollback.
- The WMI A/B harness had continued to force the obsolete `varisat`
  invalid-model fallback. Commit `94c86c0` aligns new WMI gates with the
  promoted Linux `cadical-refine` default. Every old result remains
  interpretable through its recorded environment, but it is not a production
  promotion result unless that configuration is explicit.
- Unconditional scoped-let restoration is rejected: full gate
  `142745`/`142750` lost one net solve and measured 0.9963x geometric speed.
  The predeclared `EUF_VIPER_SCOPED_LET=auto` route selects scoped restoration
  at 512 lexical lets and keeps the cloned parser below it.
- Scoped-let auto passed production targeted `142892`, sample `142895`,
  hot-400 `142918`/`142926`, and full `142952`/`142996` gates. The full result
  was coverage 7,219 to 7,249, all-total 1.0337x, common-total 1.0165x, and
  geometric 1.0072x, with no baseline-only cases, wrong answers, or errors.
  Binary SHA-256 is
  `4d5431135c95a2c528d287efd2803eaf895a5ec526c9642a570797b02fd47eb7`.
  Repeated c2n1 `143029`/`143033` and c3n1 `143034`/`143039` confirmations
  added 29 and 15 solves respectively, improved all-total 2.598x and 1.272x,
  and produced no baseline-only cases. The route is promoted.
- The finite permutation clique-core prefilter passed its repeated 151-case
  gate `142796`/`142800` but failed hot-400 `142867`/`142871`: coverage
  321 to 319 and every speed metric below 0.98x. Stop; do not launch a full
  gate or default-enable focused finite support.
- Broad equality facts are rejected. Production sample `142898` measured
  0.9763x common and 0.9337x geometric speed. Hard-hit `142899`/`142907`
  added 18 solves but still regressed common/geometric speed.
- The path-independent `guarded_disequality_clauses > 0` equality-fact route
  is rejected on the current baseline. Its actual mode passed sample `143160`
  narrowly, but selected-population gate `143161` stayed 29/29 and regressed
  all-total to 0.9960x, common-total to 0.9852x, and geometric speed to
  0.9816x. Scoped-let now solves all 11 historical fact-only gains. Keep
  `guarded-facts` default-off and do not launch its hot/full gates.
- Typed sort tracking is the soundness prerequisite for definitional
  substitution. Initial sample `142943` failed speed because it traversed
  valid assertions twice. Commit `991d700` defers diagnostics to parse-error
  paths. Sample gate `143080` recovered all-total/common speed to
  1.0023x/1.0038x but geometric speed stayed at 0.9971x. Do not implement
  substitution on an untyped arena and do not promote typed parsing before all
  speed gates pass.
- Dense `Vec<Option<FunDecl>>` indexing in `1820fef` is a measured typed-branch
  improvement: isolated sample `143178` kept 37/37 and improved
  all/common/geometric speed by 1.0102x/1.0203x/1.0129x. Direct gate `143188`
  against accepted pre-typed `58efe9d` still failed at
  0.9962x/0.9923x/0.9835x. Keep the accepted binary unchanged and optimize
  repeated application checks next.
- Exact-term application reuse in `f7b52fb` preserved first-seen sort checking
  but failed isolated sample `143202`: all-total 0.99995x, common-total
  0.99987x, geometric 1.00003x at 37/37. It was reverted in `d69792a`; do not
  spend production-baseline, hot, or full gates on it.
- Typed QG profile `143209` measured faster candidate parse medians on all four
  completed controls. Removing the rejected guarded-facts context in
  `93e2d90` still failed isolated sample `143220` at 0.9992x all-total and
  0.9985x common-total despite 1.0036x geometric speed. `92a7a8f` restored it.
- Cross-architecture typed+dense confirmation `143228` on c2n1 stayed 39/39
  but failed at 0.9997x all-total, 0.9995x common-total, and 0.9876x geometric.
  Worst-10 profile `143224` localized the main loss to parse time. The
  `HashMap::entry` reuse candidate `d5a0e14` then failed isolated `143232` at
  0.9935x/0.9873x aggregate speed and was reverted by `aaffae3`.
- Global-get candidate `4a0ff44` improved worst-10 parse by 1.0337x, but sample
  `143239` failed geometric speed at 0.9955x despite 1.0011x/1.0021x aggregate
  speed. `6973ed4` reverted it. Next validate sorts once per unique interned
  application rather than once per syntax occurrence.
- Unique-term validation `5f67b6f` improved worst-10 parse/end-to-end profile
  `143246` by 1.0127x/1.0159x and sample geometric speed by 1.0017x, but sample
  `143244` regressed all-total/common-total to 0.9931x/0.9865x. Reject before
  broader gates; dense SortTable indexing is the next independent hypothesis.
- Fresh four-solver two-second campaign `143049`/`143051`/`143052` completed
  against exact scoped binary commit `58efe9d`: euf-viper 6,948, Z3 7,176,
  cvc5 6,926, Yices2 7,434. Euf-viper beats Z3 on 6,907 common solves by
  1.119x aggregate and 2.083x geometric speed, but Z3 adds 228 net solves.
  Yices2 adds 486 net solves and is about 3.46x faster on common aggregate.
  No overall Z3 or Yices2 superiority claim is allowed.
- Global PGO for accepted source `58efe9d` is rejected. The disjoint 512-case
  holdout lost four solves and regressed all/common aggregate speed despite a
  1.0203x geometric gain. A structural PGO rule passed five-fold and
  independent-sample gates, but its all-time gains were only 1.00040x and
  1.00010x before runtime routing overhead. Do not implement an external PGO
  launcher; retain the signal only for future in-process code partitioning.
- Exact 60-second campaign `143248`/`143249`/`143254` used binary SHA-256
  `4d543113...` and completed all 30,012 observations without errors or wrong
  answers. Coverage is euf-viper 7,478, Z3 7,490, cvc5 7,473, and Yices2
  7,500. Viper's euf/Z3 common geometric ratio is 1.888x, but common-total is
  0.723x because of the hard tail. Yices remains decisively ahead.
- Exact 1,200-second timeout-only resume `143382`/`143383`/`143384` inherits
  solved rows from `143248` and reruns 71 timeout observations. Prep verified
  source `58efe9d`, binary SHA-256 `4d543113...`, and 7,503 manifest rows. It
  is running; do not infer final coverage from the older competition campaign.
- Focused permutation support is again an implementation candidate only under
  the existing scoped-let structural selector. Same-binary WMI `143412` gated
  all 17 files with at least 512 lexical lets: coverage stayed 17/17,
  all/common-total improved 1.6475x, geometric speed improved 1.8109x, and
  `NEQ027_size11` fell from 56.39s to 1.16s median. Do not enable focused mode
  globally; implement the conjunction on accepted source, then rerun sample,
  hot, and complete-corpus gates.
- The same route's five-repeat two-second gate `143438` improved deep-let
  coverage 9 to 12 and passed all speed metrics at 1.2357x all-total, 1.1934x
  common-total, and 1.1670x geometric. It added three stable solves with no
  loss. This is the strongest next production candidate, but it is not a
  full-corpus result.

## Local Canary Results

- Warm rerun synthetic canaries:
  - `generated/synthetic/chain1000_sat.smt2`: `euf-viper` 0.0029s, Z3
    0.0064s.
  - `generated/synthetic/chain1000_unsat.smt2`: `euf-viper` 0.0030s, Z3
    0.0062s.
  - `generated/synthetic/grid1000x8_unsat.smt2`: `euf-viper` 0.0033s, Z3
    0.0057s.
- `tests/fixtures/eq_diamond_unsat.smt2` proves the safe common-branch
  consequence preprocessor can return `unsat` on a positive `or` case.
- These are narrow canaries, not global SMT-LIB evidence.

## OR Preprocessor Improvement

- Branch-aware positive `or` preprocessing now tracks both equalities and
  disequalities per branch.
- Same-level `and` processing delays positive `or` analysis until surrounding
  non-`or` literals have been collected.
- New generators:
  - `euf-viper gen diamond BRANCHES DEPTH`
  - `euf-viper gen pruned-or BRANCHES`
  - `euf-viper bench-or --cases N --branches N --depth N`
- Local median comparison against Z3 4.16.0:
  - `diamond_b128_d8_unsat.smt2`: 18.8x faster.
  - `diamond_b512_d4_unsat.smt2`: 64.4x faster.
  - `pruned_or_b512_unsat.smt2`: 1.7x faster.
- A larger local single point, `diamond 2048 4`, solved in about 0.01s by
  `euf-viper` and about 5.10s by Z3.

## WMI Runs

- Job `139145` completed on WMI `cpu_idle` node `c3n1` in 10s with MaxRSS
  `479492K`; 40 synthetic cases, 600380 total terms, benchmark wall time
  2.895389861s. The submit script initially failed to forward local
  `EUF_VIPER_CASES` and `EUF_VIPER_SIZE`; fixed after the run.
- Job `139146` completed on WMI `cpu_idle` node `c3n1` in 14s; OR bench used
  8 cases, branches 1024, depth 4, total terms 24584, wall time 217220141ns.
- Job `139149` completed the fixed QF_UF corpus campaign on WMI in 1:56 with
  MaxRSS `2338356K`; official SMT-LIB 2025 QF_UF corpus ingested as 7503 files,
  deterministic 40-instance sample run with `euf-viper`, Z3Py 4.16.0, and cvc5
  1.3.4. No Z3/cvc5 mismatches; `euf-viper` solved 1 eq-diamond instance and
  returned `unsupported` on 39 Boolean-heavy instances.
- Job `139158` completed all 7,503 official instances at two seconds per solver.
  `euf-viper` solved 6,276 (83.65%), Z3 solved 6,910 (92.10%), and cvc5 solved
  6,513 (86.81%); all three had zero wrong answers. `euf-viper` median latency
  was 0.1126s versus Z3's 0.1676s and cvc5's 0.2939s.
- Job `139229` is the accepted post-parser finite-domain smoke checkpoint:
  37/40 correct, matching Z3 coverage on that sample, with 1.0848x aggregate
  speedup over `139211` on common correct instances.
- Job `139375` confirms the accepted platform split still builds and solves on
  Linux after rejecting the Kissat 4 experiment.
- Job `139381` is the first full four-solver, two-second campaign after adding
  pinned Yices 2.7.0. Final coverage: `euf-viper` 6,471, Z3 6,911, cvc5 6,505,
  Yices2 7,394; medians were 0.0886s, 0.1705s, 0.2956s, and 0.0450s
  respectively. There were no wrong answers or solver disagreements.
- Jobs `139382` through `139384` validate the sharded prepare-array-merge chain
  on eight sampled instances with four solvers and strict completeness checks.
- Jobs `139420` through `139422` completed the full 7,503-instance corpus at 60
  seconds with 64 shards and four active allocations. Coverage was 7,434 for
  `euf-viper`, 7,486 for Z3, 7,471 for cvc5, and 7,500 for Yices2, with no wrong
  answers, disagreements, or execution errors. The complete prepare-to-merge
  wall interval was 26m35s and peak shard MaxRSS was 5,413,416 KiB.
- Jobs `139433`, `139477`, and `139497`/`139498` form the accepted invalid-model
  fallback gate. The affected profile improved 2.36x, the 40-case control kept
  39/40 coverage, and the full paired corpus improved 6,873 to 6,886 correct
  with 1.0034x timeout-inclusive aggregate speed and no wrong answers.

## Research Position

- Current evidence supports a fast-head portfolio tier, not a general claim of
  being a better SMT solver than Z3.
- Yices2 decisively dominates the current implementation at two seconds: it
  wins 6,166 of 6,463 jointly correct instances and has 98.55% coverage. The
  research target is now a specialized certifying front tier or a structural
  portfolio contribution, not an overall fastest-QF_UF claim.
- The unresolved tail is concentrated in finite-model, pigeonhole-shaped
  families where one-hot CNF encounters hard resolution proofs.
- Raising the finite-domain eager cap from 8 to 11 did not attack that wall:
  WMI job `139766` solved 0/4 selected PEQ size 9-11 cases at 120 seconds for
  both configurations. Do not reintroduce the cap change without a different
  encoding or symmetry argument.
- Disabling automatic finite-domain routing is also rejected. Hard-tail A/B
  `139710`/`139711` reduced coverage from 12/69 to 8/69 despite faster
  common-solved timings. Preserve the route unless a candidate keeps or raises
  coverage under the same timeout.
- The root-level finite pigeonhole detector is rejected. Tail A/B `139798`
  kept coverage at 9/69 with a noise-sized 1.0007x aggregate change, and
  corrected profile `139875` detected zero target cliques while costing
  63-486ms on eligible cases. The implementation was removed.
- Sequential per-term at-most-one encoding is rejected. WMI `139894`/`139898`
  solved 0/4 selected finite-model gaps for both pairwise and sequential
  encodings at 120 seconds, with equal timeout-inclusive totals. The option was
  removed; future cardinality work must target cross-term structure.
- Direct CaDiCaL routing does not solve that target either. WMI
  `139900`/`139904` produced 0/4 correct for auto/Kissat and direct CaDiCaL at
  120 seconds with equal totals. Backend selection is not the missing
  cross-term reasoning.
- The 60-second run leaves 69 `euf-viper`, 17 Z3, 32 cvc5, and 3 Yices2
  timeouts. The all-solver oracle covers 7,500/7,503; `PEQ014_size10`,
  `PEQ014_size11`, and `PEQ018_size7` are the shared UNSAT gaps.
- The revision-aware 1,200-second continuation is complete as
  `139688`/`139689`/`139690` at revision `1f68ff1`. It retained 22,457
  unchanged comparator rows and measured all 7,503 `euf-viper` rows plus 52
  comparator timeout rows. Coverage is 7,478 `euf-viper`, 7,500 Z3, 7,491
  cvc5, and 7,503 Yices2, with zero wrong answers or execution errors.
- On 7,478 common `euf-viper`/Z3 solves at competition budget, `euf-viper` has
  a 1.069x geometric speedup and wins 3,878 versus 3,600, but common totals are
  20,668.55s versus 5,365.05s and Z3 has 22 additional solves. Yices wins
  6,852 common cases, covers all 25 `euf-viper` gaps, and is the only solver
  that covers the complete corpus.
- All 6,396 QG-classification instances are covered by every solver at the
  competition budget. The remaining performance and coverage deficit is
  entirely in the 1,107-instance non-QG stratum.
- The accepted opt-in structural portfolio is a separate claim from standalone
  `solve`. It uses only bounded lexical structure, routes 65 corpus cases to
  in-process `euf-viper`, and execs a supplied Yices binary otherwise. Full
  exact-source WMI `140030`/`140035` preserved 7,503/7,503 coverage and improved
  aggregate time from 1,241.01s to 1,186.49s (1.0460x), with zero wrong answers
  or errors. Its geometric speed is 0.8788x and Yices wins 6,327 pairings.
- Portfolio evidence is same-corpus-trained. Five-fold source-hash validation
  had no coverage failures and projected only 1.0030x before launcher overhead.
  Do not present the 1.0460x full result as an independent or general Yices
  victory; fallback answers depend on Yices and need a new-release test.
- The exact-source portfolio binary measured in `140030` has SHA-256
  `2f2b90b94fd05e1b45e4067834a6045f39f2c1b7ddd80b79575ff61f3ffe6ea5`.
  Streaming input was rejected by `140012`/`140017` because overhead regressed.
- Certificate work should pair SAT proof traces for the exact emitted CNF with
  a replayable manifest of EUF-derived clauses and finite-domain axioms.
- Corpus workers must checkpoint in completion order; ordered executor results
  can hide completed tasks behind one slow early task. A/B summaries must
  render missing common-case metrics as `n/a` rather than crashing.

## Benchmark Corpus

- Official source: SMT-LIB release 2025 non-incremental benchmark record
  `10.5281/zenodo.16740866`.
- QF_UF archive: `QF_UF.tar.zst`, size `54182823`, MD5
  `e185bc80a80116bcfea116df190f87d2`.
- Local and WMI ingestion found 7503 `QF_UF` SMT2 files: 4361 `unsat`, 3142
  `sat`.
- Downloaded corpora and manifests are ignored under `benchmarks/smtlib-2025/`
  because manifests contain machine-local absolute paths.

## Solvers

- Local cvc5 Homebrew formula was unavailable; installed official cvc5 1.3.4
  macOS arm64 static release under ignored `third_party/solvers`.
- WMI cvc5 uses official cvc5 1.3.4 Linux x86_64 static release.
- WMI Z3 uses Python `z3-solver 4.16.0.0` wrapper because WMI glibc is 2.35
  and official Z3 4.16.0 Linux CLI binary requires glibc 2.39.
- WMI Yices uses official Yices 2.7.0 Linux x86_64 static-GMP release, SHA-256
  `49566b6f817692820538df78fe406878400d79810631c9372b2495bc81d3e00a`.
  Four-solver smoke job `139380` passed. The official Apple arm64 asset links
  to `/usr/local/lib/libcudd-3.0.0.0.dylib`; local setup omits Yices with a
  warning when that dylib is unavailable.

## LTS/Magma

- LTS has Magma at `/opt/magma/V2.28-3/magma`; use `magma -n` to bypass the
  user startup file because home-directory logging hit quota.
- `scripts/lts/run_magma_remote.sh` ran `artifacts/magma/euf_quotient.m`
  successfully from `/tmp/$USER/euf-viper-cas`.
- The 2026-07-08 revalidation passed Sage and Singular locally and Magma
  V2.28-3 on LTS in 0.010s; the Julia fallback passed with Oscar unavailable.
  `check_cas_local.sh` supplies isolated writable homes for Sage and Julia,
  invokes Julia directly, and layers a writable depot before installed
  packages to avoid cache and launcher lock failures.

## Literature Pointers

- SMT-LIB QF_UF permits closed quantifier-free formulas over Core with free
  sort and function symbols.
- LLM2SMT reports that a QF_UF solver using Nieuwenhuis-Oliveras congruence
  closure plus preprocessing was competitive but still behind Z3 on solved
  instances in their 2026 experiment.
- The equational diamond family is a key DPLL(T) stressor; common-branch EUF
  consequences are a high-priority preprocessor target.

## Critical Soundness Correction (2026-07-10)

- The accepted source `58efe9d` and exact WMI binary
  `4d5431135c95a2c528d287efd2803eaf895a5ec526c9642a570797b02fd47eb7`
  are unsound for parser-supported Boolean-as-data formulas. Three unasserted
  Boolean constants used as arguments to `f : Bool -> U`, with three distinct
  outputs, are reported SAT although Z3 and cvc5 correctly report UNSAT.
- Root cause: Boolean terms used only as UF data need not receive `BoolTerm`
  atoms, while theory validation traverses only represented CNF atoms.
  CaDiCaL `DontCare` values mapped to zero create a second total-model hazard.
- The 7,503-instance results remain exact-corpus timing evidence because they
  have zero observed mismatches. They do not establish general soundness.
- Restore the accepted source lineage, atomize all Boolean data terms, require
  total theory assignments, and rerun correctness gates before promoting any
  performance route or restoring soundness claims.

## Exact 1,200-Second Frontier (2026-07-11)

- Campaign `143382`/`143383`/`143384` completed all 64 shards and the strict
  merge. Coverage is 7,502 euf-viper, 7,500 Z3, 7,495 cvc5, and 7,503 Yices2,
  with zero observed wrong answers or errors.
- Euf-viper's full timeout-charged total is 8,575.78s versus Z3's 8,676.80s,
  but its common-solve aggregate ratio is only `0.6939x`; do not describe this
  as a uniform timing victory. Yices2 totals 2,010.00s and remains complete.
- The measured `58efe9d` binary retains the known Boolean-as-data defect, so
  the campaign is exact-corpus performance evidence only.
- The repaired exact-baseline branch is `soundness/accepted-58efe` at
  `53c12f7`. It must pass WMI differential and paired gates before acceptance.

## Novelty Campaign (2026-07-11)

- Do not claim novelty for eager SAT reduction, partial-trail e-graphs,
  Ackermannization, ordinary symmetry, Hall propagation, DAG sharing,
  portfolios, certificates, or systems optimization in isolation.
- The active differentiated mechanisms are pre-CNF complete-model scouts,
  theory-conditioned Boolean quotient compilation, proof-carrying multi-table
  orbit quotienting, bit-sliced quotient swarms, SAT-native quotient-state
  search, and per-component proof-system migration.
- Yices2 cannot be reached by tail repair alone. The frozen rank-changing
  envelope `TABLE_CORE OR GRAPH_32` contains 7,305/7,503 formulas; broad head
  acceleration is mandatory.
- First behavioral candidate is the complete-model scout because it can only
  return independently validated SAT and targets the broad satisfiable head.
  Orbit and DAG mechanisms begin in telemetry/reference mode in parallel.

## Sound Candidate Checkpoint (2026-07-11)

- Historical performance binary `58efe9d` is not generally sound. Exact repair
  branch `53c12f7` fixes Boolean values used as UF data; main commit `ad1a3ae`
  additionally preserves quoted reserved identifiers and rejects mutating or
  repeated commands after the single supported `check-sat`.
- Corrected WMI Bool-data differential `143698` ran 10,041 formulas with zero
  euf-viper discrepancies. The one common timeout was retried as `143728` and
  all three solvers returned UNSAT.
- Mandatory repair sample `143697` preserved coverage but measured slightly
  slower. Full paired array `143700` and merge `143701` confirmed the cost:
  zero wrong answers, but `0.9974x` total, `0.9940x` geometric, `0.9963x`
  median speed, and two fewer boundary solves. Never describe the mandatory
  repair as an optimization.
- WMI candidate build `143747` is pinned to source
  `b39706e7243c97d3950fceef636ea56a1f8b04c6`. It builds in node-local scratch
  and persists only the gate-tested binary. Direct-negated-root canary
  `143751`, profile `143758`, full four-solver array `143752`, and merge
  `143753` are dependency-chained behind it.
- `EUF_VIPER_DIRECT_NEGATED_ROOT` is default-off. Its same-binary gate must
  pin every other environment setting equally. Gate `143792` timed out in both
  arms on all 14 qg7 targets; despite removing 15,120 CNF items on the exemplar,
  it achieved only `1.00004x` timeout-charged speed. Reject it as a hard-tail
  mechanism and do not broaden it without a different causal hypothesis.
- Exact probe of `qg7/iso_icl_nogen001.smt2` proved that all 5,040 forbidden
  complete binary operation tables form one `S_7` conjugacy orbit. Treat this
  as opportunity evidence until typed base-invariance extraction, independent
  witness replay, and production equivalence gates pass.
- Current exact reference mechanisms are test-only: complete SAT model scouts,
  syntactic/theory Boolean DAG census, binary table canonization, bounded
  quotient CSP with Hall propagation, forbidden-orbit extraction, and exact
  base-invariance/orbit-cover certificates through degree eight. Added exact
  multi-valued table MDD, stabilizer-order, table-aware BVA, and certified
  quotient-state search oracles; none changes production answers.
- The ranked unorthodox route is canonical forbidden-table quotienting,
  stabilizer MDD/AST-guided BVA, certifying Hall/PB escalation, theory-aware
  vivification, and search-aware congruence explanations, with composite
  certificates developed alongside every UNSAT-capable mechanism.
- Fastest sound exact branch is `soundness/exact-parser-negroot` at `ebf8e27`.
  WMI gate `143794` passed 100 tests, all four backend routes on the Boolean
  data counterexample, quoted-symbol fixtures, and query-order rejection. Its
  persisted binary SHA-256 is
  `38421e03b51fae69c354258614f25d507409a689e7fb70981b51328f23e4412a`.
- Exact parser campaign `143811` executed 1,620 cases in 550 groups with zero
  euf-viper case or group failures. Strict comparator findings are preserved:
  21 failed cases/groups across cvc5, Yices2, and Z3 behavior. Differential
  rerun `143810` and full exact array `143798`/merge `143799` remain live.

## Active Measured Candidates (2026-07-11, Round 2)

- SmallVec clause candidate `0a37b0f` is the only broad mechanism currently
  past two independent timing gates. Hot-80 `143825` and disjoint hot-320
  `143826` both pass all statistical checks at equal coverage. Resource job
  `143861` finds no RSS cost and a 1.53% reduction in summed paired median RSS.
  Full 7,503-instance array `143842` and merge `143843` are mandatory before
  merge or default promotion.
- Deep-let automatic focused permutations `3426e63` materially improve the
  17 selected NEQ instances, including +4 solves at two seconds and 1.636x
  common-total speed at 60 seconds. It remains unpromoted because the
  pre-registered median lower bound is 0.9984. Refinement `88bcede` adds a
  verified-domain-size >=6 guard; jobs `143876`--`143878` are live.
- Unconditional leaf quotient `414b109` is sound on current fixture,
  Boolean-data, and parser gates but is rejected as a general timing route:
  target-90 median is 0.9854x and p=`0.3657`, despite two extra Goel solves.
- Qg7 census `143840` covers 418/418 formulas and identifies 174 exact
  first-orbit pattern families. Test-only RTXC commit `a1749dc` searches the
  Latin pattern-avoidance abstraction with Algorithm X, caps, and independent
  witness replay. Its SAT/UNSAT labels are not SMT answers.
- Current complete-model scouts hit only 4/3,142 SAT formulas and are rejected.
  Unconditional quotient telemetry remains useful: 4,058 affected formulas,
  668,507 unique nodes removed, and 1,200 formulas above 10% reduction.
- Isolated direct Kissat loading, borrowed atoms, and `x86-64-v3` are rejected.
  Borrowed atoms retain parser-phase evidence only; the active successor is an
  exact-lineage `tree|shadow|stream` one-pass semantic parser.
- Resource harness commits are `bc27b33` and `dcd9bf5`; 113 Python tests pass.
  Main WMI candidate variables explicitly default unconditional quotienting
  off in commit `6724be2`, preventing environment leakage between gates.

## Round-2 Adjudication (2026-07-11)

- SmallVec `0a37b0f` passes every full-corpus timing statistic on 7,503 files
  (`1.0089x` total, `1.0380x` geometric, `1.0328x` median) but is rejected as a
  global default because one instance and one net repeat lose coverage. Its
  coverage-preserving structural router retains only a negligible 1.00006x
  all-total gain. Preserve the cache-locality evidence; do not merge this
  implementation.
- The verified-domain-six deep-let refinement loses causally to the original
  candidate on all 15 common solves. Reject `88bcede`; do not reinterpret its
  extra boundary solve as a mechanism win.
- Uniform leaf quotienting is rejected, but exact canonical unique-node
  reduction >=1000 is a promoted structural hypothesis: 30 -> 32 solves and
  2.6275x/2.2127x/1.4464x common total/geometric/median speed on 32 frozen
  formulas at 60 seconds. The generic policy in `d2f3946` permits only
  candidate timeout improvements and remains strict against reverse losses.
- External comparison `143950` shows the same forced leaf route at 31/32,
  ahead of Z3 29/32 and cvc5 26/32 but behind Yices2 32/32. Yices2 is 23.11x
  faster geometrically on common solves and wins every pair. Never present the
  leaf slice as a Yices2 victory.
- RTXC `143938` finds 164 eligible qg7 abstractions and all 164 are abstract
  SAT. The shadow engine omits the predicates that distinguish the 18
  source-UNSAT ICL cases from 146 source-SAT BRN cases. Require a source
  assertion ledger with fail-closed consumption; anti-idempotent local cycle
  filters reduce a column from 5,040 to 240 candidates.
- Stream parser `86b1266` passes WMI soundness `143952` and independent review.
  Require parse-only shadow parity over all 7,503 files before timing.
- Auto leaf commit `1cd9ec4` encodes the exact reduction >=1000 selector and
  is locally tested. It remains default-off until review, WMI soundness,
  target reproduction, and full-corpus non-regression complete.

## Flat Clause Promotion And Guarded Successors (2026-07-12)

- Flat persistent clause storage passed WMI soundness, hot-320 timing/resource
  gates, and full array `144072`. On all 7,503 files it improves coverage
  `7,418 -> 7,419`; common-total, geometric, and median speed are `1.0071x`,
  `1.0309x`, and `1.0314x`, with every 95% lower bound above parity, paired
  p=`0.00009999`, and no reverse timeout conversion. It is promoted on main as
  `3c178dc`. Current-lineage array/merge `144224`/`144225` independently gives
  `7,418 -> 7,421` coverage and `1.0094x`/`1.0320x`/`1.0323x` common-total,
  geometric, and median speed. Its strict policy flags one reverse repeat on
  `PEQ014_size9`; same-node adjudication `144309` solves 31/31 in both arms and
  favors the candidate by `1.0225x`, so the regression is not reproducible.
- Automatic leaf quotient `1cd9ec4` passes soundness and the frozen 32-case
  gate, but full array/merge `144056`/`144061` rejects default activation.
  Coverage improves `7,271 -> 7,272`, while common-total/all-total/geometric/
  median speed are `0.9970x`/`0.9995x`/`0.9940x`/`0.9974x`; two baseline-only
  instances and ten reverse timeout samples violate quality. Its early exact
  prefilter `550853b` is neutral on
  hot-320 (`0.9998x` total, `1.0004x` geometric, equal coverage), so this run
  does not justify a successor full gate.
- Forced leaf quotient plus full Ackermann can improve six selected Goel cases
  by `19.27x` geometrically, but an unguarded mixed run OOMs after 10,136,258
  Ackermann clauses. Any production route must cap base CNF, applications,
  arity, literal slots, pair examinations, and fill work before cloning, and
  must activate only on the intended backend.
- Component-local class labels project fewer completion watches but cannot yet
  close the Yices2 gap and require exact term-sort retention. The streaming
  parser and source-bound qg census remain fail-closed until their provenance,
  opened-byte, atomic-checkpoint, and wrapper audits pass.

## Fresh Sound Comparator And QG Result (2026-07-12)

- Current flat-main four-solver jobs `144328`/`144329`/`144330` use exact
  binary SHA `808c59ce...2903ff` and all 7,503 SMT-LIB 2025 QF_UF files at two
  seconds. Coverage is euf-viper 7,408, Z3 7,450, cvc5 7,373, Yices2 7,490;
  timeout totals are 885.69s, 639.66s, 976.53s, and 228.56s. Euf-viper beats
  cvc5 overall and is `1.5666x` faster geometrically than Z3 on common solves,
  but loses Z3 common aggregate at `0.7467x` and trails Yices2 at `0.3543x`
  geometric. No overall Z3 or Yices2 victory exists.
- Exact source-bound qg7 census `144349` contains 419 records for 418 files and
  verifies every source/problem binding. Of 31 eligible cases, 12 yield shadow
  witnesses and 19 abstain; zero yield a refutation. Keep the engine test-only.
- Bounded Ackermann `7bf410b` passes Linux soundness `144317`. Discard timing
  `144371`: its old wrapper omitted causal mode variables. Corrected rerun is
  `144631` with quotient `auto` in both arms and candidate `leaf-budget`.
- Corrected job `144631` rejects bounded Ackermann: baseline/candidate coverage
  is 32/31, the candidate loses `frogs.4.prop1_ab_br_max`, and timeout-charged
  all-case speed is `0.9894x`. Its favorable `1.8056x` common aggregate and
  `2.2359x` geometric ratios cannot override the coverage loss.
- The closed research checkpoints are parser evidence harness `58f015b` (49
  tests plus 45 subtests) and fused quotient census `eae27d0` (136 Rust tests).
  Neither is merged or promoted. No `euf-viper` WMI jobs remain active after
  cancelling eleven superseded pending jobs.

## Best-Overall Campaign Reset (2026-07-12)

- `PLAN.md` is now an actionable campaign rather than a historical job ledger;
  the full design is
  `research-vault/02-design/2026-07-12-best-overall-qf-uf-campaign.md` and the
  validated contract is `campaigns/best-overall-qf-uf-2026-07.json`.
- Add the exact 3,521-case SMT-COMP 2025 QF_UF selection and OpenSMT 2.9.2.
  Keep the 7,503-file corpus as development regression, not a fresh holdout.
- Production Linux uses a Kissat SC2021 wrapper. Causally test Kissat 4.0.4 and
  modern inprocessing before attributing broad gains to new SMT mechanisms.
- Primary architecture hypothesis: stable-ID, proof-carrying per-component
  migration among eager CNF, rollback EUF, quotient/class coding, and native
  adequate-range Hall/PB. Parser/formula staging, semantic DAG factoring,
  explanation economics, and canonical frontier/bit-sliced search are gated
  supporting tracks.
- Phase P0 must complete exact hashes, family/duplicate groups, sealed holdout,
  normalized runner, hierarchical statistics, independent SAT model checking,
  and base-CNF reconstruction before heavy successor timing.

## Phase-Zero Evidence Foundation (2026-07-12)

- The exact 3,521-row SMT-COMP 2025 QF_UF manifest is committed with SHA-256
  `ed00b0e2...2aaa6` and official result archive hash `d79dd5d6...4a1e`.
- `campaigns/solver-releases-2026-07.json` pins official artifacts and source
  revisions for Z3, cvc5, Yices2, OpenSMT 2.9.2, and Kissat 4.0.4. WMI records
  the exact installed executable hashes before campaign freezing.
- Parent, shard, and runtime CPU-binding locks now bind all source, corpus,
  taxonomy, binary, environment, resource, schedule, and output bytes. The
  runner uses cold process groups, affinity/RLIMIT controls, CPU/RSS accounting,
  chained journals, and exact-prefix immutable resume.
- Global analysis rejects missing, duplicate, drifted, or incorrectly derived
  shards before combining observations. Promotion statistics run over the
  complete parent corpus, not shard-local samples.
- Certificate schema v2 emits total SAT assignments or base-CNF plus replayable
  EUF lemmas and DRAT. The independent Python parser reconstructs typed source,
  atoms, and canonical Tseitin without importing Rust code. Focused SAT/UNSAT
  smoke passes; corpus-wide shadow validation remains open.
- The durable WMI chain is prepare -> full/official two-second arrays -> global
  audit. Do not claim any new performance result until this exact revision is
  committed, published, and the global artifacts return.
- Public fixed revision `70f0a60` has green hosted CI run `29199707319` and is
  the last hosted-green revision. WMI prepare/full/official/audit
  `144767`/`144768`/`144769`/`144770` were cancelled during the requested pause.
  Jobs `144763`–`144766` were cancelled before execution because their commit's
  tests depended on ignored local certificate-smoke outputs. No benchmark rows
  exist yet; retain campaign `144328` as the current performance evidence.
- The resumed local checkpoint implements sparse timeout continuations and
  independent per-stage plus staged-union certificate audits. Do not treat it
  as evidence until committed, published, hosted-green, and executed on WMI.
- Commit `1308be8` passed hosted run `29212534371`, but WMI chain
  `144817`/`144818`/`144819`/`144821` was cancelled during preparation because
  the locked binary lacked the opt-in certificate command. The next P0 build
  must use `cargo build --release --features certificates` and bind that exact
  binary for both timing and proof emission.

## Resumed P0 And Modern SAT Control (2026-07-13)

- Corrected revision `b46b137` has green hosted run `29212660080`. Its live WMI
  P0 graph is prepare/full/official/audit `144823`-`144826`, continuation
  dispatcher `144827`, and base certificate chains `144828`-`144833`. At the
  last check, `144823` was running the full taxonomy pass and had emitted no
  benchmark rows. All dependent jobs remain held.
- A local 20-pair ABBA on `loops6/iso_icl053` rejects unconditional CaDiCaL
  clausal congruence as a broad default: conflicts improve `62 -> 51`, but
  median end-to-end time regresses `8.055 -> 9.737` ms (`1.209x` slower).
- Public branch `research-modern-kissat` validation commit `d7c14da` adds
  pinned Kissat 4.0.4 as a feature-selected Linux backend while preserving
  SC2021 as the default control. It exposes fail-closed
  `EUF_VIPER_KISSAT_MODE`/`EUF_VIPER_KISSAT_OPTIONS`, fully namespaces Kitten,
  supports Linux `--all-features`, and records the linked backend in
  `--version`.
- WMI paired artifact validation `144945` passed. SC2021 binary SHA-256 is
  `d7321602b8cc86683ccb41e90bea7b843a5059caad62d1eba347bb3e69c70362`;
  Kissat 4.0.4 binary SHA-256 is
  `ecbcfebb1f39c725c1d0266442c7dcc80083b8347e3b77d90bfb5646bd4ea6b6`.
  Both pass shared SAT/UNSAT fixtures; modern certificate smoke passes with
  pinned `drat-trim` SHA `58a121de...943e5`. No timing evidence exists yet.
- Do not compose Hall or rollback work into the modern-SAT experiment. Measure
  the backend first; the next original mechanisms are proof-pressure-triggered
  conflict-only rollback for validation-dominated Goel cases and a
  source-certified guard-conditioned adequate-range Hall census.
- Baseline prepare `144823` produced both taxonomies but failed before freezing
  because the pinned-wheel Z3 C runner rejected the intentional
  `sat.euf=true` comparator argument. No benchmark rows exist from that graph;
  cancelled dependents `144824`-`144833` remain invalid. The four partial
  taxonomy/split hashes are `ecab4f1f...c80b`, `14cf3582...f7e7`,
  `ec3daa08...deda`, and `d7aa7720...f013`.
- Commit `30828a4` fixes the native wrapper with fail-closed
  `sat.euf=true|false` global-parameter translation and an install-time
  integration smoke. Hosted run `29215009504` passed. Replacement exact-revision
  P0 jobs are prepare `144990`, full `144991`, official `144992`, and audit
  `144993`; no performance claim exists until the audit completes.
- P0 prepare `144990` completed successfully in `01:09:16` at exact revision
  `30828a4f0c1e7e478a9c6f406ccb245eeefc4961`. Full/official lock hashes are
  `58e6cbdf...cd886ad`/`6ba7f60a...9410f9`, solver config is
  `490e959e...a2570`, and the frozen euf-viper binary is
  `edcf8d1a...ba576`. Both locks are promotion-eligible for all six
  configurations. Full array `144991` is producing rows; official `144992` and
  audit `144993` are open. Do not infer aggregate coverage from preparation or
  partial shards.
- The pinned rollback pilot preserves the first invalid eager assignment,
  conflicts, SAT time, and validation time, then uses a conflict-only CaDiCaL
  external propagator. `auto` triggers at validation time
  `>= max(2ms, first SAT time)`; default is off and unknown settings fail.
  Current Kissat exposes no trail/LBD/conflict telemetry, so this is a
  validation-pressure control, not a SAT proof-pressure claim. Whole-instance
  rollback is known; novelty remains component-local checked representation
  migration after the pilot wins.
- Public branch `research-cadical-external-propagator` at `81e0c36` completes
  only the safe conflict-only CaDiCaL 2.2.1/RustSAT callback prerequisite.
  Hosted run `29217315701` passes after `19` vendored unit, `11` integration,
  `2` doc, `222` root-default, and `228` root-all-feature tests. The restricted
  session prevents replacing or reconnecting the solver while callback state is
  borrowed; cached SAT, registration failure, callback panic, operation panic,
  and teardown failure have regressions. Do not call this rollback EUF or a
  performance improvement until the closure, typed explanations, integration,
  and paired timing gates pass.
- Public branch `research-rollback-euf-core` at `0d9ec50` completes the pure
  rollback congruence and explanation core only. Its deterministic union-by-size
  state has rollbackable parent-use and disequality incidence; independent fresh
  closure replays canonical conflict clauses. A `64 x 160` randomized trace
  compares every term pair after every assignment/level/backtrack operation.
  Root tests pass `230` default and `234` all-feature cases, and hosted run
  `29217833901` passes. CaDiCaL integration, complete-model validation, target
  timing, and promotion remain open.
- Source-only adequate-range/Hall census commits `012c963`/`02b68d5` and
  exact-revision submitter `86d76fc` use the independent structured parser,
  bind its hash, report only proved guard-conditioned ranges and bounded Hall
  witnesses, and never solve or claim SAT/UNSAT. Full-corpus WMI job `145027`
  depends on P0 prepare `144990`; audit its eligible population and 30% cell
  saving gate before implementing Hall/PB in the solver.
- Modern SAT paired campaign revision `e67c688` fixes identical complete
  runtime environments for validated SC2021/Kissat-4 binaries, checks all
  source and artifact hashes, binds one CPU, and audits exact shard coverage.
  Jobs `145029`/`145030`/`145031` are externally dependency-bound to successful
  P0 audit `144993`; broad timing runs only after the deterministic sample
  passes. Queue state is not performance evidence.

## Audited Live Checkpoint (2026-07-13)

- Exact P0 revision `30828a4` rejects overall superiority at every completed
  full/official two/60-second audit. Coverage is euf-viper `7,269`/`3,400` at
  two seconds and `7,480`/`3,508` at 60 seconds; Yices2 is
  `7,445`/`3,490` and `7,500`/`3,518`; Z3 default is `7,412`/`3,474` and
  `7,489`/`3,514`. The fast common-instance head does not offset aggregate and
  tail losses. Do not claim euf-viper is better overall.
- The authoritative full 60-second audit has SHA-256
  `2458b01872a290c89f715a277dfd41e2c28091fc649925c9acbfefeb6e72686a`.
  Z3 default and Yices2 solve the same 22 instances missed by euf-viper: nine
  Goel, `PEQ012_size6`, and twelve `qg7` isomorphism cases. Euf-viper has 13
  Z3-only and two Yices-only solves; without regressions it needs ten new solves
  to lead Z3 and 21 to lead Yices. Matching Yices common timing needs about
  `2.04x` geometric and `4.89x` aggregate improvement.
- Valid modern-Kissat sample `145905` rejected replacement: equal 53/64
  coverage, 16 candidate wins versus 37 losses, geometric speed `0.928694`,
  common-total speed `0.963416`, and sign-flip `p=0.999500` when ratios are
  SC2021/Kissat-4. Broad `145906` and merge `145907` are cancelled.
- Range census `145883` is the only current T4 opportunity gate. Certificate
  chains `145892`-`145894` and `145897`-`145899` are held behind it and certify
  only canonical source reruns, not literal timed production evidence.
- Rollback jobs `145900`/`145901`/`145902` exposed an adapter bug and were
  stopped. Commit `01be0a9` records a conflict as emitted only when CaDiCaL
  actually takes it through `external_clause`; undelivered pending conflicts
  may validly recur. Head `2dc4bf7` adds a strict anti-target ABBA preflight and
  passed hosted run `29275599640`. Chain `145916`/`145917`/`145918` failed before
  the canary because nested `srun` could not resolve bare `python3`; dependents
  cancelled. Commit `835d134` pins a validated absolute interpreter and passes
  11 focused plus 302 full Python tests. Exact head `dcc7263` passed hosted run
  `29276687808`; prepare `145923` reached the canary but candidate returned two
  deterministic coverage misses from a persistent-lemma recurrence during
  `notify_assignment`; `145924`/`145925` cancelled. Commit `8e26569` suppresses
  and counts only assignment-time repeats. Complete-model or handoff recurrence
  still aborts. Exact branch head `6e402f0` passed hosted run `29277510106`.
  Fresh prepare `145927` passed its four-observation ABBA canary with baseline
  `correct:2`, candidate `correct:2`, and four bounded repeated-assignment
  conflicts. Binary SHA-256 is `0cff30a189d46423...`, preflight journal SHA-256
  is `e223befc265ee95e...`, and preflight-summary file SHA-256 is
  `2809e913e30b5bb7...`. Array `145928` released automatically; audit `145929`
  remains dependency-held, so no promotion claim exists.
- Full/official 1,200-second continuation graph `145785`-`145789` is intact and
  scheduler-pending. Do not cancel or resubmit from queue state alone.
- T5 must first pass a 7,503-source typed, hash-chained structural projection.
  Require at least 25% broad QG/Goel clause or watch reduction, at least half of
  each eligible family individually at that threshold, weighted and p95
  variable ratio at most `1.25`, eight lineages, complete decoder telemetry,
  and zero parse/hash/cap failures before implementing quotient RAM.

## Corrected Gate Checkpoint (2026-07-13)

- First T4 census `145883` is invalid as a final opportunity decision: it wrote
  7,503 records but had 17 deep-`let` parser errors. Its parsed subset projected
  zero value-cell savings, but T4 can only be rejected after corrected exact
  census `146071` returns 7,503 rows with zero errors. Parser fix `6b51b39` and
  wall-time pin `8f78543` are public.
- Replacement certificate chains are full `146076`-`146078` and official
  `146079`-`146081`, dependency-held behind `146071`. The predecessor chains
  were cancelled; never treat them as corpus evidence.
- Rollback evidence remains array `145928` plus audit `145929`; 1,200-second
  evidence remains `145785`-`145789`. Preserve both graphs and use final audits
  only.
- T1 is isolated at `research-typed-stream-parity` `47d7b0a` pending a final
  snapshot repair and fresh WMI parity chain. T5 is isolated at `b51c75e`
  pending second review. T6 is isolated at `9833ec3`, job `146075`, and cannot
  promote from its historical hard-10 set.
- Production sidecar branch `6095e29` is review-only. A source-valid SAT model
  is not enough: integration requires an independent check that the exact
  production assignment satisfies every production CNF clause and that the
  atom map is complete, plus fail-closed clean-build identity.
- T1 exact revision `8952dcb` passed WMI `146214`/`146215`/`146216`: 7,503
  semantic-snapshot matches, zero fallback/mismatch/error, records SHA
  `593e7e9b...c82ede`, audit SHA `1a0e0d67...b93b26`. Treat this only as parser
  parity until independent review and the ABBA timing gate pass.
- T5 `b51c75e` is no-go pending repair because its WMI receipt did not replay the
  full bundle, contradictory oracle counters passed, and malformed rehashed
  count rows passed. Do not submit it before a strict independent verifier and
  attack regressions clear review.
- Production-evidence schema v1 `6095e29` is no-go. It did not bind the complete
  production CNF/variable map and had TOCTOU, dirty-build, status, and resume
  gaps. Preserve UNSAT fail-closed behavior while schema v2 is repaired.
- Frozen shared deficit is 6 SAT and 16 UNSAT: nine Goel (6/3), one UNSAT PEQ,
  and twelve UNSAT qg7. After T1/T2/T4/T5/T6, run T3 M0 only if two fixed arms
  survive with at least 10% oracle headroom; otherwise test scalar source-exact
  qg7 frontier search before SIMD.
- Rollback final audit `145929` is a valid scientific rejection, not an
  infrastructure failure. All 12 shards completed; 576 observations have zero
  wrong/errors and coverage `15 -> 23`, with target speedups
  `7.6029x`/`9.0741x`/`7.3178x`. Anti-target p95 overhead
  `11.1689x`/`32.7545x`/`23.3462x` fails the `1.10x` cap. Never promote
  whole-instance rollback; use its frozen split only for M0 telemetry.
- T3 M0 is preregistered in `campaigns/t3-m0-component-pressure-v1.json`.
  The 24-source rollback panel is family-confounded and its coverage-aware
  PAR-2 oracle headroom is only `3.74%`, so it cannot train or authorize a
  selector. S0 is representation-neutral typed/base-CNF telemetry; S1 is an
  identical bounded eager shadow prefix. Runtime features exclude path, family,
  lineage, names, hashes, expected/final result, final runtime, winner, and
  post-checkpoint events. Require two eligible fixed arms, headroom LCB at least
  `10%`, balanced-accuracy LCB at least `0.80`, telemetry p95 ratio UCB below
  `1.01`, and byte-identical off/on traces before migration.
- T8 M0 is preregistered in `campaigns/t8-scalar-frontier-census-v1.json`.
  Historical right-translation/orbit search is source-incomplete and has `0/12`
  source-exact UNSAT coverage on the frozen qg7 deficits. The authoritative
  design is a no-forget typed partial-algebra transducer with command-level
  source/auxiliary lineage, complete residual state, an independent tiny-domain
  total-model-set oracle, checked SAT models, and checked UNSAT cube-cover DAGs.
  Do not implement it before independent T1 review, the missing assertion
  ledger, and corrected T4 finite-range evidence. Scalar gates are 200/261
  source-complete one-table cases, 10/12 P12 below one million states, and build
  cost at most 10% of Yices2 on at least 7/12; SIMD remains conditional.
- T5 revision `e930abf` remains no-go after independent review. Direct digest
  and pinned-Python checks passed, but coordinated semantic mutations could
  still reach `completed`, the final check/publish boundary was mutable, failed
  reruns could leave stale completed metadata, and untracked Python modules
  were outside the exact-revision check. Require full semantic replay over
  captured bytes, immutable atomic bundle publication, failure cleanup, and a
  clean import environment before WMI submission.
- T1 revision `7214d63` and WMI `146374`-`146376` mechanically produced 7,503
  matches and zero other statuses, but remain no-go. The source bytes are now
  correctly captured once for hash and stdin parsing; however the parser binary
  was hashed then reopened by path, Python was not canonicalized to its
  realpath, and non-finite shard JSON passed audit. Require descriptor-bound
  executable use, canonical interpreter identity, strict JSON everywhere, and
  a fresh full chain before integration or timing.
- Production-evidence schema v2 `e3add515` remains no-go. A sidecar-controlled
  congruence-closure origin bypassed CNF checks; exact clauses, variables, and
  atom maps were not independently reconstructible; the analyzer could count
  unchecked SAT; final shadow publication preceded rehash; parent symlinks and
  incomplete frames were accepted. Keep UNSAT unsupported. Schema v3 must
  reconstruct initial CNF from source/config, replay dynamic API clauses,
  require exact maps, gate analyzer SAT on the checker, and fail closed on path,
  frame, or JSON ambiguity.
- T4 is finally rejected by corrected WMI census `146071` at revision `8f78543`.
  It completed 7,503/7,503 rows with zero parser errors but found 124,698
  uniform and 124,698 non-uniform value cells, zero savings, zero eligible
  sources, 157 certified domains, 25,760 effective ranges, 24 Hall subsets, and
  zero Hall conflicts. Aggregate/records SHA-256 are
  `b37b9550...c4e42`/`4cfb2d1d...ff961c`. Do not implement Hall/PB; exact range
  telemetry may feed T8 only through its independent source ledger.
- The 12 frozen P12 qg7 rows in T4 records all have empty domains, zero range
  facts, and `no_proven_non_bool_range`. Do not cite global T4 telemetry as T8's
  domain-seven certificate. T8 needs a separate checked finite-domain proof in
  its source ledger before scalar state construction.
- T8's machine contract and exact P12 negative-range artifact are enforced by
  `scripts/bench/validate_t8_scalar_contract.py` in hosted CI. The validator
  binds the raw summary and T4 receipt hashes, all 12 paths, strict JSON, and
  zero-range fields; both evidence paths are mandatory. A successful validation
  means the design is correctly frozen and blocked, not that scalar or SIMD
  implementation is authorized.
- Independent review of the repaired T8 control at `14754f8` is GO for
  preregistration retention only. Hosted run `29290493620` passed, and explicit
  regressions reject receipt drift plus omitted summary, receipt, or both API
  evidence paths. T8 implementation remains blocked on its three prerequisites.
- T5 `ea8dee5` remains no-go. Its semantic reconstruction and Python identity
  passed review, but skip-worktree could hide changed imported bytes, the final
  digest-to-pathname-link interval remained mutable, and failed same-job reruns
  exposed an old completed bundle. Require exact HEAD-blob comparison,
  publication of the checked inode, and attempt-scoped current completion before
  any WMI submission.
- T1 typed-parser parity evidence is accepted at main commit `84b4c8e`; the
  exact reviewed parser source and fixtures are source-complete at `00c11a5`.
  Exact revision `e77846d`, jobs `146510`/`146511`/`146512` and independent
  reconstruction `146652` produced 7,503 matches with zero fallback, mismatch,
  error, or other status. Descriptor execution, canonical Python, strict JSON,
  and hashes passed independent review. This is parity only; 98 rows contain
  4,851 unsupported diagnostics, and timing/completeness still require gates.
- T5 revision `64770d8` remains no-go. Exact Git-blob checking and semantic
  replay passed, but publication exposed a new destination before it was fully
  written and checked, early preflight failure could retain stale `.current`,
  and cleanup ownership raced destination creation. Require atomic no-replace
  publication of the checked staging inode, entry-first marker invalidation,
  and publisher-owned cleanup before another independent review or WMI action.
- Production-evidence schema v3 `578deb8` passes its SAT-only semantic unit
  boundary (230 Rust and 330 Python tests), including independent CNF/map/event
  replay and analyzer gating, but remains merge NO-GO. It predates current main,
  changes the default feature binary without timing, disables several normal
  fast routes in evidence mode, and makes UNSAT nondecisive. Reconstruct it on
  current main as opt-in, then require a 7,503-source shadow and off-mode timing.
- T5 `2080b26` remains no-go despite passing Linux FD-bound publication probes.
  Its non-Linux fallback can link a replacement path, cleanup can unlink a
  replacement after a prior identity check, and a source-swap test incorrectly
  requires relinking instead of fail-closed behavior. Reject unsupported
  publication and never delete staging paths without atomic inode ownership.
- Current-main production-evidence `d47e1c6` remains no-go. Locked prepare omits
  the separate evidence feature while invoking `--evidence-out`; ordinary solves
  still allocate transcripts and duplicate clause streams with evidence off;
  and solve CLI compatibility drifted. Require real feature-combination tests,
  zero evidence-only off-mode work, and ordinary CLI parity before publication.
- Production-evidence repair `939bc60` also remains no-go. It correctly requests
  `certificates,production-evidence` and guards the reviewed SAT happy paths, but
  WMI provenance permits ambient/untracked build influence, ordinary help/error
  bytes differ from `f8d9205`, exceptional exits lack zero-work assertions, and
  no exact combined release traverses recorder/checker/runner/analyzer. The next
  review requires an attempt-private environment-whitelisted checkout, exact CLI
  differential, path-complete telemetry, and a real combined-release smoke.
- T5 `cf1aa3e` remains no-go. The retained staging hard link can mutate the
  completed archive after `.current`; the symlink marker is swappable; Git/lock
  checks are environment-sensitive; final nonce/digests are not receipt-bound;
  pathname cleanup races remain; and the verifier reuses the candidate analyzer.
  Require an unnamed one-link Linux inode, content-bearing completion receipt,
  exact-blob/environment guard, real Linux races, and independent projection
  recomputation before publication or WMI.
- Initial T1 timing revision `a99d9bf` was rejected for empty-tail acceptance,
  timeout censoring, replaceable contract/manifest inputs, metrics before
  semantic parity, telemetry inside the timed path, and untracked remote
  influence. Repair `20be404` also remains no-go: exact payloads were not bound
  to captured stdout, enabling a demonstrated forged all-7,503 timing pass; the
  corpus digest self-certified from mutable remote state; 128 shards were
  mislabeled as repetitions; Cargo had a transient source race; and machine/CI
  identity was below the sub-1% contract. Require raw-output and shard sealing,
  the accepted manifest hash, distinct shard/round constants, monitored builds,
  homogeneous controls, and real-release Linux CI before publication or WMI.
- Live WMI graph remains unchanged: certificate prepares `146076`/`146079` are
  complete; arrays `146077`/`146080` and T6 `146075` are priority-pending;
  certificate audits are dependency-held; full 1,200-second range `[2-63]` and
  official array `145787` are pending with no active continuation shard. Never
  interpret partial rows or alter the fixed dependency graph for queue delay.
