# Plan

## Objective

Build the best standalone single-core QF_UF solver overall: sound, certifying,
faster than Z3, cvc5, Yices2, and OpenSMT, and at least as complete at 2, 60,
and 1,200 seconds on both official and full-library benchmarks.

The detailed design is in
`research-vault/02-design/2026-07-12-best-overall-qf-uf-campaign.md`. The
executable contract is
`campaigns/best-overall-qf-uf-2026-07.json`.

## Current Truth

Authoritative exact-revision campaign: prepare/full/official/global-audit
`144990`/`144991`/`144992`/`144993`, solver revision `30828a4`, with all six
configurations and both corpus selections hash-bound by the campaign locks.

| Solver configuration | Full 2s / 7,503 | Official 2s / 3,521 | Full 60s / 7,503 | Official 60s / 3,521 |
| --- | ---: | ---: | ---: | ---: |
| euf-viper | 7,269 | 3,400 | 7,480 | 3,508 |
| cvc5 | 7,222 | 3,384 | 7,479 | 3,510 |
| OpenSMT | 6,916 | 3,215 | 7,448 | 3,497 |
| Yices2 | 7,445 | 3,490 | 7,500 | 3,518 |
| Z3 default | 7,412 | 3,474 | 7,489 | 3,514 |
| Z3 `sat.euf=true` | 7,395 | 3,469 | 7,484 | 3,511 |

All four global audits reject promotion. At 60 seconds euf-viper's common-wall
geometric factor is `1.5685x` over Z3 default on the full corpus and `1.5214x`
on the official set, but common-wall aggregate factors are only `0.5873x` and
`0.6146x`; Yices2 geometric factors are `0.4910x` and `0.4710x`. Euf-viper is
therefore not yet the overall leader. The exact full 60-second pairwise deficit
is 22 shared Z3/Yices solves missed by euf-viper: nine Goel, one PEQ, and twelve
QG `qg7` cases. With no regressions, euf-viper needs ten added solves to lead
Z3 and 21 to lead Yices; matching Yices common timing additionally needs about
`2.04x` geometric and `4.89x` aggregate improvement. Full 1,200-second array
`145785` has started on WMI: two shards are complete, one is active, and the
remaining shards are scheduler-bound. Official array `145787` remains
priority-bound, with audits/finalizer `145786`/`145788`/`145789`
dependency-held. The graph is unchanged.

## Victory Contract

- [ ] **V0 valid:** zero wrong answers, validation failures, execution errors,
  missing rows, hash mismatches, or unreplayable proof steps.
- [ ] **V1 official leader:** match best coverage and beat the leading score on
  the exact SMT-COMP 2025 QF_UF selection.
- [ ] **V2 full-library leader:** equal or exceed all comparator coverage at 2,
  60, and 1,200 seconds and improve timeout/PAR-2 plus common geometric time.
- [ ] **V3 held-out leader:** reproduce the direction on sealed source-family
  holdout or newly released data and a second CPU class.
- [ ] **V4 differentiated contribution:** pass closest-prior-art audit and
  ingredient ablations for any novelty claim.

No external comparator fallback, family/path/hash routing, warm daemon, or
result cache can satisfy V1-V4.

## Reconciled Historical Questions

- [x] Independently parse SMT-LIB and reconstruct the atom map and base Tseitin
  clauses before accepting EUF clauses or the SAT proof. The standalone checker
  now owns parsing, atom IDs, canonical Tseitin, EUF replay, SAT assignments,
  and DRAT validation; corpus-wide shadowing remains a separate P0 gate.
- [x] Gate and reject typed-sort tracking as a standalone optimization.
  Exact sort metadata is retained for correctness; do not compare again with
  unsound parent `58efe9d`.
- [x] Implement and reject automatic deep-let focused permutations. Commit
  `3426e63` remains default-off research; refinement `88bcede` lost causally in
  `143878`.
- [ ] Reduce the finite tail only through named frozen mechanisms T4/T5/T8,
  each with causal, cross-architecture, and full-corpus gates.
- [ ] Treat existing tables as empirical performance evidence. Certifying or
  superiority tables wait for independent base-CNF, model, and proof checks.
- [x] Retain exact term/function sort metadata in current main.
- [ ] Prototype component-local class coding only after a corpus-wide
  construction projection and exhaustive decoder equivalence.
- [x] Retire `143752`/`143753` and `143798`/`143799` as superseded and cancelled;
  use `144328`/`144329`/`144330` as authoritative.
- [x] Close exact-lineage prerequisites: `143794`, corrected `143810`, and
  replacement parser gate `143811` passed before the current-main campaign.
- [x] Reject the current production orbit-cover route. Source-bound census
  `144349` has 12 witnesses, 19 abstentions, and zero refutations; preserve it
  test-only.
- [x] Complete the fail-closed QG assertion ledger and local filters in
  `144349`; no production answer can be produced.
- [x] Park the one-pass parser at public research commit `58f015b`. A 7,503-file
  shadow campaign is a restart prerequisite, not evidence of promotion.
- [x] Promote flat persistent clause storage as `3c178dc` after full and repeated
  adjudication.
- [x] Reject automatic leaf quotienting after `144056`/`144061`; successor
  `550853b` is neutral.
- [x] Reject bounded leaf Ackermann after corrected causal job `144631` lost one
  solve and regressed all-case time.

## Phase P0: Freeze Evidence

- [x] Add local and GitHub CI validation for
  `campaigns/best-overall-qf-uf-2026-07.json`; every submission must invoke the
  same validator. First public workflow run remains a publication check.
- [x] Ingest and hash the exact SMT-COMP 2025 QF_UF selection. The portable
  3,521-row manifest is reconstructed from official result data at commit
  `82b2c91e` and has SHA-256 `ed00b0e2...2aaa6`.
- [x] Install and release-lock OpenSMT 2.9.2; repin Z3, cvc5, and Yices2 source
  and official artifacts. Exact WMI binary hashes are generated by the pending
  prepared baseline and bound into its campaign lock.
- [x] Add family/generator taxonomy, normalized SMT-LIB fingerprints, duplicate
  closure, and grouped development/holdout splits. The complete 957 MB
  fingerprint execution remains part of WMI preparation; random file-hash
  folds are forbidden.
- [x] Add a declarative campaign lock that generates all child environments and
  rejects omitted causal variables. Locks now bind source, release lock,
  solver binaries, corpus bytes, taxonomy, budgets, ordering, resources, and
  output journals; deterministic child shard locks preserve the parent hash.
- [x] Add a cgroup/BenchExec-style runner with one-core binding, memory/RSS/CPU
  accounting, process-group termination, balanced solver order, and immutable
  resume. The runner records which affinity/RLIMIT controls the host actually
  enforces instead of claiming unavailable cgroups.
- [x] Add hierarchical family-cluster analysis: exact McNemar, PAR-2,
  family-macro score, 99% superiority intervals, and Holm correction. Sharded
  evidence is reconstructed against the exact parent lock and analyzed only as
  one complete corpus, never as independent shard promotions.
- [ ] Add independent SAT-model emission/checking for every candidate SAT result.
  Public research branch `research-production-evidence` at `6095e29` adds an
  atomic `solve --evidence-out PATH` sidecar and is under independent
  adversarial review. It is not integration-ready until the checker rejects
  dirty builds and independently verifies that the recorded production
  assignment satisfies every exact production CNF clause with a complete atom
  map. Source-model validity alone is not literal production-path evidence.
- [ ] Finish independent base-CNF reconstruction and batch certificate checking.
  The standalone typed parser, canonical Tseitin reconstruction, SAT witness
  checker, EUF lemma replay, and DRAT integration now pass focused and smoke
  tests. The sharded journal runner, strict global auditor, physical-stage
  wrapper, and staged physical-origin union auditor are implemented. First
  range dependency `145883` failed after writing all 7,503 source rows because
  17 deeply nested `let` sources exceeded the Python recursion limit; its old
  certificate dependents were cancelled. Replacement full chain
  `146076`/`146077`/`146078` and official chain
  `146079`/`146080`/`146081` are held behind corrected census `146071` at exact
  revision `8f78543`. Returned complete corpus evidence remains before this
  item closes.
- [x] Run current sound main plus Z3/cvc5/Yices2/OpenSMT at two seconds.
  Revision `70f0a60` chain `144767`-`144770` was cancelled during the requested
  project pause before producing benchmark rows. The replacement immutable
  chain at `1308be8` passed hosted CI but was cancelled during preparation when
  the exact locked binary lacked certificate emission. Corrected revision
  `b46b137` prepare `144823` completed both taxonomies but failed before lock
  creation because the old-glibc native Z3 adapter rejected the frozen
  `sat.euf=true` argument. No benchmark row exists; dependent jobs
  `144824`-`144833` were cancelled. Commit `30828a4` now translates the two
  supported `sat.euf` values through Z3's global parameter API and installs a
  fail-closed native-runner smoke. Hosted run `29215009504` passed. Replacement
  prepare/full/official/audit jobs are `144990`/`144991`/`144992`/`144993` and
  are dependency-bound to exact revision
  `30828a4f0c1e7e478a9c6f406ccb245eeefc4961`. Prepare `144990` completed in
  `01:09:16` with status `prepared`: full/official lock hashes are
  `58e6cbdf...cd886ad`/`6ba7f60a...9410f9`, the solver configuration hash is
  `490e959e...a2570`, and the euf-viper binary hash is
  `edcf8d1a...ba576`. Both parent locks are promotion-eligible and bind all six
  configurations over `7,503`/`3,521` instances. Full array `144991`, official
  array `144992`, and global audit `144993` completed. Both exact two-second
  audits rejected promotion: euf-viper solved `7,269`/`3,400`, versus Yices2
  `7,445`/`3,490` and Z3 default `7,412`/`3,474`.
- [ ] Resume only two-second timeouts at 60 seconds and only remaining timeouts
  at 1,200 seconds. Both 60-second continuations and audits completed and
  rejected promotion. Dispatcher `145397` generated full/official 1,200-second
  arrays `145785`/`145787`, audits `145786`/`145788`, and finalizer `145789`;
  two full shards are complete, one is active, and remaining full plus official
  work is pending on node availability, priority, and dependencies.
- [x] Publish a new current-main opportunity atlas before tuning a route.
  Commit `d948993` binds the exact post-parser-fix full 60-second audit and the
  22-source shared Z3/Yices deficit. A bounded unresolved-track refresh is in
  progress; it cannot alter the frozen deficit or preregistered gates.

P0 exit: exact manifests, five hashed binaries, complete current baselines,
independent evidence checks, and a frozen family holdout.

## Phase P1: Cheap Falsification

### T0: Modern SAT Backend

- [x] Embed Kissat 4.0.4 behind the current clause/model interface while
  preserving the SC2021 backend as an exact control. Research branch
  `research-modern-kissat` at `d7c14da` implements the feature-selected pinned
  backend and fail-closed option surface. WMI validation `144945` passed with
  preserved SC2021/4.0.4 binary hashes `d7321602...c70362` and
  `ecbcfebb...ea6b6`. Exact paired campaign revision `45ba12c` fixes every
  `EUF_VIPER_*` value identically in both arms, sanitizes ambient state, binds
  one CPU, and verifies all 7,503 source hashes. The first post-P0 sample
  `145884` failed before timing because inherited absolute paths named another
  checkout. Corrected source rebinding passed hosted run `29274065472`;
  replacement sample `145905` completed validly and rejected replacement: both
  arms solved `53/64`, Kissat 4 won 16 and lost 37 paired instances, geometric
  speed was `0.928694`, common-total speed was `0.963416`, and sign-flip
  `p=0.999500` with SC2021/Kissat-4 orientation. Broad `145906` and merge
  `145907` were dependency-cancelled.
- [ ] Ablate clausal congruence, equivalence sweeping, factor/BVA,
  vivification, and phase options on identical emitted CNF.
  A 20-pair local ABBA canary rejects unconditional CaDiCaL clausal
  congruence on `loops6/iso_icl053`: conflicts improve `62 -> 51`, but median
  end-to-end time regresses `8.055 -> 9.737` ms (`1.209x` slower). This is a
  cheap falsification result, not WMI promotion evidence.
- [ ] Require independent SAT-model/proof checks and broad end-to-end gain;
  formula-size reduction alone cannot pass.

### T1: Typed IR And Staged Formula Machine

- [ ] Port only the useful streaming lexer/collector from old untyped checkpoint
  `58f015b` onto current typed main. Keep the tree parser authoritative and run
  exact opened-byte semantic-snapshot parity over all 7,503 files, including
  every sort, function signature, term sort, application, assertion,
  Boolean-data term, and unsupported diagnostic. Zero silent fallback.
  Public branch `research-typed-stream-parity` has the typed parity harness and
  pins Cargo plus parser semantics at `47d7b0a`. Its first WMI prepare `145940`
  failed before testing because bare `cargo` was absent; dependents
  `145941`/`145942` cancelled. A final semantic-snapshot repair is being tested
  before a fresh immutable 7,503-source chain is submitted.
- [ ] Require parse and end-to-end ABBA improvement with p95 miss overhead below
  1%; otherwise stop T1.
- [ ] Profile fused Boolean/model/signature passes. Build bytecode only if at
  least 70% of routed CPU time is reusable and schedule cost projects below 5%.

### T2: Lazy-First And Rollback EUF

- [x] Add a safe conflict-only IPASIR-UP bridge to the pinned CaDiCaL/RustSAT
  binding. Public branch `research-cadical-external-propagator` at `81e0c36`
  vendors the hash-bound 0.7.5 binding and CaDiCaL 2.2.1, disables external
  decisions and propagations, catches callback panics, validates observed
  literals and falsified conflict clauses, preserves teardown failures, and
  prevents safe Rust from replacing or reconnecting the solver while native
  callbacks hold borrowed state. Vendored tests pass `19` unit, `11`
  integration, and `2` doc cases; root tests pass `222` default and `228`
  all-feature cases; hosted run `29217315701` passes. This is an isolated
  prerequisite, not production integration or timing evidence.
- [x] Implement and differentially verify the solver-independent rollback core.
  Public branch `research-rollback-euf-core` at `0d9ec50` uses deterministic
  union by size without path compression, rollbackable application and
  disequality incidence, capped signature work, causal congruence edges, and
  an independent fresh-closure conflict replay. Its randomized gate covers
  `64 x 160 = 10,240` assignment/level/backtrack transitions and compares every
  term pair after each transition; cap, typing, rollback, literal-reuse, and
  tampering regressions also pass. Root tests pass `230` default and `234`
  all-feature cases; hosted run `29217833901` passes. No timing claim exists.
- [x] Attach that core behind the scoped CaDiCaL bridge. Every callback conflict
  must carry an independently replayable typed EUF explanation; no external
  decisions or propagations are permitted in the first pilot, and the existing
  complete-model validator remains authoritative. Public rollback head
  `2dc4bf7` connects a default-off standalone backend and fails closed as
  `unsupported` on any bridge or validation failure. Commit `01be0a9` fixes a
  WMI-discovered pending-clause handoff defect; root matrices pass `242`
  default and `248` all-feature tests, and hosted run `29275599640` passes.
- [x] Preserve the first invalid eager assignment, checked conflict clauses,
  SAT time, and validation time. The default-off `auto` pilot triggers only
  when validation is at least `max(2ms, first SAT time)`; `force` exists only
  for causal tests. Unknown settings fail closed. After the callback-handoff
  repair, root matrices pass `242` default and `248` all-feature tests; hosted
  run `29275599640` passes.
- [ ] Run forced Goel/GRAPH controls against `current`, `model-cuts`, and
  dynamic full Ackermannization. Require fewer complete validations on every
  multi-round target, `1.10x` target speedup, no baseline-only solve, and
  independently replayed conflicts before selector work. Public harness
  `e8fb05c` passed hosted validation. The first WMI attempt was rejected before
  timing on a corpus-root mismatch. The path-correct `145900`/`145901`/`145902`
  attempt was stopped after two shards exposed 40/48 candidate `unsupported`
  observations caused by the adapter handoff defect. Fixed commit `2dc4bf7`
  adds an exact four-observation anti-target ABBA preflight. Chain
  `145916`/`145917`/`145918` rejected before that canary because nested `srun`
  could not resolve bare `python3`; dependents cancelled automatically. Commit
  `835d134` pins one validated absolute interpreter. Exact branch head
  `dcc7263` passed hosted run `29276687808`; prepare `145923` then reached the
  canary but returned baseline `correct:2`, candidate `coverage_miss:2` because
  an already persistent lemma recurred during `notify_assignment`. Dependents
  `145924`/`145925` cancelled. Commit `8e26569` suppresses and counts only
  assignment-time repeats; complete-model or handoff duplicates still abort.
  Exact branch head `6e402f0` passed hosted run `29277510106`. Fresh prepare
  `145927` completed in `00:06:06`: its immutable ABBA canary returned baseline
  `correct:2`, candidate `correct:2`, and four bounded repeated-assignment
  conflicts. The exact binary SHA-256 is `0cff30a189d46423...`, preflight
  journal SHA-256 is `e223befc265ee95e...`, and summary SHA-256 is
  `2809e913e30b5bb7...`. Array `145928` released automatically; audit `145929`
  remains dependency-held. Only that final audit can promote.
- [ ] Add component-local migration and then delayed propagation only after the
  whole-instance engineering control passes. Rollback DPLL(T) itself is known;
  the differentiated claim requires stable atoms and checked bridge facts
  across per-component eager/rollback/Hall representations.

### T4: Adequate-Range Hall/PB

- [ ] Complete source-only opportunity census. First attempt `145883`, exact
  revision `628dabf`, wrote 7,503 rows but terminated nonzero after 17 deeply
  nested NEQ sources hit Python expression recursion. Among parsed sources it
  found 91,895 uniform and 91,895 non-uniform cells, zero cell saving, 151
  certified uniform domains, 14,311 effective ranges, 24 checked Hall subsets,
  and zero Hall conflicts; this is not a final rejection because the zero-error
  gate failed. Commits `6b51b39`/`8f78543` parse nested `let` chains
  iteratively and pin a four-hour census wall time. Corrected exact census
  `146071` is active on WMI. The structured independent parser emits
  hash-bound guard-conditioned ranges, non-uniform value-cell savings, bounded
  Hall-tight/conflict witnesses, caps, and abstentions without invoking a
  solver or producing SAT/UNSAT. The hardened runner requires exactly 7,503
  sources and zero parse errors. Reject implementation if the returned corpus
  population misses the preregistered 30% cell-saving threshold.
- [ ] Prove non-uniform finite ranges and compare pairwise, totalizer,
  near-optimal CNF, native PB, and reversible matching on generated EUF-PHP
  through at least `n=32`.
- [ ] Require at least 30% fewer value cells and checked Hall/PB reasons before
  frozen PEQ/SEQ timing.

### T5: Component Quotient RAM

- [ ] Project class-code, restricted-growth, sorting-network, clause, literal,
  two-watch, and decoder cost over all 7,503 files using only the independent
  typed parser. Require an exact hash-chained row per source, zero parse/hash/
  cap failures, and no SAT/UNSAT execution. Compare against exact eager
  Ackermann plus equality-triangle counts; do not convert structural estimates
  into timing claims.
- [ ] Implement only if a broad frozen QG/Goel stratum projects at least 25%
  fewer clauses or watches than eager triangles/Ackermann pairs. In each family,
  require weighted and median reduction, at least half the files individually
  meeting the 25% threshold, weighted and p95 variable ratio at most `1.25`,
  coverage of at least 5% of QG and Goel plus eight lineages, and complete
  bounded decoder telemetry. Any failed gate rejects T5 before solver work.
  Research branch `research-t5-component-quotient-census` at `b51c75e` now has
  a bounded executable decoder oracle over 316 assignments, complete parser
  symbol accounting, and weighted plus p95 literal/watch no-regression gates.
  It remains under a second independent review and has not been integrated or
  submitted to WMI.

### T6: Theory-Conditioned Boolean DAG

- [ ] Run dual source-EUF/Boolean-gate congruence census. Exact research
  revision `9833ec3` pins Cargo and all source/provenance hashes; WMI job
  `146075` is priority-pending. Historical hard-10 rows are explicitly marked
  pre-fix development evidence, and promotion is disabled until a current
  frozen 12-source manifest is mechanically derived from P0.
- [ ] Require at least 25% projected CNF reduction on 8/10 frozen hard-table
  cases and more benefit than rejected unconditional quotienting.

P1 exit: every survivor passes semantic differential and its preregistered
opportunity threshold. Failed tracks stop before expensive timing.

## Phase P2: Isolated Mechanisms

- [ ] For each P1 survivor, create one branch and one same-binary off/on switch.
- [ ] Run exhaustive/generated correctness, target ABBA, anti-target controls,
  sample-40, and hot-400.
- [ ] Require zero loss and positive end-to-end timing; clause counts or phase
  profiles alone cannot pass.
- [ ] Publish one decision packet after each result and stop for user review.

Do not compose two candidates in P2. Attribution must remain exact.

## Phase P3: Heterogeneous Solver

### T3: Proof-Complexity-Triggered Component Migration

- [ ] Assign stable semantic IDs and component ownership across eager, rollback,
  quotient-RAM, and Hall/PB representations.
- [ ] M0 telemetry: freeze online pressure features and obtain held-out balanced
  accuracy at least 0.80 with overhead below 1%.
- [ ] M1: implement one-way eager-to-rollback migration with byte-identical
  behavior when no migration occurs.
- [ ] M2: add finite-to-PB/CQRAM migration only after M1 passes.
- [ ] Replay every bridge lemma independently.
- [ ] Beat every fixed internal representation on held-out targets; otherwise
  reject migration even if it beats current default.

### T7: SAT-Aware Explanation/Vivification

- [ ] Compare shortest, SAT-impact-aware, and certificate-aware congruence
  explanations after T2 exists.
- [ ] Run no/Boolean/EUF/combined vivification factorial and reject if generic
  vivification explains the gain.

## Conditional Phase: T8 Canonical Frontier/Bit-Sliced Quotient Search

- [ ] Reopen finite-table search only with source-complete semantics from T1 and
  checked finite ranges from T4.
- [ ] Run canonical scalar frontier census over one-table and domain-seven
  targets, recording state reuse, separator width, and transition cost.
- [ ] Require at least 70% useful SIMD lane occupancy before AVX2 work.
- [ ] Validate every SAT model; require exhaustive checked cube covers for UNSAT.
- [ ] Beat Yices2 directly on the target including setup before broad QG routing.

This track stops if the eligible source-complete population stays narrow or the
frontier cannot amortize SIMD/model reconstruction.

## Phase P4: Full Promotion

- [ ] Run complete 7,503-instance paired gates twice on two CPU classes.
- [ ] Require zero wrong/error/missing rows and no baseline-only solve.
- [ ] Require timeout total, common total, and geometric 95% lower bounds above
  one, with no material family, SAT/UNSAT, median, p95, startup, or RSS loss.
- [ ] Check every candidate SAT model and UNSAT certificate independently.
- [ ] Freeze and publish raw rows, environment/campaign locks, hashes, analysis,
  and every rejected arm.
- [ ] Stop for user approval before merging or composing an accepted candidate.

## Phase P5: Superiority

- [ ] Freeze the binary before opening the sealed holdout.
- [ ] Run official QF_UF and full-library 2/60/1,200-second campaigns against all
  four external comparators under engineering and official resource lanes.
- [ ] Repeat on a second homogeneous node/date.
- [ ] Apply 99% family-cluster intervals and Holm correction.
- [ ] Claim best overall only if V0-V3 all pass in the same frozen release.
- [ ] Audit closest prior art and ingredient ablations before a V4 paper claim.

## Global Stop Rules

Stop the affected track immediately on any wrong answer, invalid proof/model,
hash mismatch, leaked holdout, missing row, resource-limit escape, unsupported
fallback counted as a solve, or causal environment mismatch. Stop after a
failed stage without inspecting later sealed holdouts.

GPU, JIT/native stencils, quotient RAM caches, fork snapshots, cross-worker
semantic exchange, and multicore races remain census-gated. External Yices2
fallback can be an operational portfolio but never a standalone victory.

## Immediate Queue

1. Finish corrected zero-error range census `146071`; reject T4 if its exact
   7,503-row aggregate misses the preregistered opportunity threshold.
2. Let dependency-bound full/official certificate chains
   `146076`-`146078` and `146079`-`146081` batch-shadow and globally audit the
   exact two-second rows only after `146071` succeeds.
3. Let rollback array `145928` and final audit `145929` finish; promote only
   from the immutable final audit, never from completed or active shards.
4. Keep modern Kissat 4 rejected: valid sample `145905` lost both geometric and
   aggregate paired gates, so broad `145906` and merge `145907` stay cancelled.
5. Preserve the existing 1,200-second continuation graph `145785`-`145789`;
   diagnose scheduler state without changing its evidence.
6. Complete adversarial review and repair of production model/proof sidecars;
   canonical certificate reruns do not certify the timed production path.
7. Finish and audit the T1 full parser shadow; independently review T5 before
   submission; run T6 `146075`; implement only mechanisms that pass their
   frozen construction thresholds.
8. Select and compose a novel architecture only from independently checked,
   broad paired wins; then rerun P4/P5 on two CPU classes.

No result enters promotion because it was submitted, queued, or partially
observed. Every branch remains isolated until its complete audit passes.
