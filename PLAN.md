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

Authoritative sound two-second campaign: `144328`/`144329`/`144330`, solver
revision `3c178dced8eb44e13a6381bdc43290c71658ac40`, binary SHA-256
`808c59ceef559062bb61befea2030b16b890bd18b8936a98d1ea3bc3172903ff`.

| Solver | Correct / 7,503 | Median | Timeout-charged total |
| --- | ---: | ---: | ---: |
| euf-viper | 7,408 | 0.00939s | 885.69s |
| Z3 4.16.0 | 7,450 | 0.02199s | 639.66s |
| cvc5 1.3.4 snapshot | 7,373 | 0.03061s | 976.53s |
| Yices2 2.7.0 | 7,490 | 0.00504s | 228.56s |

Euf-viper beats cvc5 overall and Z3 geometrically on common solves. It does not
beat Z3 overall and trails Yices2 decisively. Historical 60/1,200-second rows
use an unsound predecessor and are opportunity evidence only; current main must
be rerun.

The official SMT-COMP 2025 primary set is also missing. Its QF_Equality division
contains 3,521 selected QF_UF instances; Yices2 won every performance category,
and OpenSMT ranked second. OpenSMT is therefore a mandatory comparator.

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
- [ ] Finish independent base-CNF reconstruction and batch certificate checking.
  The standalone typed parser, canonical Tseitin reconstruction, SAT witness
  checker, EUF lemma replay, and DRAT integration now pass focused and smoke
  tests. The sharded journal runner, strict global auditor, physical-stage
  wrapper, and staged physical-origin union auditor are implemented; returned
  corpus evidence remains before this item closes.
- [ ] Run current sound main plus Z3/cvc5/Yices2/OpenSMT at two seconds.
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
  configurations over `7,503`/`3,521` instances. Full array `144991` is
  producing rows; official `144992` and global audit `144993` remain pending.
  Preparation and partial shards are not comparison evidence.
- [ ] Resume only two-second timeouts at 60 seconds and only remaining timeouts
  at 1,200 seconds. Schema-v2 sparse derivation, dynamic WMI shards, staged
  assembly, and exact carried-row provenance are implemented but not yet run.
- [ ] Publish a new current-main opportunity atlas before tuning a route.

P0 exit: exact manifests, five hashed binaries, complete current baselines,
independent evidence checks, and a frozen family holdout.

## Phase P1: Cheap Falsification

### T0: Modern SAT Backend

- [ ] Embed Kissat 4.0.4 behind the current clause/model interface while
  preserving the SC2021 backend as an exact control. Research branch
  `research-modern-kissat` at `d7c14da` implements the feature-selected pinned
  backend and fail-closed option surface. WMI validation `144945` passed with
  preserved SC2021/4.0.4 binary hashes `d7321602...c70362` and
  `ecbcfebb...ea6b6`. Exact paired campaign revision `e67c688` fixes every
  `EUF_VIPER_*` value identically in both arms, sanitizes ambient state, binds
  one CPU, and verifies all 7,503 source hashes. Sample `145029`, broad array
  `145030`, and merge `145031` are queued behind successful P0 audit `144993`;
  broad timing releases only if the deterministic 64-case sample passes.
- [ ] Ablate clausal congruence, equivalence sweeping, factor/BVA,
  vivification, and phase options on identical emitted CNF.
  A 20-pair local ABBA canary rejects unconditional CaDiCaL clausal
  congruence on `loops6/iso_icl053`: conflicts improve `62 -> 51`, but median
  end-to-end time regresses `8.055 -> 9.737` ms (`1.209x` slower). This is a
  cheap falsification result, not WMI promotion evidence.
- [ ] Require independent SAT-model/proof checks and broad end-to-end gain;
  formula-size reduction alone cannot pass.

### T1: Typed IR And Staged Formula Machine

- [ ] Resume parser checkpoint `58f015b` and run exact opened-byte tree/shadow
  parity over all 7,503 files.
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
- [x] Attach that core behind the scoped CaDiCaL bridge as an explicit,
  default-off standalone control. Branch `research-rollback-propagator` at
  `4b60113` exposes `EUF_VIPER_BACKEND=cadical-rollback`, loads only the base
  Boolean CNF, emits independently replayed typed EUF conflicts, permits no
  external decisions or propagations, and keeps the complete-model validator
  authoritative. Backend failures return `unsupported` without silent
  fallback. Root tests pass `241` default and `247` all-feature cases; hosted
  run `29270646223` passes. This is integration evidence, not timing evidence
  or state-preserving eager migration.
- [ ] Preserve the first invalid eager assignment, checked conflict clauses,
  SAT time, and validation time. The default-off `auto` pilot triggers only
  when validation is at least `max(2ms, first SAT time)`; `force` exists only
  for causal tests. Unknown settings fail closed.
- [ ] Run forced Goel/GRAPH controls against `current`, `model-cuts`, and
  dynamic full Ackermannization. Require fewer complete validations on every
  multi-round target, `1.10x` target speedup, no baseline-only solve, and
  independently replayed conflicts before selector work. The complete
  same-binary campaign harness is published on
  `research-rollback-propagator` at `e8fb05c`: it freezes 12 atlas targets and
  12 deterministic balanced anti-targets, runs exact ABBA blocks over a
  three-comparison modulo-sharded WMI array, records singleton CPU affinity and
  hash-chained telemetry, and enforces the preregistered non-vacuous gate. The
  campaign has not run because WMI SSH is unavailable; no timing criterion is
  checked off from harness tests.
- [ ] Add component-local migration and then delayed propagation only after the
  whole-instance engineering control passes. Rollback DPLL(T) itself is known;
  the differentiated claim requires stable atoms and checked bridge facts
  across per-component eager/rollback/Hall representations.

### T4: Adequate-Range Hall/PB

- [ ] Rerun the source-only opportunity census from hardened main revision
  `628dabf`. The earlier `145027` path predates the independent-parser repair
  and is not promotion evidence. The replacement requires exactly 7,503
  sources and zero structured parse errors, then emits hash-bound
  guard-conditioned ranges, non-uniform value-cell savings, bounded
  Hall-tight/conflict witnesses, caps, and abstentions without invoking a
  solver or producing SAT/UNSAT. Reject implementation if the returned corpus
  population misses the preregistered 30% cell-saving threshold. Submission is
  pending WMI recovery and an inventory of any jobs accepted during SSH loss.
- [ ] Prove non-uniform finite ranges and compare pairwise, totalizer,
  near-optimal CNF, native PB, and reversible matching on generated EUF-PHP
  through at least `n=32`.
- [ ] Require at least 30% fewer value cells and checked Hall/PB reasons before
  frozen PEQ/SEQ timing.

### T5: Component Quotient RAM

- [ ] Project class-code, sorting-network, clause, watch, and decoder cost over
  all 7,503 files.
- [ ] Implement only if a broad frozen QG/Goel stratum projects at least 25%
  fewer clauses or watches than eager triangles/Ackermann pairs.

### T6: Theory-Conditioned Boolean DAG

- [ ] Run dual source-EUF/Boolean-gate congruence census.
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

1. Publish the complete P0 contract revision and require green hosted CI.
2. Run the immutable two-second WMI full/official chain with all comparators.
3. Batch-shadow and globally audit base-stage SAT/UNSAT certificates.
4. Resume only two-second timeouts at 60 and remaining timeouts at 1,200.
5. Certify each physical continuation stage and audit their union against the
   final per-observation physical-origin ledger.
6. Publish the opportunity atlas, then ablate Kissat and run T1/T2/T4/T5/T6.
7. Select the first novel architecture only from measured opportunity.

No WMI campaign beyond the P0 baseline enters the queue before the campaign
lock and independent validation prerequisites pass.
