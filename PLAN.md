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
is 22 shared Z3/Yices solves missed by euf-viper: nine Goel (six SAT, three
UNSAT), one UNSAT PEQ, and twelve UNSAT QG `qg7` cases. With no regressions,
euf-viper needs ten added solves to lead
Z3 and 21 to lead Yices; matching Yices common timing additionally needs about
`2.04x` geometric and `4.89x` aggregate improvement. The original 1,200-second
graph `145785`-`145789` is invalid as aggregate evidence: late full and official
shards failed after `/home` returned `EDQUOT`, and the audits/finalizer were
cancelled. Certificate arrays `146077`/`146080` failed for the same storage
reason and their audits were cancelled. Completed partial rows are quarantined
and will not be interpreted. Recovery uses a fresh exact-revision root under
`/work`, a complete rerun, and new terminal audits; the failed `/home` trees
remain immutable provenance. Recovery barrier `147305` completed, dispatcher
`147306` validated the copied P0 base, and fresh 60-second arrays/audits are
full `147307`/`147308` and official `147309`/`147310`; successor dispatcher
`147311` releases 1,200-second work only after both audits. All 64 official
array tasks, batch steps, and extern steps completed `0:0`. Full audit `147308`
was scheduler-preempted after `02:09:26` and automatically requeued with
`Restarts=1`; the first attempt left neither final nor temporary analysis.
Require a complete restarted audit plus duplicate-aware accounting and continue
to seal all rows until both audits finish. Rollback control
audit `145929`
scientifically rejected whole-instance rollback: coverage improved `15 -> 23`
and target geometric speedups were `7.32x`-`9.07x`, but anti-target p95
overheads were `11.17x`-`32.75x` against a `1.10x` cap.

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
  adversarial review rejected schema v1: auxiliary assignment flips, complete
  atom-map omission, source/sidecar TOCTOU, dirty standalone builds, and a
  deleted-sidecar resume all passed a purported validation boundary. Schema v2
  repair is active. It is not integration-ready until the checker rejects
  dirty builds and independently verifies that the recorded production
  assignment satisfies every exact production CNF clause with a complete atom
  map. Source-model validity alone is not literal production-path evidence.
  Schema v2 revision `e3add515` is also rejected. A sidecar-controlled
  `congruence_closure` origin bypassed CNF/assignment checks; exact CNF,
  variable, and atom-map completeness was not independently reconstructed; the
  primary analyzer counted unchecked SAT; final shadow publication raced its
  rehash; parent symlinks escaped containment; incomplete frames were silently
  truncated; and preparation JSON remained permissive. Schema v3 must replay
  source/config-derived initial CNF plus every dynamic API-clause event and gate
  SAT classification directly on the checker. Revision `578deb8` closes those
  schema-v3 semantic checks and passes 230 Rust plus 330 Python tests, but is
  still not integration-ready: it predates current main, enables evidence in the
  default feature set without a timing gate, and certifies only a restricted
  SAT configuration while all UNSAT results remain nondecisive. Reconstruct it
  on current main as an opt-in feature, then require a full 7,503-source locked
  shadow and paired off-mode timing before any promotion.
  Current-main reconstruction `d47e1c6` correctly makes the feature opt-in and
  preserves the semantic checker, but review remains NO-GO: locked prepare
  builds certificates without the separately required evidence feature;
  ordinary solves still allocate evidence transcripts and duplicate clauses;
  and solve-CLI compatibility changed. Require a real feature-combination smoke,
  zero evidence-only off-mode work, and legacy ordinary-CLI parity before branch
  publication or hosted validation. Repair revision `939bc60` closes the
  combined-feature build request and guards the reviewed happy-path
  allocations, but a second review remains NO-GO: WMI still accepts ambient and
  untracked build/checker influence, ordinary usage output is not byte-identical
  to `f8d9205`, exceptional paths lack zero-work coverage, and the exact
  combined release has no end-to-end smoke. An attempt-private, environment-
  whitelisted repair was published to research branch
  `research-production-evidence-v3-current`. Exact SHA `e838c1f` received a
  narrow publication-only GO, but WMI remains NO-GO: the prepare receipt
  self-certifies replaceable bytes, Cargo and solver execution are not bound to
  the descriptors/hash checks, final publication can be replaced after its
  check, dynamic loaders/libraries/toolchain closure are incomplete, and the
  CLI oracle is candidate-controlled. First hosted run `29384179332` exposed a
  negative-smoke exit-code bug. Commit `b9da60b` requires the checker's actual
  semantic-rejection exit and exact diagnostic; hosted run `29384633378` then
  passed all six Rust feature matrices and the real combined-release locked
  smoke. This authorizes neither merge nor WMI. A phase-separated, immutable-
  snapshot v4 candidate `cd62e3c` was published for diagnostics only. Exact-head
  hosted run `29389748725` failed the Python gate after 414 tests with three
  failures and four errors: an undefined hash validator, missing plan metadata,
  source-path substitution, and resume-schedule corruption. The workflow never
  reached Rust or release smoke, so the conditional one-input WMI preflight was
  not submitted. Review additionally rejects candidate-forgeable build metadata,
  an unenforced Rust compiler baseline, incomplete execution closure, and
  nontransactional publication. V4 repair remains isolated; no production-
  evidence corpus run exists. Repair `afa2a844` passed its local matrices and
  received diagnostic-publication/hosted-only approval, but review still found
  an unverified second descriptor read, candidate-authored build attestation,
  unbound build input channels, incomplete and unenforced runtime closure,
  mutable final analysis publication, shared candidate/baseline compiler-oracle
  trust, and no `GITHUB_SHA == HEAD` assertion. Exact hosted run `29395085728`
  then failed before Rust with 12 failures and five errors among 424 Python
  tests: checker-command arity, Python loader identity, missing parser metadata,
  runner-owned receipt fixtures, and early receipt failures. No Linux evidence
  primitive or WMI preflight ran. The full shadow and merge remain NO-GO.
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
  revision `8f78543`. Both prepares completed successfully, but every array
  task later failed with signal 53 when Slurm could not create output under the
  quota-constrained `/home` tree; audits `146078`/`146081` were cancelled.
  This is infrastructure failure, not certificate evidence. A fresh `/work`
  campaign must rerun prepare, every shard, and the global audit before this
  item closes; no partial artifact may be reused or counted. Fresh `/work`
  chains are full `147315`/`147316`/`147317` and official
  `147318`/`147319`/`147320`.
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
  arrays `145785`/`145787`, audits `145786`/`145788`, and finalizer `145789`.
  The arrays eventually ran, but `/home` quota failure caused three ordinary
  shard failures followed by signal-53 launch/output failures; both audits and
  the finalizer were cancelled. The graph is preserved as failed provenance,
  not benchmark evidence. Recreate the exact `30828a4` P0 input under `/work`
  and run a wholly new continuation chain through both audits and finalization.
  That replacement is live as dispatcher `147306`, 60-second full/official
  arrays `147307`/`147309`, audits `147308`/`147310`, and dependency-held
  1,200-second dispatcher `147311`.
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
- [x] Reject a broad DDFW/local-search track after the 2026 CaDiCaL refresh.
  Only six of the frozen 22 common misses are SAT, below the ten conversions
  needed to lead Z3 and the 21 needed to lead Yices2; Yices2's 60-second common
  timing advantage is also `739.461s` on SAT versus `2,624.977s` on UNSAT.
  Ordinary DDFW, rephasing, and local-search phase import are controls, not
  novelty. Reopen only if a charged perfect-EUF-model phase oracle beats both
  no-phase and shuffled-phase arms, converts at least one of the six SAT Goel
  timeouts, reaches `2x` median speed, loses no solve, and stays below `1%` p95
  phase overhead. No DDFW implementation or WMI campaign is authorized.

### T1: Typed IR And Staged Formula Machine

- [x] Port only the useful streaming lexer/collector from old untyped checkpoint
  `58f015b` onto current typed main. Keep the tree parser authoritative and run
  exact opened-byte semantic-snapshot parity over all 7,503 files, including
  every sort, function signature, term sort, application, assertion,
  Boolean-data term, and unsupported diagnostic. Zero silent fallback.
  Public branch `research-typed-stream-parity` has the typed parity harness and
  pins Cargo plus parser semantics at `8952dcb`. Its first WMI prepare `145940`
  failed before testing because bare `cargo` was absent; dependents
  `145941`/`145942` cancelled. Final chain
  `146214`/`146215`/`146216` completed at exact revision `8952dcb`: all 7,503
  typed snapshots match with zero fallback, mismatch, or error. Audit SHA-256
  is `1a0e0d67...b93b26`. This permits independent review and the timing gate;
  it is not a speed or production-selection result. Repair revision `7214d63`
  reran exact opened-source-byte chain `146374`/`146375`/`146376` with 7,503
  matches and zero other statuses, but independent review rejected its evidence
  boundary: the verified parser executable was reopened by path, Python was
  pinned as an alias rather than a realpath, and `NaN` passed shard JSON audit.
  Final revision `e77846d` executes the no-follow-opened binary through its
  inherited descriptor, pins canonical Python identity, and strictly rejects
  ambiguous or non-finite JSON. Fresh chain `146510`/`146511`/`146512` plus
  independent reconstruction `146652` produced 7,503 matches and zero fallback,
  mismatch, error, or other status. Independent review reproduced all rows and
  hashes and is GO for parity-only integration. Evidence machinery landed at
  `84b4c8e`; the exact reviewed parser source and fixtures are source-complete
  on main at `00c11a5`.
  Ninety-eight matching rows contain 4,851 unsupported diagnostics, so this is
  not parser-completeness, timing, or solver evidence.
- [ ] Require parse and end-to-end ABBA improvement with p95 miss overhead below
  1%; otherwise stop T1. Initial timing revision `a99d9bf` was independently
  rejected before submission: empty miss populations passed, timeout censoring
  selected the common set, ambient contract/manifest overrides were not bound
  to submission hashes, metrics preceded semantic parity, telemetry-only symbol
  cloning polluted the timed path, and untracked remote inputs escaped the
  provenance guard. Revision `20be404` repaired those acceptance formulas but
  failed the second review: stored payloads were not rebound to captured stdout,
  allowing a concrete all-7,503 forged timing win; the expected corpus digest
  was adopted from mutable remote state; `repetitions=128` falsely named the 128
  shards; source could change transiently during Cargo; sub-1% machine identity
  was underbound; and CI did not run the exact release path. Raw-output sealing,
  the accepted manifest digest, a shards/rounds schema split, mutation-monitored
  builds, homogeneous timing controls, and real-release CI are under repair. No
  WMI timing row exists. Revision `26156e3` closed the raw-output, shard-set,
  accepted-corpus, dimension, and offline-build requirements and passed its
  local matrices, but independent review authorized only exact-SHA diagnostic
  publication. WMI remains NO-GO: submitter and job roots are ambient-selectable;
  either public stop sentinel can terminate mutation monitoring before Cargo;
  the final ELF lacks a recursively checked loader/library/toolchain closure;
  and the observed placement cannot support the preregistered sub-1% inference.
  Exact hosted run `29386186960` then failed before GitHub created a job because
  `runner.temp` was used in `jobs.validate.env`, where the `runner` context is
  unavailable. Repair those boundaries, add a genuinely bounded canary mode,
  and obtain a fresh independent review before any WMI submission. Repair
  `7a278b7` fixed workflow evaluation and received branch-only approval, but
  exact hosted run `29389308332` failed both real Linux mutate-and-restore
  monitor tests. The same review rejected full timing because build and harness
  scripts are reopened by pathname after monitoring, the hand-rolled ELF walk
  does not bind the dynamic loader's actual closure, and `0-127%32` combined
  with `--exclusive` on sole node `c1n1` can run only one array element at a
  time. The conditional one-shard WMI canary is therefore stopped. Bind every
  executed script/runtime byte, require monitor-owned readiness evidence, and
  use an evidence-valid placement schedule before another hosted review. No T1
  timing WMI job exists. Repair `ea28651` was independently accepted only for
  branch publication and hosted diagnostics. Review found that arbitrary
  canary shard identifiers can still assemble a full 128-shard
  `research_only_pass`, checked helper scripts are later reopened by pathname,
  readiness binds only a count rather than the exact watch set, and runtime
  evidence underbinds the submitted array plus cancellation ownership. Exact
  hosted run `29392563168` then failed the guarded release build because global
  `+crt-static` flags reached host proc-macro compilation. No release artifact,
  canary, or WMI row exists. Repair the mode/population contract, opened-byte
  execution, exact monitor set, scheduler receipt, and target-scoped static
  build before review.
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
- [x] Run forced Goel/GRAPH controls against `current`, `model-cuts`, and
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
  `2809e913e30b5bb7...`. Array `145928` completed all 12 shards. Final audit
  `145929` returned a valid scientific `reject` over 576 observations. Every
  arm had zero wrong/errors,
  no baseline-only solve, coverage `15 -> 23`, and target geometric speedups
  `7.6029x`/`9.0741x`/`7.3178x` for current/dynamic/model-cuts. Their anti-target
  p95 overheads were `11.1689x`/`32.7545x`/`23.3462x`, far above the `1.10x`
  cap. Whole-instance rollback is rejected as a default.
- [ ] Add component-local migration and then delayed propagation only after the
  whole-instance engineering control passes. It did not pass its broad gate;
  therefore no migration implementation is authorized. T3 M0 may consume the
  frozen rejected arm only to test whether its sharp target/anti-target split is
  predictably isolatable. Rollback DPLL(T) itself is known; the differentiated
  claim requires stable atoms and checked bridge facts across per-component
  eager/rollback/Hall representations.

### T4: Adequate-Range Hall/PB

- [x] Complete source-only opportunity census. First attempt `145883`, exact
  revision `628dabf`, wrote 7,503 rows but terminated nonzero after 17 deeply
  nested NEQ sources hit Python expression recursion. Among parsed sources it
  found 91,895 uniform and 91,895 non-uniform cells, zero cell saving, 151
  certified uniform domains, 14,311 effective ranges, 24 checked Hall subsets,
  and zero Hall conflicts; this is not a final rejection because the zero-error
  gate failed. Commits `6b51b39`/`8f78543` parse nested `let` chains
  iteratively and pin a four-hour census wall time. Corrected exact census
  `146071` completed on WMI in `01:53:20`, exit `0:0`. The structured
  independent parser emits
  hash-bound guard-conditioned ranges, non-uniform value-cell savings, bounded
  Hall-tight/conflict witnesses, caps, and abstentions without invoking a
  solver or producing SAT/UNSAT. The hardened runner requires exactly 7,503
  sources and zero parse errors. Final aggregate has 124,698 uniform and
  124,698 non-uniform value cells, zero savings, 157 certified uniform domains,
  25,760 effective ranges, 24 Hall subsets, zero Hall conflicts, and zero
  eligible sources. Records SHA-256 is `4cfb2d1d...ff961c`.
- [x] Stop before non-uniform/PB implementation. The corrected complete corpus
  misses the 30% cell-saving gate with exactly 0% savings, so pairwise,
  totalizer, near-optimal CNF, native PB, and reversible matching work is not
  authorized.
- [x] Reject frozen PEQ/SEQ timing for T4. Its source range telemetry may feed
  T8's independently checked ledger, but no Hall/PB route survives. All 12 P12
  qg7 rows have empty domains and zero range facts, so T4 does not satisfy T8's
  finite-domain prerequisite.

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
  A second review rejected its evidence wrapper: WMI completion trusted summary
  booleans, contradictory oracle counters could pass, and rehashed rows could
  violate count invariants. A strict independent bundle-verifier repair is
  active; the branch has not been integrated or submitted to WMI. Revision
  `e930abf` fixed direct receipt-digest and Python-identity checks but failed a
  third review: coordinated semantic mutations still reached `completed`, a
  final check-to-publish race remained, failed reruns preserved stale completed
  metadata, and untracked Python modules were outside revision integrity. A new
  immutable captured-byte publication repair at `ea8dee5` closed semantic
  reconstruction and interpreter identity but failed the next review:
  skip-worktree tracked bytes escaped revision checking, the final staged digest
  still preceded pathname publication, and failed same-job reruns exposed an old
  completed bundle. Revision `64770d8` repaired exact Git-blob identity and
  semantic replay, but review still found a visible partial destination, stale
  `.current` on early preflight failure, and cleanup ownership inferred from a
  racy absence check. Checked-inode atomic publication and entry-first marker
  invalidation were repaired at `2080b26`, but the next review found an unsafe
  non-Linux pathname fallback, pathname check-then-unlink cleanup, and a test
  that required relinking after source replacement instead of accepting a
  fail-closed stop. Revision `55c0101` removed that fallback but the fifth
  review still rejected publication: it trusted a stage pathname after checking
  descriptor identity, cleanup could unlink a replacement `.current`, and
  revision-keyed remote work/results allowed concurrent same-revision campaigns
  to erase each other. Generated Python caches also violated the post-test
  checkout guard. Revision `cf1aa3e` added descriptor-selected publication and
  unique roots, but the sixth review found a concrete post-completion corruption
  path through the retained staging hard link, a swappable symlink marker,
  environment-sensitive Git/lock checks, incomplete nonce/final-digest binding,
  lower-level cleanup races, pathname-only Linux emulation, and common-mode
  semantic replay. An unnamed one-link archive, content-bearing completion
  receipt, hermetic exact-blob guard, real Linux tests, and independent
  projection implementation are under repair. No WMI submission is allowed
  before another independent review. Commit `6249393` from the next repair is
  not a valid Git artifact: its isolated clone lost required objects and failed
  `git fsck`. Only the physical files were copied into a fresh valid clone at
  `/private/tmp/euf-viper-t5-recovered`; the corrupt object database will never
  be pushed, cited as evidence, or repaired in place. Valid recovered commit
  `0ad8431` passed local object/test checks but remains WMI NO-GO. Independent
  review reproduced a deterministic 3,521-row official-manifest selection
  against a required 7,503 rows, found the claimed unprivileged
  `linkat(AT_EMPTY_PATH)` gate capability-dependent, found Slurm identity bound
  only to a recyclable numeric job ID, and judged the projection verifier only
  implementation-separated. Diagnostic-only hosted run `29385400195` then
  failed two Linux consumer-test contracts; its one-link syscall test passed,
  but effective capabilities were not recorded. Repair the manifest,
  capability-free procfs publication, full Slurm allocation identity,
  independent oracle, runtime inventory, and end-to-end Linux tests before a
  new review. Commit `446b424` implemented those repairs and exact-head hosted
  run `29388947138` passed its Linux publication diagnostics, but the next
  review still rejected research evidence and WMI. Both candidate and audit
  parsers incorrectly let caller-local bindings leak into `define-fun` macro
  bodies; the submitter releases the held census before the local receipt is
  durably validated; and hosted CI skips the provisioned 7,503-source pipeline
  while its optional driver uses synthetic scheduler evidence. Fix lexical
  scope independently in both parsers, preserve local cancellation ownership
  through receipt persistence, split mandatory Linux publication diagnostics
  from provisioned semantic integration, and review again. No T5 WMI
  submission exists. Repair `48f3cec` passed hosted run `29392694401` for
  mandatory ordinary-Linux publication/procfs and root tests; the provisioned
  7,503-source job truthfully skipped without a corpus. Independent review
  still rejects the scanner and every cluster action: transitive free-global
  dependencies escape through intermediate macros, release/cancel do not
  revalidate full scheduler ownership, the remote namespace admits unchecked
  extras, unique physical source coverage and unsupported top-level forms are
  not closed, the tiny canary underbinds revision and scheduler identity, and
  hosted identity/action pinning is incomplete. No corpus scan, canary, census,
  or T5 timing row exists.

### T6: Theory-Conditioned Boolean DAG

- [ ] Run dual source-EUF/Boolean-gate congruence census. Exact research
  revision `9833ec3` pins Cargo and all source/provenance hashes; WMI job
  `146075` is priority-pending. Historical hard-10 rows are explicitly marked
  pre-fix development evidence. Diagnostic commit `b71a491` mechanically
  reconstructs the current 12-source P0 set and was independently reproduced,
  but review rejects hash-then-reopen inputs, incomplete observation-matrix
  validation, unproved `DOMAIN7_HUGE` membership, path aliases, and a gate not
  bound to population size. It is branch-only and nonpromotable; job `146075`
  remains untouched while the generator is repaired. Exact-head hosted contract
  run `29390630178` is green and changes none of those restrictions. Repair
  `b587847` produced a byte-identical hardened 12-source artifact with SHA-256
  `1b3f4e52...05c21`; independent review accepts those exact population bytes
  and reproduced all physical structural metrics. The branch remains no-go:
  caller-supplied digest overrides can redefine frozen inputs, non-finite JSON
  passes, corpus-manifest regeneration is checkout-path-dependent, and the
  Rust/Slurm consumer still hardcodes manifest v1, 10 sources, and an 8-source
  gate. Do not publish or submit this revision. A separate reviewed consumer
  repair must support v2 and the derived 10-of-12 gate.
  Successor `58aee6e9` independently reproduces the same 12 sources in portable
  artifact `33a9f001...07c78`; it removes contract overrides, rejects strict
  JSON violations, supports manifest v2, and binds the 10-of-12 consumer.
  Diagnostic publication is allowed and supplemental exact-head run
  `29397378080` is green, but WMI remains NO-GO. The workflow omits exact T6
  modules/toolchain pinning; WMI has only Rust 1.93 and a 1.96 rustup install
  fails quota; ambient build/toolchain identity is underbound; Rust runtime
  opening follows joined paths; and the final report is not independently
  recomputed. Projection is still `not_executed` and promotion is false.
- [ ] Require at least 25% projected CNF reduction on `ceil(4N/5)` frozen
  hard-table cases, which is 10/12 for the current population, and more benefit
  than rejected unconditional quotienting. Derive both `N` and the threshold
  mechanically before reading any T6 projection output.

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
- [ ] M0 telemetry: freeze online pressure features and obtain lineage- and
  family-disjoint held-out balanced accuracy at least `0.80` with p95 overhead
  below `1%`. Stop before migration if fewer than two fixed representations
  survive or their oracle headroom is below `10%`.
  - [x] Preregister S0/S1 checkpoints, semantic feature allowlists, forbidden
    leakage fields, Williams labels, duplicate-closure splits, depth-four tree,
    coverage-aware PAR-2 headroom, and confidence gates in
    `campaigns/t3-m0-component-pressure-v1.json`.
  - [x] Reject the 24-source rollback panel as selector training evidence: its
    target/control split is perfectly family-confounded and its coverage-aware
    oracle headroom is only `3.74%` (`223.453 / 215.403 - 1`). Preserve it only
    for schema and label-pipeline tests.
  - [ ] Collect all-source S0 features only after reviewed T1 integration;
    freeze family/lineage/raw-plus-normalized-duplicate closure before labels.
  - [ ] Run the four-arm label panel only after at least two arms become
    migration-eligible; require the 95% cluster-bootstrap lower bound on
    headroom at least `10%` before training or implementing migration.
- [ ] M1: implement one-way eager-to-rollback migration with byte-identical
  behavior when no migration occurs.
- [ ] M2: add finite-to-PB/CQRAM migration only after M1 passes.
- [ ] Replay every bridge lemma independently.
- [ ] Beat every fixed internal representation on held-out targets; otherwise
  reject migration even if it beats current default.

### T7: SAT-Aware Explanation/Vivification

- [ ] Compare shortest, SAT-impact-aware, and certificate-aware congruence
  explanations after T2 exists. Require at least 20% fewer validation rounds or
  downstream propagations, selection overhead below 5%, and `1.10x` target
  speed; reject if shortest-proof alone explains the gain.
  - [x] Freeze a non-compositional opportunity falsifier on exact rollback head
    `6e402f0`. Both `off` and `on` construct and replay the same at-most-four
    deterministic candidate forests and restrict selection to the identical
    minimum-width clause pool. `off` uses lexical order; `on` minimizes LBD,
    current-level count, second-highest level, negative reuse, then lexical
    order. Current eager/model-cut paths are ineligible because they expose no
    decision levels or alternative reasons.
  - [x] Stop after one shadow pass unless at least two of the three frozen
    multi-round controls have two distinct replay-valid minimum-width candidates
    and an `off`/`on` disagreement. Only a surviving opportunity gate authorizes
    a 32-observation four-source ABBA canary; only that canary authorizes the
    frozen 24-source, 192-observation panel. Exact implementation `6269084`
    rebuilt the independently reproduced 24-source manifest digest
    `bea69013...a657`, but the first M3 source timed out at 60 seconds before
    emitting a transcript. The initial opportunity gate is therefore NO-GO and
    no canary or WMI job was launched. Its analyzer, empty-report admission,
    overhead accounting, parser oracle, timing isolation, and forest-identity
    defects also require repair before this track can be reconsidered. Repair
    `fa01e99` fixed lexical macro scope, median arithmetic, terminal four-forest
    reconstruction, and resource collection, but independent review remains
    NO-GO. Prior selector history is not reconstructible, synthetic canary rows
    can self-attest certification, repeat groups do not bind complete source
    identity, and arm-asymmetric materialization can manufacture the full
    `1.10x` gate while the combined overhead remains below 5%. Two successes
    plus one failed M3 source also return `ready`, and evidence paths are
    ephemeral. Do not publish or run this revision. Reconstruct every historical
    pool/selection and certificate from source-bound artifacts, enforce stable
    identity and per-arm inclusive overhead, require all three M3 sources, and
    repeat review.
  - [ ] Require nonzero disagreements, zero replay/certificate/fallback/wrong/
    error/missing/off-only outcomes, selected width equal to the common minimum,
    selector work below 5%, at least 20% fewer validations or propagations,
    `1.10x` target geometric speed, and A12 p95 overhead at most `1.10` with no
    coverage loss. A pass authorizes only a current-main port and the later
    shortest/SAT-impact/certificate-aware comparison.
- [ ] Run no/Boolean/EUF/combined vivification factorial and reject if generic
  vivification explains the gain. EUF or combined must beat Boolean-only,
  remove at least twice as many useful literals, reduce later validation or
  propagation by at least 15%, and deliver `1.05x` target speed without broad
  loss.

## Conditional Phase: T8 Canonical Frontier/Bit-Sliced Quotient Search

- [ ] Reopen finite-table search only with source-complete semantics from T1 and
  checked finite ranges from T4.
  - [x] Freeze the source-ledgered scalar contract in
    `campaigns/t8-scalar-frontier-census-v1.json`. Historical right-translation
    search has `0/12` source-exact UNSAT coverage and is an accelerator/control,
    never the authoritative state.
  - [x] Enforce the exact contract and P12 negative-range artifact in hosted CI
    with `validate_t8_scalar_contract.py`. Strict JSON, the raw summary and T4
    receipt hashes, all 12 paths, and every zero-range field are bound; both
    evidence paths are mandatory and a valid contract still authorizes neither
    implementation nor SIMD. Independent review is GO for retaining this
    denial-only preregistration control.
  - [ ] Add command-byte-span/raw-AST identities and complete lineage for every
    source assertion and parser-generated auxiliary. T1 parser parity alone
    does not provide this ledger.
  - [ ] Require a checked P12 finite-domain certificate and independent review
    of T1 before scalar implementation. Corrected T4 evidence is complete but
    proves no non-Boolean range on all 12 P12 sources, so a separate source-
    ledger proof is mandatory.
- [ ] Run canonical scalar frontier census over one-table and domain-seven
  targets, recording state reuse, separator width, and transition cost. Require
  zero exhaustive-checker mismatches, at least 10/12 frozen qg7 targets under a
  `1,000,000`-state cap, and build cost at most 10% on most targets.
  - [ ] Start with a no-forget authoritative state, an independent domain-1--3
    total-model-set oracle, and checked SAT models/UNSAT cube-cover DAGs.
  - [ ] Require at least 200/261 `DOMAIN7_ONE_TABLE` sources to be
    source-complete and the build-cost gate on at least 7/12 P12 targets.
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

1. Preserve corrected zero-error range census `146071` as a final T4 rejection:
   7,503 rows, zero parse errors, zero eligible sources, and exactly zero
   value-cell savings against the 30% threshold. Do not implement Hall/PB.
2. Quarantine failed certificate chains `146076`-`146078` and
   `146079`-`146081`. Recreate them from exact revision `8f78543` under a fresh
   `/work` root and require complete arrays plus terminal audits; do not reuse
   or interpret partial `/home` output. Replacement full chain is
   `147315`-`147317`; official is `147318`-`147320`.
3. Preserve rollback audit `145929` as a rejection: do not promote
   whole-instance rollback. Reuse its frozen target/anti-target telemetry only
   in T3 M0 after the remaining fixed-arm gates finish.
4. Keep modern Kissat 4 rejected: valid sample `145905` lost both geometric and
   aggregate paired gates, so broad `145906` and merge `145907` stay cancelled.
5. Preserve failed 1,200-second graph `145785`-`145789` as immutable provenance.
   Copy and verify the exact P0 base under `/work`, submit a fresh continuation
   chain, and accept only complete full/official audits plus finalization.
   Barrier/dispatcher `147305`/`147306` passed; monitor arrays
   `147307`/`147309`, audits `147308`/`147310`, and successor `147311`.
6. Complete adversarial review and repair of production model/proof sidecars;
   canonical certificate reruns do not certify the timed production path.
7. Finish and audit the T1 full parser shadow; independently review T5 before
   submission; run T6 `146075`; implement only mechanisms that pass their
   frozen construction thresholds.
8. If at least two fixed representations survive with 10% oracle headroom, run
   T3 M0 component-pressure telemetry under the frozen S0/S1 contract. The
   current family-confounded 24-source panel has only 3.74% coverage-aware
   headroom and cannot authorize it. Otherwise stop migration and test the
   scalar source-exact T8 qg7 frontier census under its frozen no-forget/source-
   ledger contract before any SIMD work. T8 remains blocked until T1 review,
   assertion lineage, and corrected T4 evidence complete.
9. Select and compose a novel architecture only from independently checked,
   broad paired wins; then rerun P4/P5 on two CPU classes.

No result enters promotion because it was submitted, queued, or partially
observed. Every branch remains isolated until its complete audit passes.
