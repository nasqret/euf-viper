# Plan

## Objective

Build a fast-head, certifying Rust QF_UF solver and benchmark campaign that can
make reproducible comparisons against Z3, cvc5, and Yices2, then serve as the
front tier of a coverage-oriented portfolio.

## Milestones

- [x] Create Rust project scaffold in `/Users/airbartek/codex/z3`.
- [x] Implement a strict QF_UF ground-conjunction parser and congruence-closure
  verifier.
- [x] Add generated synthetic benchmark families.
- [x] Add durable memory, journal, Obsidian vault, Jupyter Book, and CAS
  artifact scaffold.
- [x] Install local Z3 comparator and run small canary comparisons.
- [x] Run first WMI synthetic benchmark job.
- [x] Run Magma artifact on LTS.
- [x] Add a DPLL(T) layer for arbitrary Boolean structure.
- [x] Add diamond/common-consequence preprocessing for QF_UF disjunctions.
- [x] Add branch-aware positive-`or` pruning against surrounding disequalities.
- [x] Add repeated median Z3 comparator for cold-start-resistant local timing.
- [x] Integrate SAT backends through RustSAT plus a Linux Kissat bridge.
- [x] Install or build cvc5 comparator in a reproducible environment.
- [x] Download SMT-LIB QF_UF benchmark release and build a full corpus manifest.
- [x] Run WMI cluster campaign with fixed timeout, memory, and artifact logs.
- [x] Expand `euf-viper` beyond one solved official eq-diamond sample instance.
- [x] Run the full 7,503-instance QF_UF corpus at a fixed two-second budget.
- [x] Add per-instance A/B comparison and structural manifest filtering.
- [x] Add pinned Yices 2.7.0 to every comparator schema and solver log.
- [x] Run the full four-solver corpus at a fixed two-second budget.
- [x] Add restartable SLURM array sharding with strict complete-result merging.
- [x] Run the full corpus at 60 seconds per solver.
- [x] Run a competition-budget campaign using sharded SLURM jobs.
- [x] Quantify family balance and report QG versus non-QG results separately.
- [x] Emit exact DIMACS plus SAT proof traces for UNSAT eager runs.
- [x] Check SAT proofs independently and replay EUF-derived axiom manifests.
- [ ] Independently reconstruct the base Tseitin CNF from SMT-LIB input.
- [x] Route invalid eager SAT models through measured CaDiCaL lazy refinement.
- [x] Test finite-cap, finite-bypass, sequential-AMO, direct-CaDiCaL, and
  root-pigeonhole tail hypotheses under paired WMI gates; remove every
  candidate that fails coverage and speed gates.
- [x] Add an opt-in structural Yices portfolio and pass a full 7,503-instance
  coverage and aggregate-speed gate.
- [x] Add a post-validation dynamic Ackermann/chordal route and pass targeted,
  hot-path, hard-family, and full 7,503-instance paired speed/coverage gates.
- [x] Add verified finite-domain symmetry breaking, remove parser token-string
  duplication, and pass full paired gate `142412`: coverage `6,891 -> 6,898`,
  all-total `1.0059x`, common-total `1.0078x`, geometric `1.0220x`, with zero
  wrong answers or execution errors.
- [x] Confirm the coverage-changing cases with seven repeats on both WMI CPU
  architectures (`142478`, `142479`) and eliminate the apparent baseline-only
  timeout as a reproducible regression.
- [x] Add deterministic A/B opportunity analysis with coverage, family,
  timeout-neighborhood, and largest-delta reports.
- [x] Complete fresh four-solver two-second campaign `142480`/`142481`/`142482`
  using the exact promoted binary SHA-256. The solver beats cvc5 overall and
  beats Z3 by `1.111x` common-total and `2.035x` geometric speed, but trails Z3
  by 249 solves and Yices2 by 546 solves.
- [x] Re-run the exact promoted scoped-let binary in four-solver campaign
  `143049`/`143051`/`143052`: euf-viper 6,948, Z3 7,176, cvc5 6,926, Yices2
  7,434; euf-viper keeps a `1.119x`/`2.083x` common-total/geometric edge over
  Z3 but trails its coverage by 228 and Yices2 by 486.
- [x] Promote direct-root CNF after full gate `142591` improved coverage
  `6,825 -> 6,843`, all-total `1.006x`, common-total `1.010x`, and geometric
  speed `1.026x` with zero wrong answers or execution errors.
- [x] Add bounded Yices-style equality abstraction with independent semantic
  audit, shadow telemetry, and default-off fact insertion.
- [x] Replace cloned nested-`let` environments with scoped restoration;
  `NEQ027_size10/11` improved by `5.63x` aggregate in repeated gate `142743`.
- [x] Complete scoped-`let` full gate `142745`/`142750`; reject unconditional
  activation after a one-solve coverage loss and `0.996x` geometric speed.
- [x] Promote the predeclared `>=512` lexical-let automatic route after
  targeted, sample, hot, full `142952`/`142996`, and repeated c2n1/c3n1
  coverage-change gates all passed without a baseline-only case.
- [x] Re-run and reject the clique-core finite-support policy: repeated finite
  gate `142796` passed, but hot-400 `142867`/`142871` lost two solves and
  regressed every speed metric, so no full gate was launched.
- [ ] Gate compact typed-sort tracking against its pre-sort parent before
  implementing definitional substitution. Removing the duplicate valid-path
  traversal recovered aggregate speed in `143080`. Dense declaration indexing
  then passed isolated sample `143178` at `1.0129x` geometric speed, but the
  combined typed branch still lost to `58efe9d` in `143188` at `0.9835x`.
  Exact-term reuse then failed its isolated gate `143202` at
  `0.99995x`/`0.99987x` aggregate speed and was reverted. Continue reducing
  measured valid-path allocation or signature overhead before substitution;
  removing the guarded finite context also failed `143220` and was restored.
  Cross-architecture `143228` confirmed the production loss, and an entry-API
  reuse path failed isolated `143232`. Global-get `143239` improved aggregate
  speed but failed geometric speed and was reverted; unique-term post-parse
  validation then failed aggregate speed in `143244`. Revert it before testing
  dense sort-symbol indexing as an independent candidate.
- [x] Implement and reject non-default equality `guarded-facts`. Sample
  `143160` passed narrowly, but current-baseline selected-population gate
  `143161` stayed 29/29 and regressed all three speed metrics. Scoped-let had
  already recovered every one of the 11 historical fact-only solves, so no
  hot-400 or complete-corpus gate was launched.
- [x] Rerun the accepted standalone solver at 60 seconds. Exact campaign
  `143248`/`143249`/`143254` completed at 7,478 euf-viper, 7,490 Z3, 7,473
  cvc5, and 7,500 Yices2 solves with no wrong answers or errors.
- [x] Complete the accepted standalone 1,200-second timeout-only resume.
  Prep `143382`, array `143383`, and merge `143384` produced euf-viper
  `7,502`, Z3 `7,500`, cvc5 `7,495`, and Yices2 `7,503` solves. The measured
  historical binary retains the Boolean-data defect and is performance
  evidence for the exact corpus only.
- [x] Evaluate PGO globally and through a source-SHA-folded structural route.
  Reject global PGO for coverage and aggregate regressions; reject an external
  router because independent all-time gain is only `1.00010x` before overhead.
- [ ] Implement and promote the deep-let focused-permutation conjunction.
  Same-binary selected-population gate `143412` passed at 17/17 coverage with
  1.6475x all/common-total and 1.8109x geometric speed. Two-second boundary
  `143438` added three stable solves and passed all speed metrics. Restore
  accepted source, implement the exact automatic route, then require repeat,
  sample, hot-400, and complete-corpus gates before promotion.
- [ ] Reduce the remaining finite-model tail without regressing a full-corpus
  paired speed or coverage metric.
- [x] Run local/LTS CAS checks for the quotient-congruence artifacts.
- [ ] Publish benchmark tables only after independent checker validation.

## Live 2026-07-12 Measured Iteration

- [x] Promote flat persistent clause storage as `3c178dc` after soundness,
  hot-320, resource, and full 7,503-instance gates. Full campaign `144072`
  improves coverage `7,418 -> 7,419`, common-total `1.0071x`, geometric
  `1.0309x`, and median `1.0314x`, with all lower confidence bounds above one
  and no reverse timeout conversion.
- [x] Complete current-main exact-lineage confirmation `144224`/`144225`:
  coverage `7,418 -> 7,421`, common/all/geometric/median speed
  `1.0094x`/`1.0073x`/`1.0320x`/`1.0323x`, with every timing confidence bound
  passing. The strict merge flags one reverse repeat on `PEQ014_size9`; pinned
  31-repeat job `144309` solves 31/31 in both arms and favors flat clauses by
  `1.0225x`, so retain promotion while preserving the mechanical rejection.
- [x] Adjudicate and reject automatic leaf quotient full gate
  `144056`/`144061`. Coverage improves `7,271 -> 7,272`, but two baseline-only
  instances, ten reverse timeout samples, and `0.9970x` common-total,
  `0.9995x` all-total, `0.9940x` geometric, and `0.9974x` median speed violate
  the promotion contract.
- [x] Measure early quotient prefilter `550853b` against its direct parent on
  hot-320 (`144222`). Equal coverage and `0.9998x` total time are neutral; do
  not launch a full successor gate without stronger causal evidence.
- [x] Finish and independently audit the bounded Ackermann successor. Commit
  `7bf410b` passes 138 Linux tests in `144317`; corrected 32-case causal gate
  `144631` then rejects it for a lost solve and `0.9894x` all-case speed.
- [x] Close the parser track for this round at research checkpoint `58f015b`.
  Its exact-byte, paired, atomic evidence harness passes 49 tests and 45
  subtests. It remains unmerged; a 7,503-file shadow campaign is mandatory if
  the track is resumed.
- [x] Finish the source-bound qg wrapper and exact qg7 census `144349`.
  All 418 bindings verify; 31 cases are eligible, with 12 shadow witnesses,
  19 abstentions, and zero refutations. Reject it as a production UNSAT engine.
- [ ] Retain exact sort metadata before implementing a component-local class
  label prototype; require exhaustive small-model equivalence and a frozen
  construction-cost gate before SAT timing.
- [x] Run fresh exact current-main two-second four-solver campaign
  `144328`/`144329`/`144330`: euf-viper 7,408, Z3 7,450, cvc5 7,373, Yices2
  7,490. Euf-viper beats cvc5 overall and Z3 geometrically on common solves,
  but loses Z3 aggregate/coverage and trails Yices2 decisively.
- [x] Adjudicate bounded Ackermann on corrected 32-case causal job `144631`.
  Baseline/candidate coverage is `32/31`; common speed is `1.8056x` aggregate
  and `2.2359x` geometric, but the candidate loses `frogs.4.prop1_ab_br_max`
  and all-case speed is `0.9894x`. Reject. Discard invalid job `144371`.

## Acceptance Criteria For A Superiority Claim

No claim that `euf-viper` is faster than Z3 is accepted until all of the
following exist:

1. A named benchmark corpus with immutable source URLs or checksums.
2. Exact solver revisions for `euf-viper`, Z3, cvc5, and Yices2.
3. Machine, CPU, memory, timeout, and parallelism metadata.
4. Raw per-instance timing and result logs.
5. A discrepancy audit for every nonmatching `sat`, `unsat`, `unknown`, timeout,
   or crash.
6. A public reproducibility script.

The stronger claim "beats both Z3 and Yices2" additionally requires:

7. Standalone operation without invoking either comparator as a fallback.
8. Coverage at least equal to both comparators at 2, 60, and 1,200 seconds.
9. Lower timeout-charged aggregate time and lower geometric mean on common
   solved instances in two independent full-corpus runs.
10. A source-family-held-out or newly released QF_UF evaluation to rule out a
    corpus-specific router or detector.
11. Independently checked UNSAT evidence for every newly introduced
    preprocessing, symmetry, counting, or theory-propagation rule.

## 2026-07-10 Research Program

The detailed hypothesis ledger and execution order are in
`research-vault/02-design/2026-07-10-superiority-program.md`. The program has
three parallel technical fronts:

1. Remove head overhead using direct-root CNF, streaming semantic parsing,
   compact term/clause storage, SAT-boundary copy removal, and profile-guided
   code layout.
2. Change the proof system on finite tails using native finite-domain
   `AllDifferent`/Hall propagation, pseudo-Boolean explanations, and complete
   multi-table orbit canonization.
3. Replace model-level theory retries on general QF_UF with model-directed
   Ackermann cuts and, if justified, a rollback e-graph attached through
   CaDiCaL's external-propagator interface.

Every candidate remains default-off until it passes the same-binary targeted
gate, hot-path gate, hard-tail gate, and complete 7,503-instance gate. A
target-family win is evidence for routing, not evidence for promotion.

## 2026-07-11 No-Compromise Novelty Campaign

The active campaign is specified in
`research-vault/02-design/2026-07-11-no-compromise-novelty-campaign.md`.
Primary novelty candidates, in execution order, are:

1. pre-CNF complete-model scouts with independent SAT-model validation;
2. theory-conditioned quotient compilation of the Boolean DAG;
3. proof-carrying stabilizer-chain orbit quotienting for finite tables;
4. bit-sliced quotient-model swarms;
5. canonical quotient RAM and frontier quotient-state search;
6. proof-complexity-triggered per-component representation migration.

The exclusion map forbids novelty claims for eager encoding, rollback
congruence closure, dynamic Ackermannization, ordinary symmetry clauses,
Hall propagation, DAG hash-consing, portfolios, certificates, or low-level
optimization considered separately. Every mechanism starts in shadow or
reference mode and is killed before timing if its opportunity or semantic
distinction is absent.

The broad Yices2-changing envelope is `TABLE_CORE OR GRAPH_32`, covering
7,305/7,503 formulas. Narrow domain-7 and graph-2500 populations are mechanism
gates, not endpoints. Superiority requires complete or leading coverage,
`1.05x` timeout and common-total speed, `1.02x` geometric speed, lower median
and p95, two CPU classes, two repeats, held-out data, and checked evidence.

### Live 2026-07-11 Checkpoint

- [x] Repair Boolean values used as data and independently complete or reject
  partial SAT assignments (`56c56f6`; exact accepted-lineage port `53c12f7`).
- [x] Run corrected deterministic Bool-data differential: WMI `143698`
  covered 10,041 formulas with zero euf-viper discrepancies. One all-solver
  timeout was retried by hash in `143728`; all three solvers returned UNSAT.
- [x] Repair quoted reserved symbols and single-query command ordering in
  `ad1a3ae`. Quoted `|true|` and `|not|` now remain user symbols; mutation or a
  repeated query after `check-sat` is rejected instead of silently changing
  the answer.
- [x] Add fail-closed differential parsing and a deterministic paired
  promotion gate with bootstrap intervals, sign-flip tests, timeout parity,
  coverage, wrong-answer, and execution-error rejection.
- [x] Add test-only complete-model scouts, Boolean quotient-DAG telemetry,
  exact table canonization, bounded quotient CSP, forbidden-orbit extraction,
  and exact orbit-cover certificates. None can change a production answer.
- [x] Prove that `qg7/iso_icl_nogen001.smt2` contains 5,040 unique forbidden
  complete tables forming one exact `S_7` conjugacy orbit. The same input has
  497,474 Boolean occurrences but only 11,370 syntactic nodes.
- [x] Finish exact repair A/B `143700`/`143701`. The mandatory repair has zero
  wrong answers, but is not an optimization: 7,273 common correct instances,
  `0.9974x` total, `0.9940x` geometric, `0.9963x` median speed, and two fewer
  solved instances at the two-second boundary. It is retained for soundness
  and rejected by the statistical promotion gate.
- [x] Accept research-main WMI build `143747` as sound. Direct-negated-root
  run `143751` completed computation but could not write its result under the
  effective WMI file quota; exact rerun `143792` completed after bounded
  cleanup. Profile `143758` records the clause and load deltas.
- [ ] Complete fixed four-solver two-second research-main array `143752` and
  merge `143753`, then the faster exact-lineage array `143798` and merge
  `143799`, against Z3, cvc5, and Yices2. No superiority claim precedes these
  results.
- [x] Reject direct negated-root CNF as a qg7 hard-tail mechanism. It removes
  15,120 CNF items and reduces measured CNF construction on the exemplar, but
  both arms timed out on all 14 target instances and timeout-charged speed was
  only `1.00004x`. The flag remains default-off; no broader behavioral gate is
  justified from this hypothesis.
- [ ] Pass exact-lineage soundness `143794`, parser candidate gate `143797`,
  direct-on Boolean-data differential `143796`, and full campaign
  `143798`/`143799` for commit `ebf8e27`. Its first gate `143786` passed all
  100 tests and built the release binary but failed before semantic fixtures
  because the archive omitted the external counterexample; `ebf8e27` makes
  the archive self-contained and removes compile-disabled merge residue.
- [ ] Convert the exact orbit-cover reference into a production recognizer
  only after typed base-invariance extraction and replayable certificates are
  end-to-end tested.

### Live 2026-07-10 Candidates

- **Correctness repair, mandatory first:** atomize every Boolean-valued term
  used as data, require total assignments for all theory-relevant atoms, and
  fail closed on short or relevant `DontCare` models. The accepted binary has
  a confirmed SAT-for-UNSAT counterexample, so no performance candidate can be
  promoted until backend regressions, differential tests, and WMI correctness
  gates pass.

- **Base-CNF lazy-first EUF:** source audit shows current model-cuts refinement
  still loads all equality-transitivity clauses and is reached only after the
  eager first call. A default-off CaDiCaL mode will omit generic transitivity
  and congruence initially, learn only validator-explained EUF cuts, and
  abstain to the existing fallback on saturation. Forced Goel, control,
  sample, hot, and full gates are specified in
  `research-vault/02-design/2026-07-10-base-cnf-lazy-first.md`; implementation
  waits for the current finite-route gate and rejected-parser revert.

- **Deep-let focused permutation:** exact same-binary gate `143412` on all 17
  files selected by the existing `>=512` lexical-let threshold preserved
  17/17 coverage and improved all/common/geometric speed by
  1.6475x/1.6475x/1.8109x. Implement the conjunction on accepted source; do not
  infer a global win until automatic-route sample, hot, and full gates pass.
  Five-repeat two-second gate `143438` separately improved coverage `9 -> 12`
  and all/common/geometric speed by 1.2357x/1.1934x/1.1670x with no loss.

- **Domain-7 orbit breaking:** first verify whole-formula automorphisms and
  exact one-table canonization. The initial 261-case gate contains five of the
  ten closed-table 60-second timeouts and 421.54 seconds of common excess.
- **Boolean-DAG hash-consing:** telemetry must show at least 25% projected CNF
  reduction on 8/10 closed-table timeout formulas before a solving gate over
  the 174 structurally selected large formulas.
- **Partial-trail rollback e-graph:** after lazy complete-model refinement is
  sound, test conflict-only IPASIR-UP observation on 39 large non-table graph
  formulas. Propagation and decision control remain forbidden until the
  conflict-only stage passes.

- **Finite permutation support, focused:** passed repeated boundary gate
  `142578`, finite gate `142581`, hot-400 `142597`, and cross-architecture gate
  `142702`. Full gate `142610` gained five solves and improved total time but
  missed geometric promotion at `0.997x`; the original route is rejected as a
  global default. A necessary `(n-1)`-core prefilter then failed hot-400 and is
  also rejected.
- **Direct-root CNF:** full gate `142591` passed coverage and every speed metric;
  it is promoted by `50edc7d`, with `EUF_VIPER_DIRECT_ROOT_CNF=0` as rollback.
- **Model-directed CaDiCaL cuts:** explicit refinement gate `142586` improved
  common and geometric speed slightly at equal coverage. Auto-routing gate
  `142628` lost four Goel solves and is rejected; keep the mode default-off and
  preserve dynamic Ackermannization.
- **Equality abstraction:** bounded `off|shadow|facts` modes and an independent
  soundness audit are complete. Unrouted facts regressed the 40-case sample;
  associative flattening, duplicate-unit suppression, quotas, and a frozen
  shadow-hit manifest are complete. Same-binary hardened sample and hard-hit
  gates are running with fresh equality atoms disabled.
- **Streaming parser:** scoped `let` environments removed roughly eleven
  million copies on the worst nested case and passed a `5.63x` targeted gate.
  Unconditional activation failed the full-corpus gate; a predeclared
  lexical-let threshold now decides whether the scoped path is used.

### Live Round-2 Promotion Queue

- [x] Reject the current fixed complete-model scouts after full census:
  4/3,142 validated SAT hits is below the 5% opportunity threshold.
- [x] Measure unconditional quotient opportunity on all 7,503 formulas:
  4,058 affected, 668,507 unique nodes removed, 1,200 at or above 10%.
- [x] Pass SmallVec soundness, hot-80, disjoint hot-320, and peak-RSS gates.
  Candidate `0a37b0f` has equal correctness, statistically supported speed,
  and no memory regression.
- [x] Finish SmallVec full array `143842` and merge/gate `143843`. All timing
  checks pass, but one baseline-only instance and net -1 repeat coverage reject
  global promotion. A coverage-preserving router retains only 1.00006x
  all-total speed, so do not merge it.
- [x] Reject direct Kissat short-clause loading, borrowed atoms alone, and
  `x86-64-v3` as isolated performance mechanisms.
- [x] Preserve deep-let focused permutations as a narrow candidate after
  +4 two-second solves and 1.636x sixty-second common-total speed; do not
  weaken the failed median confidence gate.
- [x] Reject the verified-domain-six refinement after soundness `143876` and
  exact gate `143877`: causal job `143878` loses all 15 common pairs against
  the original mechanism.
- [x] Reject unconditional leaf quotient as a general route after target-90
  median 0.9854x and nonsignificant paired evidence, despite two extra Goel
  solves. Goel-773 confirms +8 coverage but 0.9852x median, so uniform routing
  remains rejected.
- [x] Promote the frozen structural leaf hypothesis `unique Boolean-node
  reduction >=1000` on its 32-case, 60-second, three-repeat gate: 30 -> 32
  solves and all timing lower bounds above one.
- [x] Run four-solver structural comparison `143950`. The leaf candidate beats
  Z3/cvc5 coverage but loses every common timing pair to Yices2; use this to
  target Goel SAT search rather than claiming superiority.
- [x] Complete qg7 census `143840`: 174 exact orbit covers among 418 files.
- [x] Review and run hardened RTXC census `143938`: 164 final eligible cases,
  all abstract SAT and zero abstract UNSAT. Reject the current abstraction as
  an UNSAT engine.
- [ ] Implement a fail-closed qg assertion ledger that consumes every source
  predicate or abstains, then add exact local `R_y^3`, diagonal, and cycle
  filters before another RTXC census.
- [ ] Complete exact-lineage one-pass parser in `tree|shadow|stream` mode,
  then require full-corpus semantic shadow parity before parser-phase timing.
- [ ] Prototype a flat literal slab against the original accepted clause store,
  using SmallVec's positive cache/RSS evidence but not its rejected binary.
  Follow with dense membership, reusable symmetry checking, triangle-native
  transitivity, existing-application congruence joins, and bulk model readback
  as separately gated candidates.
- [ ] Review and WMI-gate auto leaf route `1cd9ec4`, first reproducing the
  frozen 32-case structural result and then requiring full-corpus
  non-regression before any default change.

## Current Limitation

The historically measured `58efe9d` binary has a confirmed general soundness
defect for unasserted Boolean values used as uninterpreted-function arguments.
The local candidate repairs that defect, quoted-reserved symbol dispatch, and
query ordering; 220 all-feature Rust tests and 107 Python tests pass at the last
integrated checkpoint. General soundness and superiority are still unclaimed
until exact-lineage WMI build `143794`, its differential/parser gates, and the
fixed four-solver campaigns `143752`/`143753` and `143798`/`143799` complete.

At 1,200 seconds, Yices2 is faster and complete: 7,503/7,503 correct at a
0.0278s median versus `euf-viper` at 7,478/7,503 and 0.0910s. On 7,478 common
`euf-viper`/Z3 solves, `euf-viper` has a 1.069x geometric speedup, but its hard
tail makes common-instance total time 20,668.55s versus Z3's 5,365.05s. Z3
adds 22 solves and Yices covers all 25 remaining gaps. No global superiority
claim is allowed. The opt-in Yices-dependent portfolio reaches 7,503/7,503 and
is 1.046x faster than direct Yices by paired aggregate time, but its geometric
speed is 0.8788x and the router was trained on this corpus. It is not an
independent solver victory. The accepted 2026-07-09 standalone iteration
improves the previous binary from 6,993 to 7,002 solves at two seconds while
also passing all three speed metrics. Its 60-second and 1,200-second coverage
remain unmeasured, so the older competition-budget boundary still governs.
The promoted direct-root/scoped-let binary has passed paired full-corpus gates
and fresh four-solver campaign `143049`. At two seconds it solves 6,948 versus
Z3's 7,176, cvc5's 6,926, and Yices2's 7,434. On 6,907 common euf-viper/Z3
solves it is `1.119x` faster by aggregate and `2.083x` geometrically, but Z3's
228 net coverage advantage still wins timeout-charged total time. Yices2 is
about `3.46x` faster on common aggregate time and adds 486 net solves.
The exact 60-second rerun solves 7,478 versus Z3's 7,490 and Yices2's 7,500.
The exact 1,200-second continuation then reaches 7,502 versus Z3's 7,500 and
Yices2's 7,503. Euf-viper narrowly beats Z3's full timeout-charged total,
8,575.78s versus 8,676.80s, but loses common-solve aggregate time at 0.6939x.
Yices2 remains complete and about 4.27x faster by full total. These old numbers
are opportunity evidence only. The current program must first reproduce sound
coverage and then remove a broad head-cost factor; a narrow tail conversion or
an opt-in comparator portfolio cannot satisfy the victory contract.
