# Best-Overall QF_UF Campaign

Date: 2026-07-12

Status: ready for phase-zero validation; no heavy job submitted

Machine-readable contract:
`campaigns/best-overall-qf-uf-2026-07.json`

## Executive Decision

The project should stop treating the next result as a sequence of global eager
encoding tweaks. Current main already demonstrates the value and the ceiling of
that approach:

- it has low startup cost and beats cvc5 overall at two seconds;
- it is `1.5666x` faster geometrically than Z3 on common solves;
- it loses 42 solves and common aggregate time to Z3;
- it loses 82 solves and roughly `4.2x` timeout-charged total time to Yices2;
- its remaining cost is broad across QG and Goel, not concentrated in one bug.

The primary architectural hypothesis is therefore a **heterogeneous
single-search QF_UF solver**. Each connected interference component starts in
the cheapest representation and may migrate, with checked bridge lemmas, from:

1. sparse eager clauses;
2. rollback congruence closure on the partial SAT trail; to
3. native cardinality/PB reasoning for proved finite components.

This keeps the accepted eager head while creating a proof-system escape route.
Rollback EUF, Hall reasoning, and eager encoding are individually known. The
research claim, if the evidence survives, is the component-local migration
policy, stable semantic identity, and proof-carrying interchange among them.

## Benchmark Correction

The 7,503-file SMT-LIB library sweep remains the development regression corpus,
but it is not the only primary scoreboard. The official
[SMT-COMP 2025 QF_Equality result](https://smt-comp.github.io/2025/results/qf_equality-single-query/)
uses 3,821 selected instances, including 3,521 QF_UF instances. Yices2 solved
the entire division and won sequential, SAT, UNSAT, and 24-second performance.
OpenSMT solved 3,820 and ranked ahead of cvc5. A best-overall campaign must:

- ingest the exact 3,521-case QF_UF selection;
- add [OpenSMT 2.9.2](https://github.com/usi-verification-and-security/opensmt/releases/tag/v2.9.2)
  as a mandatory comparator;
- retain Z3 4.16.0 as the famous stable reference even where it did not enter;
- pin every source revision and binary hash rather than trust a version string;
- report both official-selection and complete-library results.

The 2025 library has already been inspected repeatedly and cannot become a
genuine unseen set retroactively. Grouped development folds must keep generator
siblings together: QG generator/size variants, all sizes of one NEQ/PEQ/SEQ
problem, and all properties/sizes of one Goel model. Alpha-renamed and
normalized-AST near-duplicates must share a fold. A general claim requires a
sealed external family or a later benchmark release.

## Current Empirical Boundary

Fresh sound campaign `144328`/`144329`/`144330` at two seconds gives:

| Family | N | euf-viper | Z3 | cvc5 | Yices2 | Primary implication |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| QG classification | 6,396 | 6,341 | 6,372 | 6,329 | 6,396 | Broad head and UNSAT proof-system work |
| Goel hardware | 773 | 751 | 771 | 758 | 773 | Online EUF and SAT-search work |
| NEQ | 48 | 43 | 40 | 31 | 43 | Preserve current coverage; reduce cost |
| PEQ | 47 | 36 | 33 | 26 | 39 | Native finite cardinality/Hall target |
| SEQ | 56 | 54 | 51 | 46 | 56 | Finite representation target |

QG timeout-charged time is about 727 seconds for euf-viper versus 170 seconds
for Yices2. Goel time is about 84 seconds versus 9 seconds. This rules out a
strategy based only on converting the seven all-solver gaps or the handful of
spectacular PEQ cases. The new architecture must reduce common-case work across
thousands of QG formulas and still improve the Goel and finite tails.

## Reconciled Old Plan

| Old unresolved item | Disposition | New owner |
| --- | --- | --- |
| Independent base Tseitin reconstruction | Still mandatory | F0 proof foundation |
| Typed-sort performance gate | Standalone optimization was repeatedly rejected; exact sort metadata already exists | T1 uses metadata without reopening the failed claim |
| Deep-let focused permutations | Implemented and rejected by the registered median/refinement gates | Closed, default-off research only |
| Remaining finite tail | Too vague | Split into T4 Hall/PB, T5 class coding, and conditional T8 quotient search |
| Publish only checked benchmark tables | Still mandatory for certifying/superiority claims | F0 |
| Component-local class labels | Plumbing and solver prototype remain open | T5 projection and prototype |
| Jobs `143752`/`143753`, `143798`/`143799` | Superseded and cancelled | Current campaign `144328` is authoritative |
| Exact-lineage `ebf8e27` prerequisites | Corrected gates passed; full chain superseded | Closed |
| Production orbit-cover recognizer | Current abstraction has zero refutations | Rejected; reopen only under T8 source-complete census |
| QG source assertion ledger | Completed by `144349` | Closed; route remains test-only |
| One-pass parser | Tested checkpoint `58f015b`, no full shadow or performance gate | Conditional T1 restart |
| Flat literal slab | Promoted as `3c178dc` | Closed and retained |
| Automatic leaf quotient | Full gate rejected; successor neutral | Closed pending materially new evidence |

## Goal Hierarchy

### V0: Valid and certifying

No wrong answer, incomplete merge, unvalidated SAT model, or unchecked theory
lemma is permitted. Independent reconstruction must cover the source atom map,
base Tseitin clauses, finite clauses, EUF lemmas, and final SAT proof. Existing
performance tables remain empirical evidence until that chain is complete.

### V1: Best official sequential QF_UF result

On the exact SMT-COMP 2025 QF_UF selection, match the leading solve count and
beat the leading resource-normalized time under the official single-query
resource model. Since Yices2 is complete, coverage can only tie; time must win.

### V2: Best complete-library result

On all 7,503 files, equal or exceed every comparator's coverage at 2, 60, and
1,200 seconds and improve timeout-charged aggregate plus common geometric time.
No single favorable timeout is selected after seeing results.

### V3: Generalize

Repeat the direction on a source-family holdout, unseen generated sizes, a
newer SMT-LIB release when available, and two WMI CPU classes. Random file
splits are forbidden because neighboring generated sizes leak structure.

### V4: Produce a defensible research contribution

For every novelty claim, identify the closest public mechanism, state one
falsifiable delta, run ingredient ablations, and withdraw the claim if a known
ingredient explains the gain. Performance engineering remains valuable but is
reported as engineering rather than algorithmic novelty.

## Ranked Technical Tracks

## F0. Measurement And Proof Foundation

This is prerequisite work, not a performance hypothesis.

Deliverables:

1. exact SMT-COMP 2025 QF_UF selection and immutable hashes;
2. OpenSMT 2.9.2 integration and five-solver schema;
3. fresh current-main 2/60/1,200-second baseline using timeout-only resume;
4. a new current-main family/status/opportunity atlas;
5. independent SMT-LIB-to-base-CNF reconstruction;
6. one declarative environment manifest used to generate all child processes;
7. proof/model validation and complete-result checks as hard job dependencies.
8. a family taxonomy and near-duplicate clustering tool;
9. a cgroup/BenchExec-style normalized runner with CPU binding, RSS/CPU
   counters, process-group termination, and hash-compatible resume;
10. a hierarchical analyzer for family-cluster intervals and multiplicity.

The environment manifest directly addresses the invalid `144371` failure, in
which the old wrapper silently omitted child mode variables.

Stop rule: none. Claims remain blocked until F0 is complete.

## T0. Modern SAT Backend And Inprocessing Baseline

The production Linux dependency is a vendored wrapper around Kissat's SAT
Competition 2021 code, not a current backend. Before attributing broad gains to
new SMT machinery, embed
[Kissat 4.0.4](https://github.com/arminbiere/kissat/releases/tag/rel-4.0.4)
behind the same clause/model interface and compare identical CNF. Use controlled
ablations for clausal congruence, equivalence sweeping, factor/BVA,
vivification, and phase search. The
[SAT Competition 2025 solver report](https://cca.informatik.uni-freiburg.de/papers/BiereFallerFleuryFroleyksPollitt-SAT-Competition-2025-solvers.pdf)
documents these mechanisms and their proof-production tradeoffs.

This is a high-return engineering control, not novelty. Preserve the SC2021
backend as an exact arm, validate every SAT model, and require proof compatibility
for UNSAT. Kill any isolated option that changes size but not repeated
end-to-end time; promote only a complete backend configuration that passes the
normal full gate.

## T1. One-Pass Typed Structural IR And Staged Formula Machine

Resume `58f015b` as a research branch, not as a merge candidate. Parse bytes
once into a compact typed term/Boolean arena, preserve source names for models,
and compute bounded routing features during construction. Exact sort metadata
already exists in current main; the task is to retain it without a second
valid-path traversal or duplicate syntax representation.

First gates:

- exact opened-byte tree/shadow parity on all 7,503 files;
- generated typed, quoted-symbol, Boolean-as-data, and nested-`let` differential;
- ABBA parse-only and end-to-end timing against current main;
- miss overhead below 1% at p95 and no off-mode semantic or allocation change.

Kill if the full shadow differs, p95 misses exceed 1%, or parse savings do not
improve end-to-end time. A parser-only win is not a solver promotion.

If the parser gate passes, profile whether at least 70% of routed QG CPU time
is spent in reusable static traversals: Boolean evaluation, SAT-model
projection, application-signature scans, violated-lemma discovery, and model
validation. Only then compile an immutable bytecode schedule that fuses those
passes, with scalar lockstep as oracle. Schedule construction must stay below
5% of routed solve time. Native/JIT stencils remain blocked until bytecode
beats the generic traversal and code generation can preserve exact provenance.

## T2. Lazy-First Reference And Rollback EUF

Implement the previously blocked base-CNF lazy-first experiment now that the
Boolean-data repair exists. The first version is deliberately simple:

1. load Boolean/Tseitin plus already proved finite clauses into CaDiCaL;
2. omit generic transitivity/congruence clauses on the first call;
3. validate every complete model;
4. add only checked EUF conflict clauses;
5. abstain to current behavior on caps, duplicate cuts, or interruption.

This retests lazy solving with a modern SAT backend, but it is a control rather
than a novelty claim. If it wins causally, add conflict-only rollback closure
through the [IPASIR-UP interface](https://cs.stanford.edu/~preiner/publications/2023/FazekasNPKSB-SAT23.pdf),
then propagation with delayed reasons.

Kill if it produces more invalid complete models without lower wall time,
regresses the easy head, or emits one unreplayable explanation.

## T3. Proof-Complexity-Triggered Component Migration

This is the primary candidate architecture. Build stable semantic IDs for
terms, equality atoms, and components. Start each component eager. Collect only
online, outcome-independent pressure signals:

- expected and realized Ackermann/transitivity fill;
- conflict rate and LBD/width growth involving component atoms;
- repeated invalid-model signatures;
- theory-cut yield and duplicate rate;
- finite-domain/Hall deficit evidence.

M0 is telemetry only. A frozen classifier must separate known eager wins from
tails with balanced accuracy at least 0.80 on held-out families and less than
1% overhead. M1 performs one-way eager-to-rollback migration. M2 adds
finite-to-PB migration. Learned information crosses only as replayable bridge
lemmas; no internal pointer or unproved partition state is shared.

Promotion requires beating every fixed internal representation, not merely the
current default. Kill if held-out routing fails, migration cost exceeds avoided
work, or bridge replay fails.

## T4. Adequate-Range Hall And Native Cardinality/PB

Recover only finite components whose ranges are proved from source constraints.
Use non-uniform per-term domains, reversible matching, Hall conflicts, and PB
explanations. Compare against pairwise, totalizer, native cardinality, and the
2026 [near-optimal cardinality encodings](https://arxiv.org/abs/2603.28954).
The 2026 BVA lower bound shows why blind factorization cannot be expected to
discover the best AMO representation automatically
([Automated Reencoding Meets Graph Theory](https://arxiv.org/abs/2603.27774)).

First gate: generated injective-function/table-row scaling through at least
`n=32`, followed by frozen PEQ/SEQ/finite-Hall targets. Require at least 30%
fewer allocated value cells, proof checking within 25% of candidate solve time,
one stable timeout conversion, and no loss.

## T5. Component-Local Quotient RAM And Class Coding

Assign restricted-growth class codes to terms inside one interference
component. Represent each application as an argument-code/result-code record
and enforce functionality with a source-reconstructable sorting or comparison
network rather than equality triangles and every application-pair implication.
This is the concrete successor to the unresolved class-label projection; exact
sort metadata is already present in current main.

Before implementation, project variables, clauses, watches, decoder cost, and
sorting depth over the whole corpus. Require at least 25% fewer clauses or
watches on a frozen, nontrivial QG/Goel stratum and a complete source-model
decoder. Kill if class-code variables dominate, sort plumbing requires another
full traversal, or the projected advantage is confined to a tiny selected set.

## T6. Theory-Conditioned Boolean DAG And Semantic Factoring

Armin Biere et al.'s
[Clausal Congruence Closure](https://doi.org/10.4230/LIPIcs.SAT.2024.6)
extracts and merges equivalent Boolean gates from CNF. Our candidate boundary
is earlier and typed: share Boolean subgraphs modulo proved source-level EUF
congruence, while retaining assumptions and source-to-CNF provenance. Also test
semantic extension variables for repeated application rows or theory reasons.

Run census before solver changes. Require at least 25% projected CNF reduction
on 8/10 frozen hard table cases, exhaustive small-formula equivalence, and a
generic Kissat/CaDiCaL factoring control. Kill if generic factoring matches it
or reduced CNF does not reduce wall time.

## T7. SAT-Impact-Aware Explanations And Theory Vivification

Once T2 exists, compare shortest explanations with an objective that estimates
learned-clause width, LBD, reuse, and certificate cost. Small congruence proofs
are known; the candidate is SAT-aware selection, not proof minimization alone.
Use rollback EUF as a theory oracle during bounded vivification and cache only
replayable binary/ternary consequences.

Require a factorial no-vivification/Boolean/EUF/combined experiment. Kill if
explanation construction erases propagation savings or generic vivification
accounts for the gain.

## T8. Canonical Frontier And Bit-Sliced Finite-Table Quotient Search

The existing QG route is not promoted: job `144349` found 12 witnesses, 19
abstentions, and zero refutations among 31 eligible cases. Reopen only after T1
can represent every source assertion and T4 supplies checked finite reasoning.

A successor may combine complete multi-table canonization, stabilizer search,
canonical quotient-state/frontier transducers, and bit-sliced valid-model
exploration. Start with a scalar frontier census measuring state reuse,
separator width, and transition cost;
SIMD work is allowed only if candidate batches sustain at least 70% useful lane
occupancy and amortize model reconstruction. SAT requires an independently
validated source model; UNSAT requires an exhaustive, checked cube cover. It
must compare directly with Yices2 on the target before any broad QG work.
Complete finite-model symmetry is active
research, not an empty niche; see
[Complete Symmetry Breaking for Finite Models](https://doi.org/10.1609/aaai.v39i11.33217).

Kill if the source-complete eligible population remains narrow, the abstraction
again has no UNSAT power or useful phase guidance, or target wall time cannot
beat Yices2 including setup.

## Explicitly Closed Or Deferred Venues

- global PGO, `x86-64-v3`, direct Kissat short-clause load, SmallVec clauses;
- automatic leaf quotient and bounded leaf Ackermann;
- fixed pre-CNF scouts with 4/3,142 SAT hits;
- current qg forbidden-orbit and RTXC abstractions;
- generic BVA, generic vivification, ordinary symmetry clauses, or a blind
  multi-seed SAT race as novelty claims;
- GPU, JIT, quotient RAM, fork snapshots, or semantic cross-worker exchange
  until a scalar census proves enough regular work to amortize them;
- external Yices2 fallback as evidence of standalone superiority.

These may be controls. They do not re-enter the implementation queue without a
new causal hypothesis and preregistered falsifier.

## Experimental Ladder

### P0: Freeze Evidence

1. Validate the campaign JSON.
2. Pin and hash five solvers.
3. Ingest official and full-library manifests.
4. Run sound current main at 2 seconds.
5. Resume only its timeouts at 60 seconds, then only remaining timeouts at
   1,200 seconds.
6. Build the current opportunity atlas before selecting thresholds.

Worst-case 2-second full-library work is 37,515 solver runs, about 20.8 CPU
hours before startup overhead. The staged resume avoids rerunning solved rows:
the current four solvers have only 391 total two-second gaps before OpenSMT.

### P1: Cheap Falsification

Run a modern-backend ablation plus semantic references and opportunity censuses
for T1, T2, T4, T5, and T6. A
track that misses its registered opportunity threshold stops before WMI timing.

### P2: Isolated Mechanisms

Each branch changes one causal knob in the same binary. Run generated/small
exhaustive checks, target ABBA, anti-target controls, sample-40, and hot-400.
Do not combine passing branches yet.

### P3: Heterogeneous Solver

Implement T3 only after fixed eager and fixed rollback controls exist. Compare
the migrating engine with each fixed engine on family-held-out targets. Require
the migration interaction to add value beyond the best fixed arm.

### P4: Full Promotion

Run the complete 7,503 paired gate twice on Intel and AMD classes. A default
candidate requires:

- zero wrong answers/errors and no baseline-only solve;
- timeout-charged total, common total, and geometric lower bounds above one;
- no material family, status, median, p95, RSS, or startup regression;
- independent SAT-model and UNSAT-evidence checking;
- exact artifacts and a rejection ledger.

After every P2/P4 result, publish one decision packet and stop for user review.
No accepted optimization is silently composed with the next one.

### P5: Superiority Evaluation

Freeze the binary before opening the held-out set. Run the official QF_UF
selection and full library at 2, 60, and 1,200 seconds against Z3, cvc5,
Yices2, and OpenSMT. Repeat independently. Report official-style ranking,
PAR/timeout total, common geometric time, median, p95, RSS, CPU class, and all
discrepancies. A win at one timeout is not reported as best overall.

Use two declared resource lanes. The engineering lane is one physical core and
8 GiB for every solver. The official lane reproduces the SMT-COMP time and
memory limits exactly. Results from the two lanes are never pooled.

## Statistical And Provenance Contract

- Alternate A/B order by instance and repeat; use a balanced Latin square for
  multi-solver runs.
- Pin CPU affinity and record host, microcode, kernel, compiler, linker, SAT
  backend, environment, binary SHA, and manifest SHA.
- Use paired medians, exact McNemar coverage tests, family-cluster bootstrap
  intervals, and preregistered primary metrics. Screening gates use 95%
  intervals; superiority uses 99% intervals and Holm correction across
  comparators, budgets, and primary metrics.
- Primary fixed-corpus ranking is lexicographic: zero invalid results, solved
  count, PAR-2/timeout score, then CPU time. Also report family-macro PAR-2,
  worst-family coverage delta, SAT/UNSAT strata, median, p95, and peak RSS.
- Coverage is lexicographically prior to speed for default promotion.
- Family names, paths, hashes, and previous outcomes are forbidden router
  features. Structural features are frozen before held-out evaluation.
- Small selected gates establish mechanism causality only. They cannot promote
  a default or support a superiority claim.
- Raw rows and rejected arms are retained even when the result is negative.

## Immediate Queue

1. Validate and publish this campaign specification.
2. Add exact OpenSMT and SMT-COMP selection ingestion; pin cvc5's commit and
   compare Z3 default with `sat.euf=true`.
3. Embed and causally ablate Kissat 4.0.4 against the SC2021 backend.
4. Implement independent base-CNF reconstruction and declarative child-env
   manifests.
5. Produce current-main 60/1,200-second resumes and a new atlas.
6. Run T1 shadow parity and T2 lazy-first reference in parallel branches.
7. Choose among T4, T5, and T6 for the first representation prototype based on
   census opportunity, not intuition.

No other implementation or WMI campaign enters the queue before these seven
items have an explicit decision record.
