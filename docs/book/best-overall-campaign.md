# Best-Overall Campaign

## Scope

The campaign targets standalone, single-core, cold-process `QF_UF` solving.
The operational objective is not merely a lower median. A frozen release must
match or exceed every comparator's coverage and improve resource-normalized
time at 2, 60, and 1,200 seconds on official, full-library, and held-out data.

The machine-readable preregistration is
[`campaigns/best-overall-qf-uf-2026-07.json`](https://github.com/nasqret/euf-viper/blob/main/campaigns/best-overall-qf-uf-2026-07.json).

## Starting Point

Current sound campaign `144328`/`144329`/`144330` contains all 30,012 expected
rows and no wrong answers or execution errors.

| Solver | Correct / 7,503 | Median | Timeout total |
| --- | ---: | ---: | ---: |
| euf-viper | 7,408 | 0.00939s | 885.69s |
| Z3 4.16.0 | 7,450 | 0.02199s | 639.66s |
| cvc5 1.3.4 snapshot | 7,373 | 0.03061s | 976.53s |
| Yices2 2.7.0 | 7,490 | 0.00504s | 228.56s |

The solver has a useful fast head and beats cvc5 overall. It is not better than
Z3 overall and is far behind Yices2. QG and Goel account for 77 of the 82
Yices2 coverage gaps and most of the timeout-total deficit, so narrow tail
patches cannot satisfy the objective.

## Official Scoreboard

The complete 7,503-file library remains the regression corpus. The primary
competition corpus is the exact 3,521-case QF_UF subset selected for the
[SMT-COMP 2025 QF_Equality division](https://smt-comp.github.io/2025/results/qf_equality-single-query/).
Yices2 solved the entire division and won all declared performance categories;
OpenSMT ranked second. The new comparator set is therefore Z3, cvc5, Yices2,
and OpenSMT.

The 2025 library is development data, not an unseen test. Family-held-out folds
must keep generator siblings together, and a general claim requires a sealed
new family or later benchmark release.

## Objective Functions

Correctness and coverage are lexicographically prior to speed. For timeout
budget $T$ and penalty $\lambda$, define

$$
P_{T,\lambda}(s)=\sum_i
\begin{cases}
t_{s,i}, & \text{if solver }s\text{ is correct on }i,\\
\lambda T, & \text{otherwise.}
\end{cases}
$$

Both $\lambda=1$ historical timeout total and $\lambda=2$ PAR-2 are reported.
For the common-correct set $C$, paired geometric speed is

$$
G(b,c)=\exp\left(\frac{1}{|C|}\sum_{i\in C}
\log\frac{t_{b,i}}{t_{c,i}}\right).
$$

A default promotion requires no coverage loss and lower confidence bounds above
one for timeout total, common total, and $G$. Final superiority uses 99% family-
cluster intervals, exact McNemar coverage tests, and Holm correction.

## Architectural Thesis

The main hypothesis is per-component proof-system migration. Every stable EUF
component starts in the cheapest representation:

1. sparse eager clauses for low-fill components;
2. rollback congruence closure for equality-graph pressure;
3. quotient/class coding for dense application records;
4. native Hall/PB reasoning for proved finite ranges.

Migration is triggered by preregistered online pressure signals: fill, conflict
and LBD growth, recurring invalid models, cut yield, duplicate reasons, and
Hall deficits. Learned information crosses representations only as independently
replayable bridge lemmas. The contribution is not any occupied representation
alone, but their component-local, proof-carrying interchange inside one search.

## Ranked Tracks

| Track | Mechanism | Cheapest falsifier |
| --- | --- | --- |
| F0 | Corpus, comparator, proof, model, runner, and statistics foundation | Complete campaign-spec validation and current baseline |
| T0 | Kissat 4.0.4 and modern inprocessing control | Identical-CNF backend/option ablation against SC2021 |
| T1 | One-pass typed IR and fused formula bytecode | Full parser shadow plus reusable-work profile |
| T2 | Lazy-first CaDiCaL and rollback partial-trail EUF | Forced Goel/graph causal gate without generic axioms |
| T3 | Proof-complexity-triggered component migration | Held-out telemetry accuracy >= 0.80, overhead < 1% |
| T4 | Adequate ranges, matching, Hall, and PB | EUF-PHP scaling and >= 30% value-cell reduction |
| T5 | Component quotient RAM/class codes | Corpus projection with >= 25% clause/watch reduction |
| T6 | Theory-conditioned Boolean DAG and semantic factoring | >= 25% projected CNF reduction on 8/10 hard table cases |
| T7 | SAT-impact explanations and EUF vivification | Boolean/EUF/combined factorial |
| T8 | Canonical frontier and bit-sliced finite quotient search | Scalar state-reuse/frontier census, then >= 70% useful lanes |

The rollback and Hall ingredients are known. IPASIR-UP provides the required
partial-trail interface, and recent cardinality work supplies stronger controls.
[Clausal Congruence Closure](https://doi.org/10.4230/LIPIcs.SAT.2024.6)
motivates the dual Boolean/EUF compiler, while its generic mechanism remains an
ablation rather than a novelty claim.

The conflict-only callback prerequisite is complete on public branch
`research-cadical-external-propagator` at `81e0c36`. It vendors the pinned
RustSAT 0.7.5/CaDiCaL 2.2.1 source, exposes a restricted connected session that
cannot replace or reconnect the borrowed solver, disables external decisions
and propagation, validates falsified conflict clauses over observed variables,
and fails closed on callback, unwind, registration, and teardown errors. Hosted
run `29217315701` passes. This is boundary evidence only: rollback congruence
closure, typed explanations, production integration, and timing remain open.

## Execution Ladder

### P0: Freeze evidence

Pin five solvers, ingest official/full manifests, create family/duplicate
groups, reconstruct base CNF independently, add external SAT-model checking,
and run current sound main at 2 seconds. Resume only timeouts at 60 seconds and
then at 1,200 seconds. No optimization starts from historical unsound long rows.

### P1: Falsify cheaply

First ablate Kissat 4.0.4 against the current SAT Competition 2021 backend.
Then run semantic references and opportunity censuses for T1, T2, T4, T5, and T6.
A track missing its registered opportunity stops before expensive timing.

### P2: Isolate mechanisms

One branch, one same-binary causal switch, target ABBA, anti-target controls,
sample-40, and hot-400. Passing branches remain separate. A decision packet is
published after each result and execution stops for review.

### P3: Build the heterogeneous solver

Compare fixed eager, fixed rollback, fixed finite representations, and the
migrating engine. Migration must beat the best fixed control on held-out
families; beating only the current default is insufficient.

### P4: Promote

Run two complete paired campaigns on two CPU classes. Check every SAT model and
UNSAT certificate, preserve raw rows, and reject any coverage, family, p95,
startup, RSS, or hash-integrity regression.

### P5: Evaluate superiority

Freeze before opening the sealed set. Run both engineering and exact official
resource lanes at all three budgets against all four comparators. A win at one
timeout or on one familiar family is not best overall.

## Proof Boundary

The phase-zero checker no longer trusts the Rust base Tseitin prefix. A
standalone typed Python parser reconstructs the source terms, theory atoms, and
canonical base CNF. The Rust solver emits only that base plus source-replayable
EUF cuts, a complete SAT assignment for SAT, or DRAT for UNSAT. The checker
then validates:

1. source symbols, sorts, and theory atoms;
2. base Boolean/Tseitin clauses;
3. finite and symmetry clauses;
4. EUF and migration bridge lemmas;
5. the final SAT refutation.

The local smoke covers five UNSAT fixtures and a 1,002-variable SAT fixture.
Every UNSAT proof passes DRAT-trim. Corpus-wide certificate shadowing remains a
P0 exit condition; local smoke is implementation evidence, not a complete
campaign validation.

## Phase-Zero Implementation

The campaign foundation now includes:

1. the exact 3,521-row SMT-COMP 2025 QF_UF selection and source hashes;
2. a release lock for euf-viper, Z3, Z3 `sat.euf=true`, cvc5, Yices2,
   OpenSMT, and the Kissat controls;
3. deterministic family/lineage taxonomy, normalized token fingerprints,
   duplicate closure, and sealed family folds;
4. self-hashed parent, shard, and runtime CPU-binding locks;
5. cold-process CPU, wall-time, RSS, timeout, output, and immutable resume
   records;
6. exact global shard reconstruction before family-cluster bootstrap, McNemar,
   Holm, PAR-2, and promotion adjudication.

The WMI P0 lane freezes the two-second corpus first. It does not authorize a
performance claim or novelty promotion. Sixty- and 1,200-second timeout-only
continuations start only from checked two-second rows.

## Closed Work

Automatic leaf quotient, bounded leaf Ackermann, fixed model scouts, the current
QG orbit/RTXC abstraction, deep-let permutation promotion, global PGO,
SmallVec clauses, direct Kissat loading, and ISA-only tuning have already failed
their declared gates. They remain controls and do not re-enter without a new
causal mechanism.
