# EUF World-Leader Campaign

Date: 2026-07-26

Status: active, measurement first

Contract: `campaigns/euf-world-leader-2026-07.json`

## Objective And Boundary

The objective is to make euf-viper the independently validated best QF_UF
solver, first in the cold single-query single-core setting and then in separate
incremental, warm-throughput, model, proof, and unsat-core settings. The primary
claim never mixes those settings. Quantified UF, UF combined with arithmetic or
bit-vectors, and multicore portfolios are separate future scoreboards.

"Best" means all of the following, not one favorable aggregate:

1. no wrong or unchecked decisive answer;
2. coverage at least equal to every pinned comparator at every primary budget;
3. better PAR-2, common-total, and common-geometric wall time;
4. competitive memory and instruction counts;
5. reproducibility on two CPU classes and sealed data;
6. independently checked models and proofs; and
7. a closest-prior-art and ingredient-ablation case for the differentiated
   mechanisms.

The mandatory comparators are Yices2 2.7.0, Z3 4.16.0 default, Z3
`sat.euf=true`, cvc5 1.3.4, and OpenSMT 2.9.2. Before a final world-leader
claim, the comparator census must check current SMT-COMP entries and available
veriT, SMTInterpol, MathSAT5, and Alt-Ergo releases.

## Starting Position

The authoritative broad campaign still measures revision `30828a4`, not the
current structural revision `8368d21`.

| Corpus/budget | Viper | Yices2 | Z3 default | Current interpretation |
| --- | ---: | ---: | ---: | --- |
| Full 2 s | 7,269 | 7,445 | 7,412 | large fast-tail deficit |
| Full 60 s | 7,480 | 7,500 | 7,489 | 20 behind Yices, 9 behind Z3 |
| Full 1,200 s | 7,502 | 7,503 | 7,500 | nearly complete |
| Official 2 s | 3,400 | 3,490 | 3,474 | 90 behind Yices |
| Official 60 s | 3,508 | 3,518 | 3,514 | 10 behind Yices |
| Official 1,200 s | 3,520 | 3,521 | 3,520 | one behind Yices |

At 60 seconds Viper is about `1.57x` faster than Z3 geometrically on common
full-corpus solves, but only `0.491x` as fast as Yices2 geometrically. Matching
Yices2 requires about `2.04x` common-geometric and `4.89x` common-aggregate
improvement on that old revision. This is an architectural target, not a PGO
target.

Revision `8368d21` materially changes the finite-family position at two
seconds: Viper solves 148 of 151 PEQ/SEQ/NEQ rows versus 140 for Yices2, 126 for
Z3, and 113 for cvc5. It has a `1.816x` PAR-2 factor over Yices2 on that local
discovery panel, but only `0.751x` common-geometric speed. Goel `frogs.2`
remains at `0.286x` of Yices2. These panels show where the structural route
works and where the next architecture must differ; they cannot be added to the
older broad totals.

## Measurement-Closure Audit

The first dashboard snapshot is complete at
`docs/dashboard/euf-progress.html`. Its 186 evidence records render as 174
claim-isolated panels, including separate SAT and UNSAT strata, and keep the
verified `30828a4` broad evidence separate from provisional `9a076353`
one-repeat structural evidence. Its canonical input is the compressed strict
registry `docs/dashboard/evidence/registry.json.gz`; each broad observation was
reconstructed from source-record hashes after checking the parent lock, raw
shard hash, record hash, source lock, origin budget, result classification,
and staged carry-forward.

On the combined 151-instance structural discovery set, pairwise results are:

| Comparator | Viper solves | Comparator solves | PAR-2 factor | Common geometric | Viper reduction still needed |
| --- | ---: | ---: | ---: | ---: | ---: |
| Yices2 | 148 | 140 | `1.816x` | `0.751x` | 24.9% |
| Z3 | 148 | 126 | `3.563x` | `1.678x` | 0% |
| cvc5 | 148 | 113 | `5.787x` | `5.049x` | 0% |

This is a tier win and a concrete Yices latency target, not a broad victory.
The current quotient portfolio still lacks a clean, repeated full/official
campaign.

The launch audit also found that the initial Helios adapter omitted taxonomy,
which makes frozen locks ineligible for promotion, and changed the Viper
configuration after freezing. Both are hard blockers: the exact
`quotient-portfolio` argv and configuration must be recorded before lock
creation, taxonomy must be hash-bound, and orchestration provenance must be
separate from the exact `8368d21` solver artifact. WMI PGO job `170902` is a
`cadical-up` experiment and cannot adjudicate the quotient portfolio.

V0 certification remains open. The finite SAT path currently revalidates
against the same compiled source representation, finite UNSAT reports an
exhaustive-cover flag rather than an independently replayed proof, and dormant
Fabric proof modules are not yet routed. No world-leader claim is available
until independent model/proof mutation tests close that gap.

The next mechanism order after the current broad baseline is: current-route
phase profiling/PGO, source-stable quotient learning, source-complete residual
memoization, exact EUF recurrence/factoring, conditional proof-internal
equality resolution, native discrete CDCL, and only then repeated semantic
symmetry. Rejected whole-instance rollback, component migration, Hall/PB,
syntactic guarded interning, the old parser branch, class coding, MVDD, and
orbit abstraction remain closed unless new opportunity evidence satisfies
their recorded reopen gates.

## Scoreboard

Every row has an evidence identity:

`(evidence, revision, host class, corpus, family, status, budget, repetition policy)`.

Rows with different identities are never aggregated into one superiority
number. The dashboard reports:

| Dimension | Primary measurement | Leader-relative display |
| --- | --- | --- |
| Validity | wrong/error/missing/unchecked counts | hard pass/fail |
| Coverage | solved and candidate-only/competitor-only | solve gap and `100 * candidate / leader` |
| Tail | timeout-charged wall and PAR-2 | comparator/candidate factor |
| Common speed | geometric and total common-solve time | comparator/candidate factor |
| Distribution | p50/p90/p95/p99 and cactus area | comparator/candidate factor |
| Resources | RSS, allocations, instructions, branches, LLC misses | best/candidate index |
| Proof/model | proof size, check time, validation time | completeness plus ratio |
| Robustness | repeat CV, cluster bootstrap, CPU and holdout replication | interval and pass/fail |
| Feature surface | parser, model, proof, incremental, cores, warm mode | checked coverage fraction |

For lower-is-better metrics, a Viper factor of `1.20x` means the comparator
takes 20% more resource. A factor of `0.50x` means Viper currently has half the
comparator's throughput; the dashboard separately reports the 100% candidate
improvement required to tie. A composite score is secondary and cannot hide a
failed validity, coverage, proof, host, or holdout gate.

## Agile Experiment Funnel

Every mechanism moves through the same funnel. Failed mechanisms remain as
reproducible negative results and stop consuming compute.

| Gate | Population | Maximum initial cost | Required result |
| --- | --- | ---: | --- |
| A0 | observe-only opportunity census | 15 min | preregistered opportunity exists |
| A1 | unit, exhaustive, generated differential | 30 min | zero semantic disagreement |
| A2 | paired micro ABBA | 30 min | inclusive target gain and anti-target safety |
| A3 | lineage-balanced family panel | 2 h | coverage dominance and cluster interval |
| A4 | hot-400 then full 2 s | 6 h | all comparators and dashboard improvement |
| A5 | prior-timeout-only 60/1,200 s continuation | remote | immutable complete audit |
| A6 | second CPU class and sealed holdout | remote | same direction without retuning |

Each isolated mechanism uses one branch and a same-binary off/on switch.
Composition is allowed only after both ingredients independently pass A4. One
broad step is one accepted or rejected mechanism, followed by a dashboard
snapshot and a user decision packet.

## Execution Order

### Step 0: Measurement Closure

1. Build the evidence registry and generated HTML/JSON dashboard.
2. Import the frozen broad `30828a4` analyses without rewriting them.
3. Import the `8368d21` structural scouts as local discovery evidence.
4. Complete WMI PGO/Goel job `170902` and adjudicate it exactly once.
5. Replicate the current fast cycle on Helios without PGO.
6. Run current `8368d21` full and official two-second campaigns on Helios.
7. Continue only current-branch timeouts to 60 and 1,200 seconds.

This is the first broad step. Its score delta determines the actual remaining
deficit after the structural campaign.

### Step 1: Fast Head And Front End

Measure parse, typed IR, Boolean DAG, finite analysis, CNF, SAT, model
validation, and certificate phases separately. Collect allocations,
instructions, branch misses, and LLC misses on a lineage-balanced hot-400.

Experiments, in order:

1. family-disjoint LLVM PGO;
2. one-pass typed arena with byte-for-byte parser shadow;
3. compact IDs and structure-of-arrays for terms, applications, and literals;
4. fused static traversals only where profiling finds repeated complete scans;
5. deterministic ticks-based scheduling for expensive passes.

The lane stops when the next change fails `1.05x` common geometric gain or
exceeds 1% anti-target p95 overhead. Low-level changes are engineering, not
novelty claims.

### Step 2: General Boolean EUF And Goel

This lane owns the largest known deficit. Complete the native propagation and
learning path before adding another representation:

1. replace source-atom synchronization scans with the checked reverse index;
2. attach theory reasons only to stable source terms and atoms;
3. perform first-UIP analysis over native and Boolean reasons;
4. backjump nonchronologically with replayable source-level nogoods;
5. compare shortest, SAT-impact-aware, and certificate-aware explanations;
6. retain a lazy-first model-conflict arm as the closest DPLL(T) control.

The first target is the frozen 22-source deficit panel: nine Goel, one PEQ,
and twelve qg7. A mechanism must convert one Yices-only solve and beat Yices2
on inclusive target time before broad routing. The prior whole-instance
rollback result remains rejected because of 11x to 33x anti-target p95 cost.

### Step 3: Canonical Quotient Frontier

The E3 hypothesis is that different Boolean histories frequently reach the
same source-complete typed quotient residual. The first implementation is
observe-only and scalar. A key includes the partition, disequalities, observed
function rows, residual Boolean obligations, assertion lineage, forgotten-state
summary, and structural position. Hashes index entries but a full key decides
equality.

Behavior is authorized only if exact useful repetition is at least 20%,
relevant rows account for at least 5% of corpus time, and key construction is
below 10% of avoided work. Bit slicing, SIMD, forgetting, and approximate keys
remain blocked until the scalar census passes.

### Step 4: Proof-System Compilation

Run three controls before claiming a new proof system:

1. generic learned-clause factoring/extended resolution;
2. clausal congruence closure and ordinary BVA/inprocessing;
3. EUF-specific bounded equality resolution over proof-internal equalities.

The EUF compiler carries exact side clauses through reflexivity, transitivity,
congruence, and conflict, exports only baseline variables, and is replayed by
an independent checker. The target-first gate requires a nontrivial proof DAG
or checked empty clause under fixed work and memory caps, followed by an
inclusive `1.05x` win over Yices2 and the generic controls.

### Step 5: Native Finite And Discrete Search

The existing verified finite route is frozen while Step 0 measures its broad
effect. The next research control compares its one-hot encoding with native
discrete CDCL decisions and explanations inspired by Dsat. Hall/PB explanations
and component-local restricted-growth class coding are tested only on source-
proved finite closures.

Promotion requires coverage dominance and `1.05x` common-geometric speed over
Yices2 on PEQ, SEQ, NEQ, finite generated scaling, and unseen sizes. A faster
known-family route that fails unseen sizes is rejected as overfit.

### Step 6: Repeated Semantic Symmetry

Use SORB as the generic control. Viper's candidate delta is to rerun typed
automorphism discovery after EUF rewriting exposes equality classes and
application rows absent from the original CNF. Only unit and binary cuts are
admitted initially, each with an orbit or substitution-redundancy witness.

No behavioral implementation occurs until an offline shadow finds a valid
second-round cut absent from both the current one-shot route and SORB. The
timing gate is `1.10x` target PAR-2 and at most 1% anti-target p95 overhead.

### Step 7: SAT Backend And Inprocessing

Compare identical CNF through the existing CaDiCaL path, a current CaDiCaL
configuration, and a current Kissat control where interface requirements
permit. Run a factorial over vivification, BVA/factoring, clausal congruence,
phase, restart, and proof logging. Only end-to-end wins count. The structural
solver must remain backend-independent enough that a SAT update does not erase
the differentiated architecture.

### Step 8: Certification

Complete the checker-owned source parse, atom map, base Tseitin CNF, finite
clauses, EUF proof events, model validation, and SAT proof chain. Track proof
bytes, generation overhead, replay time, and trimming. A decisive row without
independent validation is not coverage.

### Step 9: Workflow Surface

After the cold single-query core is competitive, create separate scoreboards
for warm throughput, push/pop incremental solving, assumptions, models, and
unsat cores. Shared arenas and assertion scopes may improve practical verifier
workloads, but these results never enter the primary cold score.

### Step 10: Heterogeneous Migration

Component migration remains blocked. Its existing fixed-arm oracle headroom is
3.74%, below the preregistered 10% lower-bound requirement. Recompute headroom
only after two new fixed engines independently pass A4. Do not train a router
until then.

## Compute Strategy

The Mac runs unit tests, bounded differential tests, micro ABBA, and dashboard
generation. WMI retains the exact pending PGO holdout and immutable historical
campaigns. Helios provides the second CPU class and additional sharded capacity
under `plgccaiautore2026-cpu` at
`$SCRATCH/codex-control/projects/euf-viper`.

Each solver process receives one bound CPU. Comparator processes do not contend
with one another. Runs record CPU model, affinity, wall and CPU time, maximum
RSS, executable and input hashes, environment, and scheduler identity. GPU
resources are not used for solver timing; an offline GPU analysis must be a
separately preregistered experiment with its cost and role stated explicitly.

## Broad-Step Decision Packet

After every A4 or later step, publish exactly:

1. revision and evidence hashes;
2. validity and certificate accounting;
3. coverage delta by corpus, budget, family, and SAT/UNSAT;
4. PAR-2, common-total, common-geometric, p50, p95, and p99 delta;
5. RSS and hardware-counter delta where available;
6. confidence interval and repeated-host direction;
7. accepted, rejected, or unresolved decision;
8. updated distance to each comparator; and
9. the next cheapest falsifier.

No result is described as world-leading until V0 through V6 in the contract
all pass.
