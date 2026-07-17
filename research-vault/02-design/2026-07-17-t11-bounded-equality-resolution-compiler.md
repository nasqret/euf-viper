# T11 Bounded Equality-Resolution Compiler

Date: 2026-07-17

Status: preregistered before implementation, target projection, or timing

## Decision boundary

T11 tests whether the equalities that T10 could not expose as existing SAT
atoms can remain proof-internal and be eliminated by bounded equality
resolution. It is a one-shot source compiler in front of modern SAT, not a
lazy CDCL(T) callback and not another chordal-transitivity encoding.

The implementation branch must descend from reviewed T10 core commit
`898df6d916c313baefd3baae6e820db85e678cce`; `main` does not contain the T9
or T10 solver modules. The intended branch is `perf-t11-equality-resolution`.
No T11 implementation, projection, or timing is authorized before the exact
commit containing this document is public.

T10 established the obstacle precisely. On the frozen target it enumerated
3,686 Ackermann clauses, but every clause needed a result-equality atom absent
from the 18,082-entry baseline atom table. T11 may represent such equalities as
typed proof conclusions. It may never intern them, assign them SAT variables,
or materialize a global equality graph.

## Proof system

Let (F_0) be the exact hash-bound baseline CNF interpreted with the typed EUF
atom map. Every equality proof node has a normalized typed conclusion (s=t)
and a canonical side clause (C). Its invariant is relative to that input:

\[
F_0\models_{\mathrm{EUF}} C\lor s=t.
\]

Side literals are existing baseline CNF literals. They may include auxiliary
variables and non-equality atoms, but those literals are carried opaquely. Only
baseline `BoolAtomKey::Eq` literals may be equality pivots.

The frozen rules are:

1. **Seed.** If an exact base or previously derived clause is
   (C\lor s=t), create the equality node ((C,s=t)).
2. **Reflexivity.** Create ((\bot,t=t)) for every existing well-sorted term
   during deterministic initialization.
3. **Transitivity.** From ((C,s=t)) and ((D,t=u)), derive
   ((C\lor D,s=u)).
4. **Congruence.** For same-function, same-arity, same-result-sort
   applications (f(s_1,\ldots,s_k)) and (f(t_1,\ldots,t_k)), combine one
   checked proof ((C_i,s_i=t_i)) for every differing argument and derive

   \[
   \left(\bigvee_i C_i,\ f(s_1,\ldots,s_k)=f(t_1,\ldots,t_k)\right).
   \]

5. **Conflict.** From ((C,s=t)) and an exact base or derived clause
   (D\lor s\ne t), derive the ordinary clause (C\lor D).

A conflict clause can seed another positive equality pivot. This is the
clause-level equality-resolution system, rather than the weaker operation of
assuming all positive equalities simultaneously. Symmetry is implicit in
normalized unordered term pairs. Boolean-valued application conclusions are
not equality pivots in T11 v1; `BoolTerm` and auxiliary literals remain opaque
side literals.

The empty clause is an optional stronger result. It is not required at
projection because a useful bounded prefix can still need Kissat to perform
ordinary Boolean resolution. For example, conditional paths can yield valid
short clauses without a source-only empty derivation.

## Canonical representation

- A side clause is sorted by signed `i32`, duplicate-free, and rejected if it
  contains both (l) and (-l).
- An equality conclusion is a normalized term-ID pair with equal sorts.
- Supports are hash-consed in flat `u32`/`i32` arenas.
- Each equality conclusion retains an antichain of at most eight side clauses.
  Admission compares the incoming clause against every retained support in
  `(width, literals, node ID)` order without early exit. It first discards the
  incoming clause if an existing clause is its subset, then removes every
  existing strict superset. The incoming clause is accepted if fewer than
  eight clauses remain; otherwise the incomparable ninth clause is discarded.
  Eight is a deterministic pruning threshold, not a projection-failure cap.
  The report separately counts subset discards, capacity discards, and removed
  supersets. Consequences already generated from a removed node remain valid
  and are never retracted.
- Base and derived clauses have a global exact-dedup table. Search accepts each
  unique non-tautological derived clause and performs no dynamic subsumption.
  After search terminates, final outputs are sorted by `(width, literals)` and
  a deterministic forward pass drops a clause if a base clause or an earlier
  retained output is its subset.
- No hash-map iteration order may affect search or output.

Accepting an empty Conflict clause records that clause and immediately ends
search: no child event is generated and no queued event is processed
afterward. The final lemma sequence is exactly one empty clause. It counts as
one emitted lemma and one accepted derived clause, has zero literal slots, and
has p95 and maximum width zero. All counters through acceptance of that empty
event, plus the number of still-live queued events discarded at termination,
are recorded. No later worklist event or search-resource check occurs; final
emitted-limit checks and independent replay still run.

An exhausted search with no derived output is a distinct `no_lemmas` outcome.
It has an empty lemma sequence, emitted count and slots zero, and p95 and
maximum width defined as zero. It is permitted only for the diagnostic ablation
or an unselected/off report; it cannot pass ordinary Stage 0A.

The global event key is, in order: resulting clause width, proof depth, rule
rank, normalized conclusion when present, canonical side-clause literals,
source clause ID and literal offset when present, and parent IDs. An equality
event's resulting width is its side-clause width; a Conflict event's is the
resolvent width. Optional fields use `None < Some`, and parent IDs are stored in
ascending order. Rule rank is `Seed < Reflexivity < Transitivity < Congruence
< Conflict`. Equal keys are exact duplicates and only the first insertion
remains.

Base clauses and reflexivity nodes have depth zero. A Seed has the depth stored
on its source clause. Transitivity and Congruence have one plus the maximum
parent-node depth. A Conflict clause has one plus the maximum of its equality
node depth and negative source-clause depth; that value is stored on the
derived clause and inherited by later Seeds. Every non-base parent or source
reference in an event must precede the event in the accepted trace.

Initialization scans all base clauses by `(clause ID, literal offset)`. Each
negative equality registration and each positive Seed insertion is a separate
prospective mutation in that order. It then inserts one Reflexivity event per
term as separate mutations in term-ID order. Search starts only after that
scan; the global event key, rather than insertion order, chooses the next
event. A negative registration prospectively increments (O) and logical memory
and is rejected before mutation if that cap fails.

When a new equality node is accepted, transitive joins visit current nodes that
share an endpoint in `(other conclusion, other node ID, orientation)` order.
Each join is keyed by sorted parent IDs plus the intermediate term. For a
same-function application pair, the compiler enumerates the Cartesian product
of current retained argument proofs lexicographically by the parent-node tuple;
when a new argument proof arrives, it schedules only not-yet-keyed tuples that
contain that node. A removed antichain node is not used to create future
events, but events already queued from it remain valid and are processed in
normal key order. Removed nodes and their proofs remain addressable by the
checker.

When a derived clause is accepted, its negative equality occurrences are
registered in `(clause ID, literal offset)` order and matched against current
equality nodes in node-ID order. Its positive equality occurrences then enqueue
Seed events in literal-offset order. Existing negative occurrences are always
visited by clause ID and offset for a newly accepted equality node. Application
pairs, terms, conclusions, and all index traversals are sorted by numeric IDs.

Every search iteration first removes the minimum event from the worklist and
decrements the live-entry count. It then checks and atomically accepts or
rejects that event using this post-pop live count. Admission comparisons and
all prospective accepted-object, proof-work, index, and memory deltas are first
computed without mutation; relevant caps are tested in the full table order;
then all deltas commit atomically. A duplicate or pruned event commits only the
proof-work charges explicitly assigned to making that decision.

Only after acceptance are child candidates enumerated in the rule-specific
orders above. Each child is a separate insertion transaction. Classify
ablation suppression first and, if suppressed, record it without any other
counter change. Otherwise construct its canonical key and depth, test depth and
the full proof-work delta in table order, and commit the proof-work charge. An
exact duplicate then stops with no push. For a novel key, prospectively test
push count, live count as `current_live + 1`, and logical memory in table order
before atomically inserting it. Initialization uses the same insertion
transaction starting from live count zero; it has no implicit reserved slot. A
cap failure rejects the complete projection.

One global indexed worklist is mandatory. A separate traversal for each of the
1,773 target disequality edges would inspect at least
(1773\cdot14241=25{,}249{,}293) graph edges before congruence and already
violate the work budget.

## Independent checker

The compiler and checker must be separate Rust modules. The checker may share
only immutable input types; it may not call compiler canonicalization,
subsumption, support-union, scheduling, or proof-construction helpers.

The trace is topologically ordered and records exact clause references,
literal offsets, normalized conclusions, parent IDs, application IDs, and
materialized clauses. Each Congruence record additionally stores
`(argument_index, parent_node_id)` for every differing argument in increasing
argument-index order; its event key separately uses sorted parent IDs. Every
trace reference must name a base object or a strictly earlier accepted trace
record. The checker replays every accepted equality node and every accepted
Conflict clause, including intermediate clauses later omitted by final output
subsumption. It independently:

- verifies every referenced base clause and pivot literal;
- recomputes every side-clause union and rejects a tautology;
- checks term IDs, sorts, functions, arities, and every congruence argument;
- checks transitive endpoints and deterministic reflexivity initialization;
- allows missing equalities only as internal typed conclusions;
- verifies every exported clause byte-for-byte;
- recomputes trace, lemma-sequence, term-DAG, CNF, and atom-map hashes; and
- reports exact replayed-node, replayed-clause, and failure counts.

An external Stage 0A auditor independently reconstructs event ordering,
antichain admission, all counters, cap precedence, final forward subsumption,
and the emitted sequence. The logical checker alone cannot authorize Stage 0B.

Mutation tests must independently reject changed signs, clause references,
literal offsets, term IDs, parent order, functions, sorts, support literals,
output order, and hashes. Exhaustive small typed formulas must agree with Z3,
Yices2, and cvc5, with SAT models validated by the existing checker.

## Frozen option and routing

The only option is
`EUF_VIPER_T11_EQRES=off|clique-er-auto`; absent means `off`, and every other
value fails closed. T9, T10, and T11 non-`off` modes are mutually exclusive;
multiple opt-ins are an error. `off` must preserve the baseline CNF, atom map,
route, output, and statistics.

`clique-er-auto` first calls the exact T9 selector unchanged. After that
selection, a separate T11 support guard requires no Boolean-valued application
pairs. The exact T9 selector still requires:

- no finite-domain clauses or closed-table encoding were added;
- the verified disequality-clique lower bound is at least 48;
- disequality edges exceed the clique minimum by at most eight;
- the equality graph has at least 2,500 vertices and 10,000 edges;
- there are at most 256 uninterpreted applications; and
- the routed backend is the pinned Kissat build.

The selector may inspect no path, source name, benchmark family, expected
answer, prior runtime, comparator result, or generated proof count.

The compiler and kernel use the same in-memory direct-root baseline CNF. Raw
variable IDs may not cross a rebuild. Source bytes, root-CNF mode, term DAG,
atom map, baseline CNF, trace, materialized lemmas, binary, revision, manifest,
and observation records are hash-bound.

A **missing-equality Congruence** is a Congruence node whose conclusion is
absent from the baseline atom map or which directly consumes at least one
argument proof whose conclusion is absent from that map. Merely having an
unrelated missing equality elsewhere in the dependency DAG does not qualify.
This definition is used unchanged by projection, ablation, audit, and
certificate gates.

## Hard limits

The following caps are frozen before target inspection:

| Resource | Limit |
|---|---:|
| Terms | 16,384 |
| Baseline variables | 50,000 |
| Baseline clauses | 131,072 |
| Baseline literal slots | 1,048,576 |
| Applications | 256 |
| Application pairs | 5,000 |
| Maximum arity | 64 |
| Application argument slots | 16,384 |
| Equality proof nodes | 100,000 |
| Proof parent references | 300,000 |
| Proof depth | 256 |
| Unique derived clauses/resolvents | 25,000 |
| Retained side clauses per equality conclusion | 8 (pruning threshold) |
| Canonical proof-work literal charge | 2,000,000 |
| Worklist pushes | 250,000 |
| Live worklist entries | 65,536 |
| All derived literal slots | 150,000 |
| Emitted lemmas | 8,192 |
| Emitted lemma literal slots | 65,536 |
| Emitted p95 width | 8 |
| Emitted maximum width | 32 |
| Logical incremental memory charge | 16 MiB |

Width p95 is the nearest-rank statistic at rank
(\lceil0.95n\rceil) after canonical output ordering. The proof-work charge is
an abstract deterministic counter, not a count of machine loads. Let (W) start
at the number of baseline literal slots. In ordinary search, and for each
unsuppressed ablation child, add before exact event deduplication:

- the source-clause width for every attempted Seed;
- zero for Reflexivity;
- twice the sum of premise side-clause widths for every attempted
  Transitivity or Congruence;
- twice the sum of the equality-side width and the negative source clause with
  its pivot removed for every attempted Conflict;
- the derived-clause width when an accepted Conflict is indexed; and
- incoming width plus retained width for every antichain comparison.

Every listed charge uses full widths even if a tautology, subset, or duplicate
is detected. Hashing, sorting comparisons, event-key comparisons, checker
replay, and final output sorting/subsumption add zero. This abstract schedule is
the only meaning of the 2,000,000 limit and is independently replayed.

Logical memory is also allocator-independent. At every mutation boundary it is
exactly

\[
M=64N+32C+4P+4S+64Q+16R+16O+32A+4G,
\]

where (N) is accepted equality nodes, (C) accepted Conflict clauses, (P) trace
parent references, (S) all accepted equality-side and Conflict-clause literal
slots, (Q) distinct event keys ever inserted, (R) peak simultaneously retained
antichain entries, (O) registered negative equality occurrences in base and
accepted derived clauses, (A) application pairs, and (G) application argument
slots. Counts are logical even if an implementation shares storage. The 16 MiB
test is (M\le16\cdot2^{20}); allocator capacity and WMI MaxRSS are recorded
separately and cannot change this gate.

Proof nodes, derived clauses, parent references, and literal slots count only
accepted unique objects. A worklist push counts an insertion after exact event
deduplication. Except for the explicitly labelled eight-support pruning
threshold, the cap-triggering object is neither inserted nor accepted, the
report records the pre-event value and exact prospective value, and the
complete projection is rejected with its unique cap reason. No truncated prefix
may pass Stage 0A. Integer overflow, allocation failure, malformed input, hash
drift, or checker disagreement also discards the complete candidate.

Hard limits are tested in the table order above. Static input limits are tested
before initialization. Popped-event acceptance computes all prospective
accepted-object counts, slots, antichain state, and logical memory without
mutation and uses the post-pop live count; child insertion follows the separate
transaction above. If more than one limit would be exceeded at one transaction,
the first table entry is the unique reported reason. Emitted count, emitted
slots, p95 width, and maximum width are tested in their table order after final
subsumption. The one-empty-clause outcome has emitted count one; `no_lemmas`
has emitted count zero; both define emitted p95 and maximum width as zero.

## Stage 0A: target no-SAT falsifier

The first implementation action is a target-only projection on

`QF_UF/2018-Goel-hwbench/QF_UF_sokoban.2.prop1_ab_br_max.smt2`

with SHA-256

`cfe0e5e611139004e7f8a06461c4cbf3066bb604786377db1a94d40e797f3112`.

The baseline is pinned to 21,744 variables, 18,082 atom-table entries, 89,470
clauses, and 147,132 literal slots, with the three hashes preserved in
`results/local/t10-target-preflight-898df6d/projection.json`.

Stage 0A has `sat_calls=0`. It passes only if:

- the frozen selector selects the target and every baseline identity matches;
- all hard limits and deterministic accounting hold;
- added terms, atoms, variables, fill edges, and generic transitivity clauses
  are zero;
- compiler and independent checker agree with zero replay failures;
- the external arithmetic/scheduling auditor reproduces every admission,
  counter, cap decision, final subsumption, and output hash;
- projection and materialization clause bytes and hashes are identical;
- the result is either a checked empty clause or between 1 and 8,192 checked,
  non-tautological, non-subsumed emitted lemmas;
- emitted literal slots are at most 65,536, p95 width is at most eight, and
  maximum width is at most 32; and
- for an empty result, its checked dependency DAG contains a missing-equality
  Congruence; for a nonempty result, at least one emitted lemma's checked
  dependency DAG contains one.

Failure stops T11 without a full census, SAT call, WMI job, or timing run.

## Stage 0B: complete no-SAT census

Only a passing Stage 0A authorizes a source-verified 7,503-row WMI projection.
It must use the frozen corpus/manifest contract from T9, run with zero SAT
calls, and bind source, manifest, binary, revision, baseline, trace, lemma, and
record hashes. A separate auditor replays every selected proof and independently
recomputes selector facts and all arithmetic.

Stage 0B passes only with exactly 7,503 error-free rows, exactly T9's sole
selected source, zero selected QG or frog controls, and byte-identical `off`
state. For the selected target, Stage 0B must exactly match Stage 0A's source,
revision, selector facts, baseline dimensions and hashes, zero-SAT-call status,
logical outcome, all deterministic counters and pruning counts, accepted trace
bytes and hash, emitted lemma bytes and hash, and cap decision. Platform receipt
fields may differ only for binary hash and executable format, Rust target and
toolchain receipt, host/job identifiers, wall/CPU time, and RSS; each is still
recorded and hash-bound in its own observation. No timing follows a failed
census.

## Stage 1: tree-parser kernel falsifier

Use one exact Linux binary for `off` and `clique-er-auto`. Throughout this
contract, **fresh Kissat** means a new default session of the Kissat 4.0.4
library statically linked into the Stage-0B-frozen candidate binary, with an
empty option-override list and no seed override. No external or substitute SAT
binary is allowed. Before timing, make one diagnostic call showing fresh Kissat
SAT on the target baseline Boolean CNF. Also run one mechanism ablation by
rerunning the complete
compiler and checker while suppressing every missing-equality Congruence after
its typed parent/conclusion classification but before side-clause construction,
proof-work charge, deduplication, or queue insertion. All other rules, ordering,
caps, and output processing remain unchanged, and the report records the exact
number of suppressed events. The ablated run must itself pass every checker and
cap, then fresh Kissat over the baseline plus all of its checked output clauses
must return SAT. The external scheduling auditor independently reconstructs
every qualifying suppressed event, every retained event, all counters, final
output, and hashes for the ablation just as it does for Stage 0A. This applies
identically when the ordinary run derives empty: the ablated compiler continues
independently and may retain other T11 lemmas.

Both diagnostics and all timed repeats below use the same exact execution lane.
The host is frozen to
`g1n4.cluster.wmi.amu.edu.pl` in partition `gpu_idle`, with the inner launch
`srun --ntasks=1 --cpus-per-task=1 --cpu-bind=map_cpu:0` and observed affinity
exactly `[0]`. Unavailability leaves the experiment pending; it does not permit
another node. The supervisor is the reviewed Linux runtime contract using
`/usr/bin/python3` SHA-256
`7d51cd6b48b521277f5caa4610a82126e315fa2be4df069823a8b1eeb5bd4a86`
and integer `time.monotonic_ns()` observations. Stage 0B freezes the one
hosted-qualified candidate binary hash used by every euf-viper arm. Yices2 is
the 2.7.0 binary with SHA-256
`eab7efbff2a6f0cce2fcd2c25cb4a94e0e048c902d8ef9e6fd7d7989aa54c501`.
Any receipt mismatch fails before a diagnostic or timing observation.

Each diagnostic has an end-to-end `2,000,000,000ns` supervised limit. Its
deadline starts immediately before the supervisor forks the candidate command
and ends only after `waitid` plus complete stdout/stderr drain, including the
total assignment bytes. Thus process startup, source parsing, baseline
construction, ablation compilation and checker replay when applicable, fresh
SAT-session load/solve, and assignment export are inside the limit. The
external scheduling auditor and independent assignment evaluator run after
that observation and are outside its deadline, but both must complete and
accept before the diagnostic passes. Timeout or any non-SAT result fails. Each
session exports a total Boolean assignment for every variable
`1..baseline_variables`; the independent evaluator must accept every exact
baseline and ablation lemma clause under it. Diagnostic calls are excluded from
candidate timing aggregates and Stage 0A's zero-SAT count. This source-level
ablation, rather than a SAT proof-core heuristic, is the causal gate.

After both diagnostics pass, run exactly six repeats over the frozen 24-source
control plus the selected target at the same `2,000,000,000ns` limit. Within
every source, the arm orders are exactly:

1. `off, candidate, yices`;
2. `candidate, yices, off`;
3. `yices, off, candidate`;
4. `yices, candidate, off`;
5. `candidate, off, yices`; and
6. `off, yices, candidate`.

Sources remain in frozen manifest order. Candidate end-to-end time starts
immediately before parsing and ends after the result; compiler, checker, load,
and solve component times are nested inside it. The untimed baseline and
ablation diagnostics are excluded from candidate time.

For the timed target, either the checked compiler reaches empty with zero SAT
calls, or fresh Kissat over the same in-memory baseline plus only checked T11
lemmas must return UNSAT. Kernel SAT, interruption, error, timeout, checker
failure, or identity mismatch discards the T11 session and runs the unchanged
baseline, but rejects the experiment.

The theory-empty path has `sat_session=false`, `sat_calls=0`,
`sat_variables_loaded=0`, `sat_clauses_loaded=0`, and `load_solve_ns=0` in
every observation; the result timestamp follows successful checker replay. The
nonempty path has `sat_session=true`, loads exactly the baseline variable count
and baseline clauses followed by the checked lemma sequence, and records one
fresh SAT call. These are disjoint schema states; absent or `null` component
values are invalid.

Stage 1 passes only with:

- zero wrong answers, execution errors, missing groups, or baseline-only solves;
- candidate and Yices2 return UNSAT on every selected repeat, and the candidate
  does so kernel-first before generic theory clauses;
- the untimed baseline-only and mechanism-ablation diagnostics both return SAT;
- on every selected repeat, `off` either times out or returns UNSAT; when it
  returns UNSAT, candidate elapsed nanoseconds are strictly smaller;
- candidate selected median at most `50,000,000ns`;
- compiler plus checker median at most `8,000,000ns`;
- candidate load plus Kissat solve median at most `8,000,000ns`;
- exact trace/materialization equality; on a nonempty path the fresh session
  loads the baseline variable count and only checked lemma clauses, while on a
  theory-empty path the zero-load schema above holds;
  and
- nonselected p95 overhead at most `1.01`.

Every nonselected candidate/off status must match. Paired timeouts are allowed
and excluded from overhead ratios; any one-sided status is failure. The p95 is
nearest-rank over all solved nonselected source-repeat ratios, sorting ratios
by exact cross multiplication. Its `1.01` gate is checked as
`100*candidate_ns <= 101*off_ns`; no floating-point ratio is used. For six
values, every median gate uses the sum of the third and fourth sorted integer
nanosecond observations against twice its threshold, without rounding.

No sample-40, hot-400, broad, or 1,200-second work follows failure.

## Stage 2: parser and Yices gate

Only Stage 1 success authorizes the already source-complete streaming parser as
a separate arm. It must preserve typed semantics on all 7,503 sources and keep
the T11 trace and lemma hashes unchanged. The four arms are `A = streaming
off`, `B = streaming candidate`, `C = tree-parser candidate`, and `D = Yices2`.
On the same fixed WMI CPU, the exact 12 target-repeat orders are:

1. `A B C D`;
2. `B C D A`;
3. `C D A B`;
4. `D A B C`;
5. `A D C B`;
6. `D C B A`;
7. `C B A D`;
8. `B A D C`;
9. `A C B D`;
10. `C B D A`;
11. `B D A C`; and
12. `D A C B`.

Thus every arm occupies every position exactly three times. The one exact
Linux candidate binary supplies A, B, and C; only its parser and T11 option
differ. Source order, timeout, runtime receipt, and Yices pin remain unchanged.
B, C, and D must return UNSAT in every repeat. A is a baseline parser control
and may either return UNSAT or reach the exact timeout; SAT, error,
interruption, or any other status fails. A is excluded from every speed and
absolute-time gate. Each 12-value median is represented by the sum of the sixth
and seventh sorted integer nanosecond observations, with factors of two
cancelled or carried explicitly in comparisons.

Let `A_i`, `B_i`, `C_i`, and `D_i` be end-to-end target times for repeat `i`.
Tree-to-stream speed is `median(C_i) / median(B_i)`, Yices median speed is
`median(D_i) / median(B_i)`. Let `B_6+B_7`, `C_6+C_7`, and `D_6+D_7` denote the
two central sorted-time sums. The geometric Yices gate uses unbounded integers,
not logarithms: it is

\[
20^{12}\prod_{i=1}^{12}D_i\ \ge\
21^{12}\prod_{i=1}^{12}B_i.
\]

Require:

- B's parser-component median at most `8,000,000ns`;
- B's compiler-plus-checker-component median at most `8,000,000ns`;
- B's candidate-load-plus-solve-component median at most `8,000,000ns`;
- B's end-to-end selected median at most `24,077,067ns`;
- `4(C_6+C_7) >= 5(B_6+B_7)` for at least `1.25x`
  tree-to-stream speed;
- `20(D_6+D_7) >= 21(B_6+B_7)` for at least `1.05x` median
  speed over same-node Yices2; and
- the exact product inequality above for at least `1.05x` geometric speed.

If B or C uses the theory-empty path, its load-plus-solve component is the
required integer zero from the Stage 1 schema and participates as zero in that
arm's median. Its end-to-end time still includes parsing, compilation, and
checker replay. Nonempty observations must use the fresh-session schema.

Before broader timing, the independent composite checker first replays the T11
trace against the hash-bound baseline and obtains the exact ordered lemma
sequence. On a nonempty result it constructs DIMACS bytes whose input clauses
are the direct-root baseline followed by those lemmas in that exact order, with
the unchanged baseline variable count. Fresh Kissat emits DRAT for precisely
those DIMACS bytes by attaching a proof sink to the same default embedded
session. This sink is the only permitted difference from the timed session; no
external producer may be substituted. The checker binds the Stage-0B candidate
binary hash, source, baseline, lemma sequence, DIMACS, invocation, and DRAT
hashes, then requires `drat-trim` revision
`2e5e29cb0019d5cfd547d4208dca1b3ec290349f`, binary SHA-256
`58a121dec7dc8e192f38dc2626c4a993946d487cc0238679fef11f5de63443e5`,
to verify the proof. T11 lemmas are validated theory inputs, not unvalidated
DRAT additions.

On an empty result, the independently replayed T11 trace is itself terminal:
the composite record uses `sat_layer=theory_empty`, `sat_calls=0`, no DIMACS
extension, and zero DRAT bytes with SHA-256
`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.
It may not claim a DRAT check. The mechanism ablation supplies causal evidence
in both paths; no solver-dependent DRAT-core extraction is a gate. The current
canonical-Tseitin certificate reconstruction is not a substitute for exact
direct-root proof binding.

## Prior-art and novelty boundary

The following are established and may not be claimed as inventions:

- Tveretina and Zantema's equality-resolution rule and decision procedure;
- Nieuwenhuis and Oliveras's proof-producing congruence closure;
- Bryant, German, and Velev positive equality;
- Minimal-E and Reduced Transitivity Constraints;
- Fellner, Fontaine, and Woltzenlogel Paleo's NP-complete bounded-size decision
  problem and the resulting NP-hardness of smallest-explanation optimization;
- Flatt et al.'s optimal and greedy small-proof algorithms; and
- Andreotti and Barbosa's 2026 integration of greedy shorter explanations in
  cvc5.

The 2026 cvc5 study reports smaller explanations but substantial aggregate
runtime overhead, including about 29.85% for its non-array/non-string group and
45.59% overall. T11 therefore uses hard routing and work caps rather than a
global explanation optimization.

A possible differentiated contribution is the complete combination of a
source-structural tail router, bounded clause-level equality resolution,
proof-internal missing equalities, base-variable-only exported lemmas, a
separate replay kernel, and asymmetric UNSAT trust in front of modern SAT. No
novelty claim is allowed until a broader closest-prior-art audit, held-out
evidence, and ingredient ablations establish that this exact architecture is
new and useful.

## Stop rule

T11 is killed at the first failed gate. A smaller formula, a nonempty proof
trace, a solved timeout, or a median below Z3 is not promotion evidence. The
campaign proceeds beyond Stage 2 to broader corpus work only after Stages
0A/0B, 1, 2, and the applicable composite-certificate path pass. Promotion is
still forbidden until those later broader runs pass the complete coverage,
aggregate, Z3, Yices2, cvc5, second-CPU, and held-out gates.
