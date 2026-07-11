# SAT-Native Quotient Search: Novelty Campaign

Date: 2026-07-11

Status: design-only research contract. None of the mechanisms below is an
accepted solver route, and no novelty or superiority claim is currently
allowed.

## Objective

Build and falsify several exact QF_UF engines whose primary search object is
neither an equality e-graph nor the pairwise Ackermann clauses used by the
current eager route. The intended endpoint is a standalone solver that beats
both Z3 and Yices2 on coverage and end-to-end time, not a benchmark-specific
front end or a portfolio that calls either comparator.

"Novel" has a strict meaning here. A mechanism is a novelty candidate only
until all four conditions below hold:

1. a reproducible prior-art search finds no equivalent algorithm;
2. the implementation preserves the stated non-collapse invariant;
3. an ablation shows that the new representation, rather than an incidental
   parser, SAT-backend, or routing change, causes the gain;
4. held-out and full-corpus results survive independent reproduction.

A name, unusual vocabulary, or a faster selected benchmark is not evidence of
novelty. If an implementation reduces to small-domain encoding with pairwise
functional-consistency clauses, ordinary model-cut refinement, or a hidden
congruence-closure callback, it is rejected even if it is fast.

## Stop-The-Line Prerequisites

The Boolean-as-data defect and partial SAT-model handling documented elsewhere
must be repaired before any behavioral candidate is timed. Every engine in
this note must satisfy the following common contract:

- every Boolean-sorted ground term, including a term used only as a UF
  argument, denotes exactly `false` or `true`;
- `false` and `true` are distinct in every model;
- a SAT backend `DontCare` value for a theory-relevant variable is completed
  consistently or causes abstention; it is never interpreted silently;
- a `sat` answer is accepted only after independent evaluation of the original
  typed formula in the decoded total model;
- an `unsat` answer is returned only from an exact, completeness-stage
  encoding with a checkable propositional proof;
- an incomplete stage may return a validated `sat`, but its `unsat` means only
  "grow the representation";
- every sort is nonempty and every decoded function is extended to a total
  function;
- no route may inspect a path, benchmark name, content hash, expected result,
  or historical runtime.

These conditions are part of the algorithm, not post-release hardening.

## Common Finite-Quotient Basis

Let `T_s` be the finite set of ground terms of sort `s` after typed flattening,
and let `A_f` be the ground applications of function symbol `f`. Any model of a
ground QF_UF formula induces an equivalence relation on each `T_s`. Conversely,
if the truth assignment to source atoms is realized by typed equivalence
relations satisfying functional consistency, quotienting `T_s` and extending
each observed partial function arbitrarily gives a total EUF model.

Therefore a satisfiable input has a model using at most `|T_s|` observed values
for each non-Boolean sort. This finite-quotient fact justifies all three exact
endpoints below. It does not justify a fixed smaller domain, and it does not
permit an intermediate bounded-domain `unsat` result to escape.

The Boolean sort is special. It has the fixed carrier `{0,1}`. A Boolean-valued
UF is treated as an ordinary total function into that carrier, while derived
Boolean syntax is evaluated by its connective semantics.

## Prior-Art Boundary And Kill Tests

The nearest known lines of work are:

- eager EUF-to-propositional reductions and positive equality by Bryant,
  German, and Velev;
- per-constraint and small-domain encodings, and their hybrid, by Seshia,
  Lahiri, and Bryant;
- MACE/Paradox finite model finding with explicit function tables,
  incremental domain sizes, and symmetry reduction;
- symbolic EUF decision procedures that execute closure over all predicate
  subsets and produce a shared DAG;
- lazy DPLL(T), model-driven Ackermannization, and current complete-model cuts;
- Yices2's equality engine and QF_UF symmetry mechanisms.

The following table states what must remain different.

| Candidate | Nearest antecedent | Non-collapse invariant | Immediate rejection condition |
| --- | --- | --- | --- |
| Canonical Quotient RAM | small-domain encoding; Ackermann reduction | one global sorted record memory enforces functionality; no application-pair implications exist | CNF contains one functional-consistency implication per pair of applications |
| Permuted Finite-Field Interpretation | MACE tables; finite-domain bit blasting | each UF is one shared polynomial interpretation under a jointly searched domain relabeling | full or partial table cells become independent output variables with pairwise channeling |
| Frontier Quotient Transducer | treewidth CSP dynamic programming; positive equality | SAT selects a path through canonical partial-algebra states; no equality closure is run on a SAT trail | runtime invokes union-find/e-graph closure to accept, reject, or refine an assignment |

Ideas deliberately excluded from the campaign:

- class-ID bits followed by pairwise Ackermann implications: old small-domain
  encoding in different notation;
- `f(a) != f(b) -> OR_i(a_i != b_i)`: Ackermann's axiom in contrapositive
  polarity;
- complete-model validation followed by explanation clauses: ordinary lazy
  congruence refinement, already measured in this repository;
- a BDD or AIG that symbolically executes ordinary congruence closure over all
  atom subsets: too close to the established symbolic decision procedure;
- random fingerprints used to learn conflicts: collisions make this unsound;
  fingerprints are allowed only as a filter followed by exact replay;
- one-hot function tables over a chosen finite carrier: MACE-style model
  finding, already a mature line of work;
- an external Yices2 or Z3 fallback: useful operationally, irrelevant to a
  standalone superiority claim.

## Candidate Q1: Canonical Quotient RAM

Short name: `cqram`.

### Core Hypothesis

Search directly for a canonical quotient of the ground terms, but enforce UF
functionality as consistency of records in an obliviously sorted memory. This
replaces both the quadratic application-pair graph and runtime congruence
closure with a circuit resembling a verified read-only RAM transcript.

The expected advantage is strongest when one symbol has many applications.
Pairwise Ackermannization creates `Theta(A_f^2)` candidate relationships;
sorting `A_f` records costs `O(A_f log^2 A_f)` compare-exchanges and makes all
equal keys adjacent.

### Variables And Canonical Quotient

For a non-Boolean sort `s`, enumerate terms in stable creation order
`t_0,...,t_(n-1)` and set

```
w_s = max(1, ceil(log2(n))).
```

Term `t_i` receives a `w_s`-bit class code `q_i`. Impose restricted-growth
canonicalization:

```
q_0 = 0
q_i <= 1 + max(q_0,...,q_(i-1)).
```

Comparator and prefix-maximum circuits encode the condition. Every set
partition has exactly one such labeling in the fixed term order, so domain
permutation symmetry is removed rather than merely reduced.

For `Bool`, use one bit, fix `q(false)=0` and `q(true)=1`, and constrain every
Boolean ground term to that carrier. No Boolean term may be omitted because it
does not occur as an asserted atom.

For each source equality atom `e_(u,v)`, encode the exact equivalence

```
e_(u,v) <-> AND_b (q_u[b] XNOR q_v[b]).
```

The source Boolean formula is then Tseitin-encoded over these equality bits,
predicate results, and derived Boolean expressions.

### Functionality As A Sorted Record Memory

For each symbol `f : s_1 x ... x s_k -> r` and each observed application
`u = f(a_1,...,a_k)`, create a logical record

```
R_u = (key = q(a_1) || ... || q(a_k), value = q(u)).
```

Records are not table cells and do not choose independent outputs. Feed all
records for one symbol through a deterministic stable sorting network keyed by
the concatenated argument codes. A compare-exchange conditionally swaps the
entire key/value record. After sorting, enforce for every adjacent pair:

```
equal_key(R_i, R_(i+1)) -> equal_value(R_i, R_(i+1)).
```

Any two equal keys are contiguous after sorting, so adjacent consistency is
equivalent to functionality for all observed applications. Symbols are sorted
separately. Padding records have a fixed sentinel key and an inactive bit, and
all adjacency constraints are guarded by both active bits.

Boolean predicates and Boolean-valued functions use the same record mechanism
with a one-bit value. Nullary symbols are single stored values and need no
sorter.

The first implementation uses bitonic networks because their structure is
simple to reconstruct independently. Later A/B arms may test odd-even merge,
radix partition circuits, or a verified cuckoo-memory circuit, but only one
functionality representation changes at a time.

### Soundness

Given a satisfying CNF assignment, define each observed carrier as the set of
codes assigned to its terms. Equality atoms have exactly the decoded equality
semantics. For every `f`, equal argument-code tuples become adjacent in the
sorted record sequence and are forced to have equal result codes. The records
therefore define a partial function on observed tuples. Extend it arbitrarily
on unobserved tuples and, if needed, on unused carrier values. Evaluation of
the original formula in this total interpretation matches the source atom
assignment.

No property of the sorting circuit is trusted at runtime: the model validator
recomputes exact keys and results from the decoded codes.

### Completeness

Take any EUF model and restrict each sort to the equivalence classes of its
ground terms. Relabel those classes by their first occurrence to obtain the
unique restricted-growth codes. Equal argument tuples have equal model
results, so their records satisfy adjacent consistency after any correct sort.
All source atoms retain their truth values. Since `w_s` represents at least
`|T_s|` codes, the exact endpoint represents every ground model.

### Incremental Capacity Search

Build the exact-width circuit once. Initially force selected high class bits
to zero with assumptions, giving a smaller quotient under-approximation. A
validated `sat` answer is final. An `unsat` answer only yields an assumption
core; drop one or more implicated capacity assumptions and resume the same SAT
instance. Sorts absent from the core remain narrow. At full width, `unsat` is
an exact EUF result.

This is proof-guided capacity lifting, not a sequence of unrelated finite-model
runs. Learned clauses are retained under standard assumption semantics.

### Proof-Complexity Hypothesis

The class bits and sorter wires are extended-resolution variables for the
quotient. Transitivity becomes bit-vector identity and function congruence
becomes local adjacency. The hypothesis is that hard equality cliques and
repeated application signatures obtain polynomially structured proofs without
the wide or quadratic clauses of eager Ackermannization.

Likely counterfamilies are:

- many terms but very few applications or equality atoms;
- many tiny symbols, where sorter setup dominates;
- wide, high-arity keys with almost no duplicate signatures;
- binary-code pigeonholes whose resolution proofs remain hard despite
  restricted-growth symmetry;
- formulas solved during parsing or root propagation by the current engine.

### Certificate And Incremental Story

- `sat`: emit term codes plus sorted observed records; reconstruct and validate
  the total quotient model independently.
- `unsat`: emit the exact CNF and DRAT/FRAT/LRAT from the full-width stage. The
  checker rebuilds restricted-growth, compare-exchange, and adjacency clauses.
- push/pop: preserve the quotient/sorter circuit while assertions are supplied
  as activation literals. New ground terms require a new generation unless
  spare lanes were reserved.
- intermediate bounded-width proofs are optimization telemetry, not EUF
  certificates.

### Required Telemetry

One `cqram_v1` JSON record per solve must include:

- per-sort terms, full width, active width, used codes, and capacity-core hits;
- per-symbol arity, applications, key bits, padding records, comparators, and
  equal-key adjacencies in the final model;
- exact variables/clauses by category: quotient, canonicalization, sorter,
  adjacency, formula, and activation;
- projection counts for the current eager route and the ratio to CQRAM;
- encode/load/solve/decode/validate times and peak RSS;
- SAT calls, assumptions dropped, conflicts, propagations, restarts, proof
  bytes, and proof-check time;
- source hash, binary hash, git revision, CPU model, backend version, and all
  route flags.

### Exact Test And A/B Gates

`Q1.0`, semantic kernel:

- exhaustively enumerate all typed formulas with at most five non-Boolean
  terms, two UF symbols, arity at most two, and all Boolean-as-data placements;
- compare CQRAM with brute-force quotient enumeration, Z3, and cvc5;
- enumerate every sorter input through eight records and check stable ordering
  and record preservation;
- mutate every comparator and require at least one test to fail;
- validate `sat` models and independently check every generated `unsat` proof.

`Q1.1`, shadow projection over all 7,503 official inputs:

- build no behavioral CNF and make no extra SAT call;
- compute exact projected counts and reject any integer overflow or cap without
  an explicit `unknown_projection` status;
- freeze a target manifest using only this prospective selector:

```
total_applications >= 64
max_applications_for_one_symbol >= 32
projected_cqram_clauses <= 0.80 * projected_current_total_clauses
projected_cqram_variables <= 1.25 * projected_current_total_variables
```

Zero qualifying inputs or a median projected reduction below 25% rejects the
behavioral prototype.

`Q1.2`, targeted WMI gate:

- same binary, `cqram=off|on`, five alternating repeats;
- 10-second and 60-second limits on one AMD and one Intel CPU class;
- every frozen target input, with no family or expected-result filter;
- zero wrong answers, validator failures, malformed records, or execution
  errors; zero baseline-only solves; at least one candidate-only solve;
- timeout-charged, common-total, and geometric ratios each at least `1.10x`;
- candidate peak RSS no more than `1.25x` baseline on 99% of observations.

`Q1.3`, promotion ladder:

- sample-40, hot-400, finite hard tail, non-finite Goel tail, then all 7,503;
- full-corpus coverage nondecreasing and all three speed ratios above `1.00`;
- default routing is forbidden until a second full run and a source-family
  holdout have the same direction.

## Candidate Q2: Permuted Finite-Field Interpretations

Short name: `pffi`.

### Core Hypothesis

Do not represent a UF by application pairs or independent table cells. Search
for one algebraic program interpreting each function over a finite field, while
simultaneously searching the relabeling of quotient values that makes those
programs simple.

For the measured domain-seven closed-table region, use `F_7`. Every function
`F_7^k -> F_7` has a polynomial representation with degree at most six in each
argument. Low-degree stages are strict model under-approximations; the full
degree-six stage is exact. The research bet is that table families carrying
hidden quasigroup, loop, affine, or isotope structure become tiny algebraic
circuits after a suitable value permutation.

### Quotient And Relabeling

For a recognized exact seven-value scope, assign every relevant term a field
value `z_t in F_7`. The seven verified distinct domain constants form a
permutation of the field. To preserve useful relabeling freedom while removing
global affine symmetry, fix two ordered distinct anchors to `0` and `1`; every
other field labeling has an affine conjugate with those anchors.

For a general sort with `n` observed terms, choose the least supported prime
`p >= n`, assign terms to `F_p`, and allow unused field elements. A satisfying
EUF quotient embeds into this field carrier. General mode is an exactness
reference; the first performance implementation is only the verified
domain-seven scope.

Equality atom `u=v` is exactly field equality. Boolean terms remain in the
separate fixed two-element carrier and are never encoded as unconstrained
field elements.

### Polynomial Function Programs

For `f : F_7^k -> F_7`, stage `d` introduces coefficients
`c_(e_1,...,e_k) in F_7` and defines

```
P_f(x_1,...,x_k) =
  SUM_(0 <= e_i <= d) c_(e_1,...,e_k) * PRODUCT_i x_i^e_i  mod 7.
```

Every observed application `u=f(a_1,...,a_k)` adds the evaluation equation

```
z_u = P_f(z_(a_1),...,z_(a_k)).
```

All applications share the same coefficient vector. There are no per-cell
output variables. Powers and monomials are hash-consed across applications,
and balanced modular add/multiply circuits are bit-blasted to CNF. The initial
degree ladder is fixed before timing:

```
d = 0, 1, 2, 3, 4, 6.
```

An optional sparse arm constrains the number of nonzero coefficients with a
cardinality network, but it is a separate factorial experiment. The primary
arm changes degree only.

For Boolean-valued UFs over field arguments, synthesize one Boolean ANF over
the bit encoding of the field inputs, with the full ANF as the exact endpoint.
Mixed-sort functions use one field encoding per non-Boolean sort and one fixed
Boolean encoding where applicable.

### Soundness

At every degree, a satisfying assignment gives explicit total polynomial
functions on the complete field carriers. The decoded term values and
polynomials therefore form a genuine EUF model, not an approximation. Evaluate
the original formula independently before returning `sat`.

An `unsat` at degree below the exact endpoint proves only that no model exists
in that polynomial subclass. It cannot be returned to the user.

### Completeness

Every function `F_p^k -> F_p` is represented by a polynomial with each
variable degree at most `p-1`, for example by multivariate Lagrange
interpolation. Any ground EUF model embeds its observed classes into `F_p`, and
its partial function interpretations can be extended arbitrarily to the full
field before interpolation. Thus the full `(p-1)`-per-variable stage represents
every ground model.

For the exact seven-value route, degree six in each input is complete. If the
recognizer cannot prove that every relevant term and application is inside the
scope, PFFI must abstain or encode the entire enclosing sort at the general
exact width.

### Why This Is Not MACE

MACE-style encoding chooses a value for each function-table cell. PFFI chooses
one shared algebraic program and derives every cell evaluation from it. The
low-degree representation couples distant cells through coefficients and field
identities. The full endpoint has comparable information capacity to a table,
but its variables and proof graph remain coefficient/evaluation based. If an
implementation materializes independent table outputs and merely interpolates
them after solving, the novelty invariant has failed.

### Proof-Complexity Hypothesis

Low-degree interpretations turn many table equalities into repeated arithmetic
identities. On algebraic families, coefficient propagation may replace a large
permutation/table search with a small system of modular equations. Joint value
relabeling searches for the coordinate system in which that compression
exists.

The likely failures are explicit and severe:

- random tables have dense degree-six representations;
- several functions may have no common low-degree coordinate system;
- UNSAT inputs pay for every incomplete degree before the exact one;
- modular multiplication CNF may propagate poorly in plain CDCL;
- the remaining `5!` domain-seven labelings may dominate without useful
  algebraic constraints;
- large prime carriers and high arity make the monomial basis exponential.

These are route boundaries, not reasons to weaken correctness.

### Incremental And Certificate Story

- Prebuild the maximum selected degree for the domain-seven pilot and force
  higher-degree coefficients to zero under assumptions. Drop assumptions to
  grow the degree while retaining learned clauses.
- `sat` certificates contain field values, coefficients, and evaluated
  application records. A small independent evaluator checks all arithmetic and
  the source formula.
- Exact-stage `unsat` uses CNF plus DRAT/FRAT. The checker reconstructs modular
  gates and polynomial evaluation from source terms.
- Restricted-degree `unsat` proofs are retained only to explain growth and
  measure core structure.
- A native finite-field or XOR backend may be tested later, but it cannot be
  promoted until its proof format is independently checked. Plain-CNF PFFI is
  the trust reference.

### Required Telemetry

One `pffi_v1` record must include:

- recognized scope, field order, anchors, terms in/out of scope, and proof that
  the seven constants are distinct and exhaustive for relevant terms;
- per function: arity, applications, stage degree, total/active/nonzero
  coefficients, monomials, shared powers, and evaluation gates;
- label-search decisions, fixed points, permutation count estimate, and final
  value permutation;
- variables/clauses by field operation and formula category;
- per-stage load/solve time, conflicts, propagations, assumption core, and
  reason for growth or abstention;
- decode/validate/proof-write/proof-check time and peak RSS;
- all standard source, binary, git, CPU, backend, and campaign provenance.

### Exact Test And A/B Gates

`Q2.0`, algebraic kernel:

- exhaustively enumerate every unary function on `F_2` and `F_3` and random
  unary/binary functions on `F_5` and `F_7`; interpolate, encode, solve, and
  compare every table entry;
- enumerate all permutations for domains through five and prove anchor
  symmetry preserves degree existence;
- compare modular circuits with SageMath and Magma artifacts generated from
  the same coefficient JSON;
- mutate each add, multiply, reduction, equality, and anchor rule and require a
  differential test to fail;
- include Boolean arguments/results and the three-Bool-values pigeonhole
  regression.

`Q2.1`, read-only degree census:

- for every recognized domain-seven closed table, compute offline minimum
  polynomial degree under all anchor-preserving labelings when the table is
  fully determined by the source; do not affect solving;
- report counts at degrees `0,1,2,3,4,6`, simultaneous degree across multiple
  functions, and estimated CNF sizes;
- reject the pilot if fewer than 10% of exact one-table targets admit degree at
  most three or projected PFFI clauses are not at least 25% smaller on that
  subset.

`Q2.2`, first behavioral target is frozen by exactly:

```
domain_size == 7
closed_binary_table_functions == 1
binary_table_applications >= 49
guarded_disequality_clauses == 0
uncovered_relevant_terms == 0
all_nonconstant_applications_in_scope == true
```

Run the same binary with `pffi=off|degree-ladder`, three alternating repeats at
60 seconds on AMD and Intel WMI nodes. Also run degree arms `1`, `2`, `3`, and
`6` as an ablation, but compare promotion only with the predeclared ladder.

Required result:

- zero wrong answers, validator failures, errors, and baseline-only solves;
- at least one repeated timeout conversion on each CPU class;
- timeout-charged, common-total, and geometric ratios each at least `1.05x`;
- the complete degree-six stage is reached and proof-checked on every target
  whose lower stages do not return a validated model;
- fixed-label versus searched-label ablation attributes at least half of the
  gain on compressed tables to the coordinate search, otherwise simplify the
  claim to polynomial interpretation only.

`Q2.3`, broadening:

- broaden from exact one-table to every verified domain-seven table input only
  after a `2 x 2` factorial test of PFFI and orbit canonization;
- require no negative interaction before combining them;
- then run sample-40, hot-400, finite hard tail, all 7,503, and a source-family
  holdout under the common promotion thresholds.

## Candidate Q3: Frontier Quotient Transducer

Short name: `fqt`.

### Core Hypothesis

Compile QF_UF model construction into a layered finite-state transducer whose
states are canonical partial quotients and partial function memories. SAT then
selects one accepting path while satisfying the source Boolean formula. This
exploits low frontier width directly and never asks an equality engine to close
a SAT trail.

The mechanism is analogous in spirit to bounded-width dynamic programming,
but the state object is a typed partial algebra rather than a Boolean
assignment. It targets formulas whose term/application incidence is large yet
admits a narrow elimination schedule.

### Event Schedule

Build a deterministic min-fill order over a typed incidence hypergraph. Its
vertices are ground terms and source equality/predicate atoms. Hyperedges cover:

- the two terms of each source equality;
- an application result and all its arguments;
- the atom variables needed together by one source Boolean gate.

Convert the order to events:

```
introduce-term
introduce-application
evaluate-source-atom
evaluate-Boolean-gate
forget-term
```

Ties use stable term and atom IDs. The schedule and its width are therefore
reconstructible and cannot encode benchmark identity.

### Canonical State

At layer `i`, a state contains:

1. a typed partition of live frontier terms;
2. zero or more typed ghost values still referenced by a live function memo;
3. for each symbol `f`, a partial map from tuples of current value tokens to a
   result token;
4. values of source atoms and Boolean gates that remain live;
5. a canonical restricted-growth renaming of every token.

An `introduce-term` transition either places the term in an existing compatible
block or creates the next canonical value. An `introduce-application`
transition computes its argument-token key. If the key already occurs in the
symbol memo, the result term must use the stored result token. Otherwise the
transition inserts that key and result. Functionality is therefore a local
state invariant, not a clause between applications.

An equality atom is true exactly when its two terms occupy one token. A
Boolean-valued UF memo returns one of the two fixed Boolean tokens. The outer
formula is evaluated by source gate events.

### Safe Forgetting And The Exact Fallback

Term IDs disappear after their final incidence. A value token may disappear
only if it is not represented by a live term and is unreachable from every
memo entry that can still match a future application. A memo entry may be
discarded when at least one key component is dead and cannot be reconstructed
from any live term or live memo result.

The intended optimization uses a maximally-diverse extension lemma: if no
future incidence can connect a new term to a dead value, arbitrary
identification with that value is unnecessary; split the future component to
a fresh value without falsifying any source atom or function constraint.

This lemma is a proof obligation, not an intuition. Until it is mechanized and
exhaustively checked, behavioral FQT retains all tokens and memo entries. That
no-forget mode is finite and complete but may be exponentially large. An
optimized state deletion that lacks the lemma is forbidden.

### SAT Encoding

Generate all reachable canonical states up to a declared cap. For each state
and legal transition, create a path-edge variable. Standard flow clauses
select one start-to-accept path:

- exactly one outgoing edge from the selected state;
- edge implies its source and destination state;
- incoming/outgoing conservation at internal layers;
- atom-emitting edges imply the corresponding source atom literal;
- only states with the final Boolean root true connect to the accept sink.

Use ladder or commander constraints for layers with many states, selected by a
predeclared state-count threshold. Transition generation is deterministic and
hash-conses equal suffix states. No runtime theory callback exists after the
CNF is loaded.

If state generation reaches its cap, the route abstains before a SAT call. It
does not treat the truncated graph as an exact encoding.

### Soundness

An accepting path defines term values and a consistent observed memo for every
function. Repeated keys have one result by construction. Extend each partial
memo arbitrarily to a total function. Atom events and Boolean gate events then
show that the original formula is true. Independent model validation remains
mandatory.

### Completeness

In no-forget mode, project any finite ground EUF model onto each event prefix,
canonicalize its observed values, and retain every observed function record.
The projections form a legal accepting path. Thus the uncapped no-forget
transducer represents every model.

Optimized forgetting is complete only after proving the maximally-diverse
extension lemma and showing by induction that every full model has an
equivalent projection through the garbage-collected states. If either proof or
exhaustive finite check fails, optimized FQT is rejected rather than patched
with a congruence-closure oracle.

### Why This Is Not DPLL(T) Or An E-Graph

SAT never chooses an equality assignment and asks a theory engine whether it
is closed. It chooses a path whose states are already complete partial-algebra
objects. There is no union-find, equality explanation forest, theory
propagation callback, or learned EUF lemma. All reasoning is present in the
static transition graph and ordinary CNF flow constraints.

If profiling shows a hidden runtime closure pass, or if invalid SAT models are
repaired by adding congruence clauses, this candidate has collapsed and must be
reported as rejected.

### Proof-Complexity Hypothesis

For peak live width `w`, the expensive object is the number of canonical
partial algebras, not the total number of terms. On genuinely narrow inputs,
the path encoding is an extended formulation of a dynamic program: conflicts
become local dead ends, and unit propagation removes states that cannot extend.
This can give short resolution proofs even when the source contains long
equality chains or repeated application structure.

Expected failure families:

- high pathwidth or a dense equality/application incidence graph;
- many live memo keys even when term width is small;
- Boolean formulas keeping old atom values live for a long interval;
- symmetric states not removed by canonical token renaming;
- formulas solved faster than the transducer can be generated;
- garbage-collection rules too conservative to expose a narrow frontier.

### Incremental And Certificate Story

- Assertions over an unchanged atom universe can be activation clauses on one
  immutable transition CNF; the transducer is reusable across push/pop.
- `sat` certificates are accepting edge paths plus decoded term/memo values.
  A checker replays every transition and then validates the source model.
- `unsat` certificates are DRAT/FRAT over the exact, uncapped transition CNF.
  The checker reconstructs the schedule, reachable states, transitions, and
  flow clauses deterministically.
- A state cap always produces abstention and fallback to another exact internal
  engine; it never produces `unknown` when the overall solver can continue.

### Required Telemetry

One `fqt_v1` record must include:

- incidence vertices/hyperedges, elimination order hash, raw width, typed term
  frontier width, live Boolean width, and memo width;
- states and transitions per layer, peak and total counts, canonicalization
  cache hits, duplicate states, dead states, and suffix sharing;
- live/ghost tokens, memo entries by symbol, forget attempts, successful
  garbage collections, and reasons for retained entries;
- state cap, cap layer, abstention reason, and projected complete size;
- build/CNF-load/solve/decode/validate/proof times, peak RSS, SAT statistics,
  variables/clauses, and proof bytes;
- standard source, binary, git, CPU, backend, and route provenance.

### Exact Test And A/B Gates

`Q3.0`, transition semantics:

- exhaustive brute-force comparison for all typed ground problems with at
  most eight terms, two symbols, arity at most two, and arbitrary event orders;
- compare no-forget and optimized-forget accepted atom assignments;
- model-check the maximally-diverse extension lemma for every enumerated case;
- include cross-symbol equalities, Boolean arguments/results, term ITEs, and
  predicate congruence;
- mutate each transition rule, memo lookup, canonical renaming, and forget rule
  and require a failing witness;
- check every complete small `unsat` CNF proof independently.

`Q3.1`, shadow schedule over all official inputs:

- compute schedule and bounded state projection without altering solving;
- use a hard generation cap of `1,000,000` states and record exact cap status;
- freeze a target manifest using only:

```
ground_terms >= 256
peak_typed_term_frontier <= 12
peak_live_memo_entries <= 32
projected_reachable_states <= 1_000_000
schedule_complete == true
```

Zero qualifying inputs, or build time above 10% of baseline solve time on more
than half the qualifying inputs, rejects behavioral work.

`Q3.2`, targeted WMI gate:

- same binary, `fqt=off|on`, five alternating repeats at 10 and 60 seconds;
- AMD and Intel CPU classes; every frozen target, no family filter;
- zero wrong answers, errors, validator failures, baseline-only solves, capped
  behavioral encodings, or transition-check failures;
- at least one candidate-only solve and all three speed ratios at least
  `1.10x` including transducer construction;
- 99th-percentile RSS at most `1.50x` baseline and proof-check time reported
  separately.

`Q3.3`, promotion ladder:

- sample-40, hot-400, finite and non-finite tails, then all 7,503;
- retain the structural route only if full-corpus coverage is nondecreasing and
  all three timing ratios exceed `1.00`;
- rerun on a source-family holdout designed after the target manifest is
  frozen, not after timings are seen.

## Campaign Organization

### Independent Workstreams

Each candidate gets an isolated implementation branch and one semantic owner.
The owners share only:

- typed ground IR and source-formula evaluator;
- total-model validator;
- CNF/proof writer;
- benchmark/provenance harness.

They do not share a candidate theory encoder. This makes ablation and failure
attribution possible. A fourth reviewer owns adversarial test generation and
tries to produce a wrong answer before any performance run.

### Phase A: Novelty Falsification

For each candidate, search title/abstract/full text and implementations using
the exact mechanism terms plus older vocabulary. Produce a claim chart with:

- each algorithmic step;
- nearest publication and codebase;
- identical and distinguishing elements;
- whether the distinction affects semantics, proof system, or only
  engineering;
- a final label: `known`, `new-combination`, `novel-candidate`, or `unknown`.

At minimum, inspect references and descendants of the papers listed below,
SMT-COMP solver descriptions, SAT/CP finite-domain encodings, finite model
finders, knowledge compilation, symbolic model checking, and proof complexity.
No paper draft may use "first" until two independent reviewers sign this
chart.

### Phase B: Semantic Reference Implementations

Implement deliberately slow reference kernels first:

- CQRAM record sorting and quotient decoding;
- PFFI interpolation/evaluation over `F_7`;
- FQT no-forget state enumeration.

Cross-check all three against brute quotient enumeration on small inputs and
against Z3/cvc5/Yices2 on generated typed formulas. Performance code cannot
replace the references; optimized kernels dual-run them in debug/property
tests.

### Phase C: Telemetry-Only Corpus Census

Run every structural projection over the complete corpus without changing one
answer, CNF, backend call, or timing route. Archive raw per-instance JSON and
freeze candidate manifests before behavioral timing. If the proposed
structural opportunity does not exist, reject or redesign the candidate.

### Phase D: One-Mechanism Gates

Run the exact candidate-specific gates above. No two novelty mechanisms are
combined in this phase. Compiler flags, SAT backend, parser, binary, CPU
affinity, timeout, warmup count, and validation settings are identical between
arms. Alternate arm order and preserve every raw observation.

### Phase E: Interaction Experiments

Only individually surviving mechanisms enter pairwise `2 x 2` factorial
experiments. Measure main effects and interaction terms on the union of their
frozen manifests. A combination is rejected if it hides a loss in either
original region, even when aggregate time improves.

### Phase F: Superiority Campaign

A default candidate must pass:

1. sample-40 and hot-400 paired gates;
2. finite hard-tail and non-finite hard-tail gates;
3. all 7,503 official QF_UF inputs at 2, 60, and 1,200 seconds;
4. AMD and Intel `x86-64-v3` WMI nodes;
5. two independent full repetitions;
6. a source-family-held-out or newly released corpus;
7. fresh pinned Z3, cvc5, and Yices2 runs under identical limits;
8. independent SAT-model validation and UNSAT-proof checking.

Standalone superiority requires, at every declared timeout:

- coverage at least `max(Z3, Yices2)`;
- zero wrong answers and execution errors;
- at least `1.05x` lower timeout-charged total than each comparator;
- at least `1.02x` geometric speed on common solved instances;
- the same direction in both full repetitions and the holdout.

Median-only, selected-family-only, or comparator-fallback results do not count.

## Decision Ledger

Every iteration appends one immutable result entry elsewhere with:

- hypothesis and exact source commit;
- baseline/candidate binary hashes;
- structural manifest and selector version;
- all flags and backend versions;
- test/proof status;
- raw artifact location and hashes;
- coverage, timeout-charged, common-total, geometric, RSS, and proof overhead;
- decision: `reject`, `retain-experimental`, `promote-route`, or
  `promote-default`;
- next falsification experiment.

No failed mechanism is silently folded into another. A later revival needs a
new causal hypothesis and must compare against both the original failure and
the current accepted baseline.

## Literature Anchors For The Novelty Audit

- Bryant, German, and Velev, *Processor Verification Using Efficient
  Reductions of the Logic of Uninterpreted Functions to Propositional Logic*:
  https://arxiv.org/abs/cs/9910014
- Bryant and Velev, *Boolean Satisfiability with Transitivity Constraints*:
  https://arxiv.org/abs/cs/0008001
- Seshia, Lahiri, and Bryant, *A Hybrid SAT-Based Decision Procedure for
  Separation Logic with Uninterpreted Functions*:
  https://www.cecs.uci.edu/~papers/compendium94-03/papers/2003/dac03/pdffiles/27_1.pdf
- Lahiri, Ball, and Cook, *Predicate Abstraction via Symbolic Decision
  Procedures*:
  https://arxiv.org/abs/cs/0612003
- Claessen and Sorensson, *New Techniques that Improve MACE-style Finite Model
  Finding*:
  https://fitelson.org/paradox.pdf
- Dutertre, *Yices 2.2*:
  https://yices.csl.sri.com/papers/cav2014.pdf
- Dejan Jovanovic and Leonardo de Moura, *The Design and Implementation of the
  Model Constructing Satisfiability Calculus*:
  https://www.cs.utexas.edu/~hunt/FMCAD/FMCAD13/papers/71-Model-Construction-SAT-Calculus.pdf
- Flatt et al., *Small Proofs from Congruence Closure*:
  https://arxiv.org/abs/2209.03398
- McEliece, *Finite Fields for Computer Scientists and Engineers*, for finite
  field interpolation and polynomial representations:
  https://agorism.dev/book/math/alg/robert-j_mceliece-finite-fields-for-computer-scientists-and-engineers-springer-us.pdf

The bounded search performed while drafting this contract found the antecedents
above but did not find an exact description of sorted quotient-record
functionality, jointly relabeled finite-field UF synthesis, or the proposed
frontier partial-algebra transducer for ground QF_UF. That observation is only
the start of Phase A; it is not a publication-grade novelty determination.
