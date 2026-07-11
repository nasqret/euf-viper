# Orbit-Quotiented Forbidden-Table Automaton

Date: 2026-07-11

Status: novel mechanism candidate; exact first-orbit extraction confirmed, no
solver promotion and no novelty claim yet

## Executive decision

The hard domain-seven classification tail is not merely a generic finite EUF
problem. At least one representative instance contains a compact algebraic
core followed by exactly `7! = 5,040` assertions, each excluding one complete
binary operation table. Encoding those exclusions as ordinary Boolean clauses
throws away the group and table structure that generated them.

The proposed mechanism is an exact, SAT-free search over canonical finite
tables. It verifies invariance of the algebraic core, quotients complete
forbidden tables by the verified value-permutation action, and stores the
remaining forbidden representatives in a row trie or minimal acyclic
automaton. Search uses row-permutation domains, Latin/Hall propagation, and
canonical augmentation. A model is accepted only after evaluating the
original formula. UNSAT is trusted only after an independently checkable
exhaustive canonical-search certificate.

This is not ordinary symmetry clauses, a renamed e-graph, or a benchmark-name
router. It is a structural replacement for a particular proof-complexity
failure mode.

## Measured trigger

The inspected formula is:

`QF_UF/QG-classification/qg7/iso_icl_nogen001.smt2`

Frozen source SHA-256:

`6e9ea0786a672c467f853bf8964283bbdc53c2b51c41e0b0e6fc1fbd8ba34be0`

Observed source structure:

| Measurement | Value |
| --- | ---: |
| Bytes | 6,013,419 |
| Lines | 5,070 |
| Top-level assertions | 5,049 |
| Assertions matching `not(and(...))` | 5,040 |
| Occurrences of binary table application `op` | 247,366 |
| Equality occurrences | 248,206 |
| Declared finite values | 7 |

The first eight assertions after the declarations encode closure, table laws,
additional identities, and pairwise distinction of the seven values. Every
remaining assertion is a complete-table exclusion of the same fixed width.
The count `5,040` is exactly the order of the full value-permutation group
`S_7`. The typed probe subsequently established that all 5,040 records are
unique and equal exactly the full orbit of the first extracted table: orbit
size 5,040, zero missing members, and zero out-of-orbit records. The measured
result and machine-readable output are recorded in
`../06-results/2026-07-11-forbidden-orbit-probe.md` and its adjacent JSON file.

The old 1,200-second campaign solved this instance only after crossing the
60-second boundary, while Z3 and Yices2 solved it near one second and below
one second respectively. The whole `DOMAIN7_HUGE` population contains 174
instances; ten remained euf-viper timeouts at 60 seconds.

## Semantic reduction

Let `T` be the finite operation table, `B(T)` the conjunction of all base
constraints, and `A_i(T)` a total assignment to every table cell. The input is

\[
  F(T) = B(T) \land \bigwedge_{i=1}^{m} \neg A_i(T).
\]

Let a verified finite permutation group `G` act on values and therefore on
table cells and outputs by conjugation. The reduction requires all of the
following:

1. `B` is invariant under every generator of `G`.
2. Every extracted `A_i` is a well-typed total table assignment.
3. Canonical augmentation visits exactly one representative of every `G`
   orbit of total tables admitted by the finite-domain constraints.
4. The anti-model set is represented by the canonical images
   `Q = { canon(A_i) }` without loss.

For a canonical table `C`, all members of its orbit agree on whether their
canonical image belongs to `Q`. Therefore canonical search may solve

\[
  B(C) \land canon(C) \notin Q
\]

instead of materializing all `m` complete-table clauses. This equivalence is
valid only under the verified invariance and complete-transversal conditions.
Checking a few generator lex inequalities is not sufficient.

## Exact recognizer

The first implementation should run after the production parser and consume
typed terms, not raw benchmark names. Eligibility is all-or-nothing.

Required checks:

1. One finite sort has a verified pairwise-distinct domain of size `3..11`.
2. One selected operation is closed on that domain and all required table
   cells exist as ground terms.
3. Every candidate exclusion is a negated conjunction of exactly one equality
   per selected table cell.
4. Each equality assigns that cell to exactly one domain value.
5. No candidate exclusion contains a duplicate or missing cell.
6. No selected equality is guarded by an unrecognized Boolean context.
7. The remaining base assertions are separated without mutation.
8. The group action maps every selected term and base assertion back into the
   typed term universe.
9. Canonicalized anti-model records are deterministic and hash checked.

Any failed check returns `ineligible`; it never produces SAT or UNSAT.

Once the typed version is established, a streaming front end may recognize
the same shape before allocating the generic Boolean tree. It must emit a
typed extraction certificate that the ordinary parser can replay in audit
mode. The streaming path is a later optimization, not part of the initial
trusted base.

## Table representation

For a binary operation on `n <= 11` values:

- store a cell in one byte;
- store each row as a compact value vector;
- when rows are permutations, encode a row by Lehmer rank;
- use an `n`-bit mask for each column's used values;
- use an `n`-bit mask for each unassigned cell domain;
- hash a complete table with a fixed, versioned digest;
- store canonical anti-model tables as row-rank sequences.

For `n = 7`, a row-permutation identifier fits in 13 bits and a full table is
seven identifiers. The 5,040 raw complete tables can therefore be represented
far more compactly than 5,040 repeated 49-equality syntax trees.

## Forbidden-table automaton

The initial data structure is a deterministic trie keyed by canonical row
rank. Identical suffixes may then be hash-consed into a minimal acyclic word
graph.

At a partial table prefix, the automaton answers:

- whether no forbidden table extends the prefix, allowing the anti-model
  constraint to be dropped for this branch;
- whether exactly one or a small set of forbidden suffixes remain;
- whether every base-admissible completion represented by the current search
  state is forbidden;
- which next-row values distinguish the remaining forbidden records.

Branching should maximize the expected split of both the base constraint state
and the forbidden automaton state. A fixed row-major order is the reference,
not the intended final policy.

## Canonical augmentation

The search tree itself must enforce one representative per orbit. The
reference oracle may compute exact canonical forms by exhaustive permutation
for small domains. The optimized path should use a stabilizer chain:

1. Fix the first introduced value.
2. Refine value colors from assigned row/column/table incidence signatures.
3. Extend only assignments whose prefix is minimal under the current
   stabilizer.
4. Split stabilizers when a new table cell distinguishes values.
5. Record the permutation witness for every orbit-pruned branch.

The existing exhaustive `orbit_canon` module is the correctness oracle. It is
not itself the production algorithm.

## Base propagation

The finite-table search should combine several exact propagators:

- row and column `AllDifferent` masks;
- Hall subset checks for small unresolved row/column sets;
- direct evaluation of ground equalities and disequalities;
- compiled evaluators for table identities;
- congruence-signature propagation for nested UF terms;
- early evaluation of Boolean sub-DAGs whose atoms become fixed;
- forbidden-automaton prefix reduction;
- canonical-prefix rejection.

Conflicts must carry enough information to replay the pruning step. The first
reference can use full state snapshots; the optimized engine should use a
reversible trail and allocation-free hot loops.

## SAT and UNSAT trust boundaries

### SAT

A found table is only a candidate. Before returning SAT:

1. construct a total model for every sort and function;
2. replay every ground application;
3. check congruence and typing;
4. evaluate every original source assertion;
5. optionally compare the result with the ordinary model checker in audit
   builds.

Failure falls back to the general solver and records a hard diagnostic.

### UNSAT

UNSAT requires a certificate containing:

- source and extraction hashes;
- finite-domain and closure witnesses;
- base-invariance generator witnesses;
- one total-table record for every extracted exclusion;
- canonicalization witnesses and the quotient anti-model set;
- a complete canonical search tree;
- a reason for every closed node: base conflict, Hall conflict, canonical
  predecessor, or forbidden canonical table;
- deterministic checker version and limits.

The checker must not share the optimized search implementation. Until this
certificate exists and replays, the mechanism may return SAT or abstain, but
must not return UNSAT in production.

## Expected performance shape

The mechanism attacks three costs simultaneously:

1. Parsing and storing millions of repeated equality nodes.
2. One-hot CNF expansion over finite table cells.
3. Exponential resolution over long complete-assignment exclusions.

The optimistic domain-seven path is:

- linear typed extraction;
- quotient 5,040 anti-models to one or a few orbit representatives;
- row-wise canonical search using bit masks;
- prune with identities and the anti-model automaton;
- validate one model or replay a compact exhaustive proof.

It should not be enabled on formulas lacking a large, verified complete-table
anti-model population. Small ordinary EUF formulas should never pay this
setup cost.

## Experiment ladder

### E0: extraction only

- Run on the ten persistent domain-seven QG tail instances.
- Report eligibility, table width, exclusion count, completeness failures,
  canonical orbit count, and extraction time.
- Require zero semantic mutation and deterministic hashes.

### E1: exact orbit quotient

- Canonicalize every complete exclusion with the exhaustive oracle.
- Verify each permutation witness.
- Measure raw exclusions to canonical representatives.
- The representative formula passed the typed set-equality check: 5,040 raw
  records form one exact orbit. The next check is base-formula invariance and
  an exact canonical-search reduction to one forbidden representative.

### E2: bounded reference search

- Solve domain sizes at most five by exhaustive canonical augmentation.
- Differentially compare with Z3, cvc5, Yices2, and euf-viper.
- Check every SAT model and every UNSAT certificate.

### E3: optimized domain-seven kernel

- Add Lehmer-ranked rows, bitset Hall propagation, and stabilizer refinement.
- Run paired WMI A/B on the ten tail instances with at least 15 repeats.
- Promote only if every instance preserves its result and aggregate time beats
  the sound baseline by at least 2x.

### E4: structural expansion

- Ten persistent domain-seven tail formulas.
- All 174 `DOMAIN7_HUGE` formulas.
- All 431 domain-seven closed-table formulas.
- Held-out complete-table formulas from other families and generated variants.

### E5: ranking gate

The mechanism is useful only if the full portfolio preserves all current
solves and materially reduces the broad UNSAT deficit. The full-corpus gate is
the same frozen Z3, cvc5, and Yices2 campaign used by the rest of the project.

## Falsification criteria

Reject or redesign this track if any of the following holds:

- the 5,040 records do not quotient strongly under a verified group;
- base-invariance checking costs as much as the existing solve;
- canonical search revisits a material fraction of the unquotiented space;
- proof replay is larger or slower than the original eager proof;
- the optimized path wins only on filename-selected instances;
- parser/extractor disagreement occurs on any generated mutation;
- the ten-instance gain disappears on the 174-instance prospective set;
- the kernel improves tail coverage but worsens full-corpus aggregate timing.

## Novelty boundary

The following ingredients are known separately and cannot support a novelty
claim by themselves:

- Latin-square enumeration;
- tries and minimal acyclic word graphs;
- symmetry breaking and canonical augmentation;
- finite model finding;
- Hall propagation;
- forbidden-assignment constraints.

The research hypothesis is the verified combination: detect orbit-generated
complete-table exclusions inside ground SMT, quotient the anti-model set under
the same certified action used by canonical finite-table search, and emit a
replayable EUF UNSAT certificate. A formal prior-art search is required before
calling that combination novel.
