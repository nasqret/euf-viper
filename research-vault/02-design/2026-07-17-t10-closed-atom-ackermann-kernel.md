# T10 Closed-Atom Ackermann Kernel

Date: 2026-07-17

Status: preregistered before implementation, projection, or candidate timing

## Decision Boundary

T10 tests whether the hard Goel tail needs a small congruence seed rather than
T9's complete Ackermann and chordal-transitivity materialization. The route is
an opt-in, source-structural UNSAT accelerator. It does not replace the normal
SAT validator, infer SAT from an incomplete abstraction, or inspect a path,
family, expected result, prior runtime, or comparator result.

The experiment reuses T9's already audited clique-pressure selector unchanged.
Only the representation after selection changes. T9 added 3,686 Ackermann
clauses, 9,900 fill edges, and 1,517,715 transitivity clauses. T10 is permitted
to add congruence clauses only when every Boolean atom in that clause was
already interned by the baseline CNF. It therefore creates no equality atom,
fill edge, transitivity clause, or SAT variable.

## Logical Kernel

For two applications of the same non-Boolean function,

\[
f(a_1,\ldots,a_k),\qquad f(b_1,\ldots,b_k),
\]

Ackermann congruence gives the theory-valid clause

\[
\neg e_{a_1b_1}\lor\cdots\lor\neg e_{a_kb_k}
\lor e_{f(a)f(b)}.
\]

Boolean-valued applications use the corresponding two implication clauses.
Let \(A_0\) be the atom map after the unchanged baseline CNF is complete. T10
keeps a clause if and only if every atom in it belongs to \(A_0\). Membership
testing may call only `get`; it may not intern a missing atom. Clauses are
canonicalized, deduplicated, and ordered deterministically.

Every admitted clause is valid in every EUF interpretation. T10 makes a
kernel-first Kissat call over the ordinary Boolean base plus these clauses,
before generating generic transitivity. Consequently, kernel UNSAT is a sound
UNSAT result for the source formula. Kernel SAT is not conclusive: that solver
session is discarded and the unchanged baseline pipeline, including its normal
transitivity generation and complete EUF validator, remains authoritative.
Unknown, allocation failure, count divergence, or any unsupported construct
also returns to the unchanged baseline path.

## Prior-Art Boundary

Ackermann reduction and sparse transitivity are established techniques. Bryant
and Velev's sparse method completes the equality graph before adding triangle
constraints:
<https://www.cs.cmu.edu/~bryant/pubdir/cav00.pdf>.
Reduced Transitivity Constraints use equality polarity to retain only
contradictory cycles:
<https://ofers.dds.technion.ac.il/publications/smt07.pdf>.

T10 does not claim either result as new. The falsifiable differentiation is the
combination of an audited structural router, an atom-preserving congruence
kernel, zero graph completion, and asymmetric trust: accept kernel UNSAT, but
validate or escalate kernel SAT. No novelty claim is allowed until a broader
literature audit and held-out evidence establish that this exact boundary is
not already implemented.

## Frozen Option And Selector

The only option is
`EUF_VIPER_T10_ACKERMANN=off|closed-atom-auto`; absent means `off`, and every
other value fails closed. `off` must remain byte-identical to main.

`closed-atom-auto` may run only when the unchanged T9 source facts hold:

- no finite-domain clauses or closed-table encoding;
- verified disequality-clique lower bound at least 48;
- disequality edges exceed the clique minimum by at most eight;
- equality graph has at least 2,500 vertices and 10,000 edges;
- at most 256 uninterpreted applications; and
- the selected backend is the pinned Kissat build.

No target identity or benchmark metadata participates in this decision.

## Stage 0: No-Solve Projection

Before candidate timing, run the exact source-verified 7,503-row corpus with
`sat_calls=0`. The projection must bind source, manifest, binary, revision,
baseline-CNF, atom-map, clause-plan, and record hashes. An independent auditor
must reproduce every selected row and count.

Stage 0 passes only if:

- exactly 7,503 rows are present with zero parse, hash, arithmetic, allocation,
  or planning errors;
- the selected population is exactly T9's single frozen structural selection;
- `off` leaves the baseline CNF and atom map byte-for-byte unchanged;
- the selected row has between 1 and 4,096 distinct closed-atom clauses, at
  most 16,384 added literal slots, and no clause wider than four literals;
- added variables, new atoms, fill edges, and new transitivity clauses are all
  exactly zero;
- materialized clause bytes equal the projection exactly; and
- every admitted clause independently replays as an Ackermann congruence
  instance over the typed term arena.

Failure stops T10 without a solve. Passing Stage 0 permits only the frozen
Stage 1 falsifier.

## Existing End-To-End Lower Bound

T9's already sealed target profile measured `32,390,952ns` in the current tree
parser. Its same-node Yices2 median was `25,280,921ns`, so the final `1.05x`
gate requires at most

\[
25{,}280{,}921 / 1.05 = 24{,}077{,}067\ \mathrm{ns}.
\]

The current parser therefore cannot win even with free theory reasoning. T10
separates the representation test from parser integration rather than hiding
both changes in one timing arm.

## Stage 1: Kernel Falsifier

Use one exact binary for `off` and `closed-atom-auto`, retaining the current
parser in both arms. Run four balanced repeats on the frozen 24-source control
plus the complete selected population, on one pinned WMI logical CPU at a
two-second limit. Run the sealed Yices 2.7.0 binary on the selected population
under the same placement and schedule.

T10 passes only with all of the following:

- zero wrong answers, execution errors, missing observations, or baseline-only
  solves;
- correct UNSAT on every selected repeat, while all candidate SAT results are
  independently validated rather than trusted;
- exact plan/materialization equality and no new atom or variable;
- kernel UNSAT before generic transitivity generation on every selected repeat;
- byte-identical nonselected CNF, backend, and route selection;
- nonselected p95 overhead at most `1.01`;
- improvement over `off` on every selected source; and
- selected median at most `50,000,000ns`, including the current parser.

Unchanged paired timeouts on nonselected controls are permitted; a timeout is
not a wrong answer. The 50ms ceiling demands a `10.95x` improvement over T9's
`547,702,323ns` median while isolating the kernel representation. T10 is
rejected if it merely closes coverage or needs graph completion. No parser,
sample-40, hot-400, broad, or 1,200-second work follows a failed Stage 1.

## Stage 2: Parser And Yices Gate

Only after Stage 1 passes may the already source-complete streaming parser be
integrated as a separate arm. It must retain exact typed semantic parity on all
7,503 sources and leave the kernel clause hash unchanged. On the same fixed WMI
core, require at least 12 balanced paired repeats, streaming-parser median at
most `8,000,000ns`, total selected median at most `24,077,067ns`, at least
`1.05x` median and geometric speed over same-node Yices2, and at least `1.25x`
speed over the Stage 1 kernel with the tree parser. Nonselected p95 overhead
remains at most 1%.

If Stage 2 passes, emit and independently check a DRAT proof for the kernel
UNSAT result, then repeat the exact binary on sample-40 and hot-400. Only those
controls can authorize broader timing. Parser microtime or formula-size
reduction alone cannot promote T10.
