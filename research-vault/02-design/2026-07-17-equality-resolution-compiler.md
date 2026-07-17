# Equality-Resolution Compiler Successor

Date: 2026-07-17

Status: superseded by the exact T11 preregistration

The resolved contract is
`2026-07-17-t11-bounded-equality-resolution-compiler.md`. In particular, an
empty clause is now an optional strong outcome rather than a mandatory
projection gate, and T11 implements clause-level equality resolution with exact
side clauses rather than an all-positive congruence explanation.

## Motivation

T9 axiomatizes equality and asks CDCL to discover an equality proof through
1,517,715 generic transitivity clauses. T10 first tests the cheapest strict
subset: atom-preserving Ackermann clauses. If that kernel cannot derive UNSAT,
the next credible route is not another fill-order heuristic. It is a bounded,
proof-producing equality-resolution compiler that derives the relevant
side-condition clauses before the first SAT call.

## Equality Resolution

Tveretina and Zantema study a sound and complete proof system for equality CNF.
Its characteristic inference composes an equality path with a conflicting
disequality:

\[
\begin{array}{c}
C_1\lor x_1=x_2,\ldots,
C_{k-1}\lor x_{k-1}=x_k,
C_k\lor x_1\ne x_k
\\ \hline
C_1\lor\cdots\lor C_k.
\end{array}
\]

The primary report is
<https://pure.tue.nl/ws/files/2252462/200302.pdf>. Their equality-pigeonhole
examples have short equality-resolution proofs even when ordinary resolution
must rediscover transitivity through a difficult encoding.

Relevant established reductions include:

- Bryant and Velev sparse transitivity:
  <https://www.cs.cmu.edu/~bryant/pubdir/tocl-trans01.pdf>;
- Bryant, German, and Velev positive equality:
  <https://www.cs.cmu.edu/~bryant/pubdir/cav99a.pdf>;
- Meir and Strichman contradictory-cycle reduction:
  <https://ofers.dds.technion.ac.il/publications/cav05_eq.pdf>;
- Rozanov and Strichman polynomial RTC generation:
  <https://ofers.dds.technion.ac.il/publications/smt07.pdf>; and
- Rodeh and Strichman Minimal-E graphs:
  <https://www.cs.bgu.ac.il/~mcodish/jsatornot/IC05.pdf>.

None of these ingredients is a novelty claim. A potentially differentiated
architecture would combine typed UF provenance, bounded equality resolution,
modern SAT, and independently replayable proofs without global triangle
materialization or a CDCL(T) callback.

## Candidate Architecture

1. Preserve equality polarity and source-versus-Ackermann provenance in a
   hash-consed typed DAG. Provenance affects scheduling, never validity.
2. Build signed equality-clause biconnected components around disequality
   edges and enumerate shortest contradictory paths first.
3. Apply equality resolution directly to the containing CNF clauses. Canonical
   hash-consing, tautology rejection, subsumption, and unit propagation happen
   after every derivation.
4. Stop on the checked empty clause or a frozen work cap. On success, return a
   replayable equality-resolution trace and optionally a DRAT translation. On
   exhaustion, add only independently valid derived clauses to Kissat or
   abstain to the existing solver.
5. Never allocate global fill-equality variables or generic triangle clauses.

Positive-equality and Minimal-E preprocessing are optional witnessed arms, not
assumptions. Each survives only if its adequacy witness checks independently
and it removes at least 25% of target equality vertices or edges.

## Candidate Projection Gate

Before implementation, a separate preregistration must freeze exact manifests,
limits, and evidence. The current literature-derived bounds to challenge are:

- `sat_calls=0` during projection;
- empty clause within 25,000 unique resolvents;
- at most 150,000 derived literal slots;
- at most 2,000,000 premise-literal inspections;
- p95 derived width at most eight and maximum width at most 32;
- peak compiler memory at most 16 MiB; and
- any triangle fallback at most 47,428 clauses and 142,285 literals, a strict
  32-fold reduction from T9.

Every UNSAT trace must replay in an independent checker. Exhaustive small
signed graphs and generated QF_UF formulas must agree with independent solvers.
Only a projection pass can authorize timing. The final fixed-core target bound
remains parser median at most `8ms`, proof compilation at most `10ms`, and total
median at most `24.077067ms` on the fixed WMI core.

## Stop Rule

Run T10 first because it is a strict, zero-new-variable falsifier. If T10
succeeds, equality resolution is unnecessary complexity. If T10 fails and a
source-only equality-resolution projection cannot derive the empty clause
within the frozen bounds, stop this successor without candidate timing.
