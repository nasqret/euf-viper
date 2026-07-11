# Novelty Campaign

The project is pursuing a standalone QF_UF solver that differs materially from
the rollback e-graph DPLL(T) architecture used by Z3 and Yices2. Novelty is
treated as a hypothesis until primary-source review, source archaeology,
ablation, and held-out experiments all agree.

## Starting Boundary

At 1,200 seconds the old exact binary solves 7,502/7,503 formulas, versus 7,500
for Z3 and 7,503 for Yices2. It narrowly beats Z3's timeout-charged total but is
about 4.27 times slower than Yices2. The binary also predates the Boolean-data
soundness repair, so this is opportunity evidence rather than an accepted
solver result.

## Distinct Mechanisms

The planned architecture combines seven independently testable mechanisms:

1. complete EUF model scouts before CNF allocation;
2. Boolean DAG compilation modulo checked theory congruence;
3. proof-carrying orbit quotienting of finite multi-table structures;
4. bit-sliced parallel search over canonical quotient models;
5. SAT-native quotient-state representations rather than pairwise Ackermann
   clauses or equality e-graphs;
6. proof-complexity-triggered migration of individual components between
   representations.
7. orbit-quotiented forbidden-table automata for classification formulas that
   enumerate complete anti-model tables.

The first mechanism can return only a separately validated SAT model. The
finite and quotient engines may return UNSAT only after an exact search with a
checkable coverage/refutation witness.

## Victory Conditions

Let $T_s$ be timeout-charged total time for solver $s$, and let

$$
G_{v,s}=\exp\left(\frac{1}{|C|}\sum_{i\in C}
\log\frac{t_{s,i}}{t_{v,i}}\right)
$$

be euf-viper's geometric speed on common solves. A superiority result requires
zero wrong answers, complete or strictly leading coverage,
$T_s/T_v\geq1.05$, common-total speed at least `1.05x`, and
$G_{v,s}\geq1.02` against both Z3 and Yices2. It must reproduce at 2, 60, and
1,200 seconds, on AMD and Intel nodes, twice, and on held-out data.

Current acceptance floors against Yices2 are:

| Budget | Required coverage | Maximum total |
| --- | ---: | ---: |
| 2s | 7,435 | 711.51s |
| 60s | 7,501 | 1,242.16s |
| 1,200s | 7,503 | 1,909.50s |

These are floors, not projected results.

## Experimental Order

Correctness repair precedes all timing. Each mechanism then passes shadow
telemetry, exhaustive reference checks, a frozen structural target, sample-40,
hot-400, hard-tail, and complete-corpus gates. Mechanisms are tested alone
before pairwise factorial experiments. No runtime selector may use paths,
families, expected statuses, hashes, or historical timing.

The full research contract and mechanism specifications are maintained in the
dated design and literature notes in the repository knowledge vault.

## Current Experimental Checkpoint

The first full census rejects the two fixed complete-model scouts: they
validate only four of 3,142 SAT formulas. Theory-conditioned Boolean quotient
opportunity is broader but modest in aggregate: 4,058 formulas change, 668,507
unique nodes disappear, and 1,200 formulas lose at least 10% of their nodes.
The first production leaf projection passes differential tests but fails its
timing gate, so quotient percentage alone is not a routing criterion.

Inline clause storage passes independent 80- and 320-instance timing gates,
reduces paired RSS, and then passes every full-corpus timing confidence bound.
It is still rejected: one baseline-only instance and net -1 repeat coverage
violate the quality contract. A structural router preserves coverage but keeps
only 1.00006x all-total speed, too little to justify the mechanism.

The finite-structure track now has a hardened qg7 population count. Of 418
files, 164 satisfy the final exact-cover eligibility checks. The degree-7
Algorithm-X implementation returns abstract SAT on all 164 and no abstract
UNSAT result. It is rejected as an UNSAT engine. The source audit now requires
an assertion ledger that consumes every predicate or abstains; checked local
cycle constraints reduce anti-idempotent column candidates from 5,040 to 240.

The unconditional leaf quotient is also split by evidence. Uniform activation
gains eight Goel solves but regresses the median. A frozen semantic selector,
canonical unique Boolean-node reduction at least 1,000, identifies 32 formulas
where the route improves 30 -> 32 solves and passes all 60-second timing bounds.
Against external solvers it covers more than Z3 and cvc5 on this slice, but
Yices2 solves all 32 and is 23.11x faster geometrically on common cases. The
auto route remains default-off pending full-corpus non-regression.

The parser track is moving beyond borrowed atoms. The active candidate parses
events directly into the retained semantic IR, with the existing tree parser
as both fallback and shadow oracle. WMI soundness and independent adversarial
review pass; a parse-only 7,503-file shadow campaign remains mandatory before
timing. This is a systems mechanism, not the claimed solver novelty, but
Yices2 cannot be challenged while two temporary syntax representations
dominate large easy inputs.
