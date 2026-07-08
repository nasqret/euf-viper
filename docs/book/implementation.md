# Implementation

The first milestone is intentionally small and auditable.

1. Parse SMT-LIB S-expressions.
2. Collect ground equalities and disequalities from conjunctions.
3. Hash-cons all terms.
4. Merge asserted equalities with union-find.
5. Rebuild function-application signatures until no congruence merge remains.
6. Check each disequality against the final classes.

The implementation rejects positive Boolean structure such as `or` because
that requires a SAT layer.  The planned design is DPLL(T): Boolean abstraction,
SAT search, theory consistency checks, theory lemmas, and selected theory
propagation.

One safe exception is implemented for positive `or`: the parser computes branch
literals, prunes branches inconsistent with surrounding EUF literals, and adds
equalities common to the remaining satisfiable branches.  If every branch is
inconsistent, or if the common equalities contradict a disequality, the solver
can return `unsat`; otherwise the formula remains `unsupported`.
