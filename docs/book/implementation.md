# Implementation

The current pipeline keeps each soundness boundary explicit.

1. Parse SMT-LIB S-expressions.
2. Hash-cons data and Boolean application terms.
3. Tseitin-encode arbitrary ground Boolean structure.
4. Detect small explicit finite domains and add sound one-hot and function
   channeling clauses where applicable.
5. Add selected equality-transitivity and congruence axioms.
6. Solve with Kissat, CaDiCaL, or Varisat according to structural routing.
7. Trust UNSAT from the sound clause set; validate SAT models with full EUF
   congruence closure.
8. If validation finds a theory conflict, add explanation clauses and refine.

The parser also retains a narrowly gated branch-intersection preprocessor for
single-assertion equational diamonds. Finite predicate-table channeling exists
as an experimental flag, but remains disabled after failing its WMI hard-tail
gate.
