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

On Linux x86_64, step 8 uses incremental CaDiCaL refinement by default after
an eager Kissat model is rejected. This is deliberately post-validation: eager
UNSAT and EUF-valid SAT paths are unchanged. Set
`EUF_VIPER_INVALID_MODEL_FALLBACK=varisat` to restore the previous fallback.
The default was promoted only after a targeted repeated profile, a repeated
40-instance control, and a 7,503-instance paired WMI gate.

The parser also retains a narrowly gated branch-intersection preprocessor for
single-assertion equational diamonds. Finite predicate-table channeling exists
as an experimental flag, but remains disabled after failing its WMI hard-tail
gate.

## UNSAT certificates

The opt-in `certificates` Cargo feature keeps proof dependencies and code out of
the benchmarked default binary. With that feature enabled, `certify` uses a
deliberately separate path. It emits the base Tseitin clauses,
equality-transitivity clauses, congruence clauses, and any EUF explanation
clauses needed to reach Boolean UNSAT. Finite-domain shortcuts are omitted in
certificate format v1. A fresh CaDiCaL instance then emits an ASCII DRAT proof
for that exact DIMACS file.

The manifest records every term, every SAT-variable interpretation, category
counts, and SHA-256 digests for the source, DIMACS, and proof. The checker first
runs `drat-trim`. For each non-base clause $C$, it then assumes $\neg C$, closes
the resulting equalities under congruence, and requires a disequality conflict.
This independently validates the SAT refutation and EUF axioms. The remaining
v1 trust boundary is reconstruction of the base Tseitin clauses from SMT-LIB.
