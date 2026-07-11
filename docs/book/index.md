# euf-viper

`euf-viper` is a Rust EUF verifier and benchmark campaign scaffold.

The current implementation supports ground Boolean QF_UF through Tseitin CNF,
multiple SAT backends, eager finite-domain and congruence axioms, and a
congruence-closure model validator with lazy theory-lemma fallback.

```{admonition} Current Status
:class: warning
At a two-second budget on 7,503 SMT-LIB 2025 QF_UF instances, `euf-viper` is
faster than Z3 on most jointly solved inputs but has lower coverage. Yices2 is
both faster and substantially more complete than the current implementation.
The exact 1,200-second campaign solves 7,502 instances, versus 7,500 for Z3 and
7,503 for Yices2. It narrowly beats Z3's timeout-charged total on this corpus,
but remains about 4.27x slower than Yices2. A critical Boolean-as-data
counterexample also shows that the measured binary is not sound for every
parser-supported input. Broad soundness and superiority claims are suspended
until repaired commit `53c12f7` passes all correctness and performance gates.
```
