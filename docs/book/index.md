# euf-viper

`euf-viper` is a Rust EUF verifier and benchmark campaign scaffold.

The current implementation supports ground Boolean QF_UF through Tseitin CNF,
multiple SAT backends, eager finite-domain and congruence axioms, and a
congruence-closure model validator with lazy theory-lemma fallback.

```{admonition} Current Status
:class: note
At a two-second budget on 7,503 SMT-LIB 2025 QF_UF instances, `euf-viper` has
the lowest median latency but lower coverage than Z3 and cvc5. The project is
therefore positioned as a fast-head, certifying portfolio tier while Yices2,
long-timeout, and proof-certificate experiments are completed.
```
