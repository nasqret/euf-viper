# euf-viper

`euf-viper` is a Rust EUF verifier and benchmark campaign scaffold.

The current implementation supports ground Boolean QF_UF through Tseitin CNF,
multiple SAT backends, eager finite-domain and congruence axioms, and a
congruence-closure model validator with lazy theory-lemma fallback.

```{admonition} Current Status
:class: warning
At a two-second budget on 7,503 SMT-LIB 2025 QF_UF instances, `euf-viper` is
`1.5666x` faster geometrically than Z3 on 7,375 jointly solved inputs, but has
42 fewer solves and loses common aggregate time. It solves 7,408 instances,
versus 7,450 for Z3, 7,373 for cvc5, and 7,490 for Yices2. It beats cvc5
overall; Yices2 is both faster and more complete. Current exact campaign
`144328`/`144329`/`144330` has zero wrong answers or execution errors. These
results do not establish overall superiority over Z3 or Yices2.
```
