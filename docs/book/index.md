# euf-viper

`euf-viper` is a Rust EUF verifier and benchmark campaign scaffold.

The current implementation supports ground Boolean QF_UF through Tseitin CNF,
multiple SAT backends, eager finite-domain and congruence axioms, and a
congruence-closure model validator with lazy theory-lemma fallback.

```{admonition} Current Status
:class: note
At a two-second budget on 7,503 SMT-LIB 2025 QF_UF instances, `euf-viper` is
faster than Z3 on most jointly solved inputs but has lower coverage. Yices2 is
both faster and substantially more complete than the current implementation.
The 2026-07-09 dynamic Ackermann iteration improves the preceding standalone
binary by nine solves and passes all full-corpus paired speed gates, but has not
yet been rerun against the external solvers at long timeout. The project is
therefore positioned as a certifying portfolio tier while long-timeout
experiments quantify the remaining niche.
```
