# euf-viper

`euf-viper` is a Rust EUF verifier and benchmark campaign scaffold.

The current implementation decides conjunctions of ground QF_UF literals by
congruence closure.  Boolean search is intentionally marked unsupported until a
DPLL(T) layer is added.

```{admonition} Current Status
:class: warning
The repository does not yet contain evidence that it beats Z3.  It contains
the engine, benchmark harness, cluster scripts, and acceptance gates needed to
produce such evidence without exaggeration.
```
