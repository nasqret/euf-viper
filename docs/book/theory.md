# Theory

The target theory is equality with uninterpreted functions (EUF).  SMT-LIB
`QF_UF` is the quantifier-free logic over Core with free sort and function
symbols.

```{admonition} Definition
:class: definition
Given ground terms built from constants and uninterpreted function symbols,
the congruence closure of a set of equalities is the smallest equivalence
relation that contains those equalities and satisfies:

$$
a_i \equiv b_i\ \text{for all } i
\quad\Longrightarrow\quad
f(a_1,\ldots,a_n) \equiv f(b_1,\ldots,b_n).
$$
```

An EUF conjunction is unsatisfiable exactly when some asserted disequality
`s != t` has `s` and `t` in the same congruence class.

## Sources

- SMT-LIB QF_UF: https://smt-lib.org/logics-all.shtml#QF_UF
- LLM2SMT case study: https://arxiv.org/abs/2603.06931
- Proof-producing congruence closure: https://arxiv.org/abs/1701.04391
- Proof-size work: https://arxiv.org/abs/2209.03398
