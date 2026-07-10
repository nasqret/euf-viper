# Soundness Status

```{admonition} Critical defect
:class: warning
The accepted binary is not currently sound for every parser-supported QF_UF
formula. It can return SAT when unasserted Boolean-valued terms occur only as
arguments to uninterpreted functions. Treat current benchmark numbers as
performance measurements on the exact checked corpus, not as a general
soundness result.
```

## Boolean Values Used As Data

Consider three Boolean constants $p,q,r$ and an uninterpreted function
$f : \mathbb{B} \to U$. The formula

$$
\operatorname{distinct}(f(p), f(q), f(r))
$$

is unsatisfiable. Distinct outputs imply distinct inputs, while the Boolean
carrier $\mathbb{B}=\{\mathit{false},\mathit{true}\}$ contains only two
values.

The current materialization path does not necessarily create SAT atoms for
Boolean terms used only as function arguments. Complete-model validation then
misses their finite Boolean-domain semantics and can accept an invalid EUF
model. The regression fixture is
`tests/fixtures/bool_data_pigeonhole_unsat.smt2`.

## Repair Contract

The solver may return SAT only after all theory-relevant Boolean terms have a
total true-or-false assignment and the resulting model passes congruence
closure. A missing SAT assignment or backend `DontCare` value must be handled
explicitly; silently ignoring it is forbidden.

The repair must pass:

1. backend-specific regressions for eager, refining, and fallback paths;
2. generated small-formula differential tests against Z3 and cvc5;
3. exact WMI sample, hot, hard-tail, and full-corpus gates with zero wrong
   answers or execution errors.

Until those gates pass, performance work remains experimental and no global
soundness or solver-superiority claim is allowed.
