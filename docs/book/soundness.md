# Soundness Status

```{admonition} Candidate under acceptance testing
:class: warning
The historically measured `58efe9d` binary is not sound for every
parser-supported QF_UF formula. The current local candidate repairs the known
Boolean-data, quoted-symbol, and query-order failures, but it is not promoted
until the hash-pinned WMI differential, paired, and four-solver gates finish.
Treat old benchmark numbers as opportunity measurements on the exact checked
corpus, not as a general soundness result.
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

The historical materialization path did not necessarily create SAT atoms for
Boolean terms used only as function arguments. Complete-model validation then
missed their finite Boolean-domain semantics and could accept an invalid EUF
model. The repair atomizes all Boolean data terms and explicitly completes or
rejects every theory-relevant backend assignment. The permanent regression is
`tests/fixtures/bool_data_pigeonhole_unsat.smt2`.

## Quoted Reserved Symbols

SMT-LIB permits quoted user symbols whose text matches a reserved word. Thus
`|true|` and `|not|` are ordinary declared symbols, not the Boolean constant
and connective. The historical tokenizer discarded quotedness and could
therefore turn a satisfiable formula into UNSAT.

The repaired token and s-expression representations preserve quotedness for
syntax dispatch while retaining SMT symbol identity between `p` and `|p|`.
The permanent regressions are `tests/fixtures/quoted_true_sat.smt2` and
`tests/fixtures/quoted_not_sat.smt2`.

## Single-Query Ordering

The solver supports one non-incremental query. Historically, `check-sat` was a
no-op during parsing, so a later assertion could silently alter the answer to
an earlier query. The parser now permits read-only `get-model` and `get-value`
commands after the query, but rejects mutation, a repeated query, or commands
after `exit`. The fail-closed regression is
`tests/fixtures/early_check_sat_rejected.smt2`.

## Repair Contract

The solver may return SAT only after all theory-relevant Boolean terms have a
total true-or-false assignment and the resulting model passes congruence
closure. A missing SAT assignment or backend `DontCare` value must be handled
explicitly; silently ignoring it is forbidden.

The candidate must pass:

1. backend-specific regressions for eager, refining, and fallback paths;
2. generated small-formula differential tests against Z3 and cvc5;
3. exact WMI sample, hot, hard-tail, and full-corpus gates with zero wrong
   answers or execution errors.

Until those gates pass, performance work remains experimental and no global
soundness or solver-superiority claim is allowed.

## Current Evidence

- Local all-feature suite: 198 passed, three environment-gated probes ignored.
- Local benchmark-tool suite: 86 passed.
- Corrected WMI Boolean-data differential `143698`: 10,041 generated formulas,
  zero euf-viper discrepancies. One common timeout was retried by exact hash in
  `143728`; euf-viper, Z3, and cvc5 all returned UNSAT.
- Mandatory repair sample `143697`: unchanged 39/40 coverage, zero wrong
  answers or errors, but a small timing regression. It is correctness work,
  not a promoted optimization.
- Full repair A/B `143700`/`143701`, candidate soundness build `143747`, and
  fixed four-solver campaign `143752`/`143753` are pending or running.
