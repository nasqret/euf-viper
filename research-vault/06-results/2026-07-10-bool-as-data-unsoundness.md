# Boolean-As-Data Soundness Defect

Date: 2026-07-10

Status: confirmed critical defect. General soundness claims are revoked until
the repair passes differential and corpus gates.

## Minimal Counterexample

```smt2
(set-logic QF_UF)
(declare-sort U 0)
(declare-fun p () Bool)
(declare-fun q () Bool)
(declare-fun r () Bool)
(declare-fun f (Bool) U)
(assert (distinct (f p) (f q) (f r)))
(check-sat)
```

The Boolean carrier has exactly two values. Three pairwise-distinct images of
the three arguments require the arguments themselves to be pairwise distinct,
which is impossible. The formula is therefore UNSAT.

The fixture is
`tests/fixtures/bool_data_pigeonhole_unsat.smt2`.

## Reproduction

The current local release binary, SHA-256
`78002c042fca258443da75bb35a57ba90f6ac4ab6edc24caf7ca044cf010852c`,
returns `sat`. Local Z3 and cvc5 1.3.4 both return `unsat`.

The exact accepted WMI binary from source `58efe9d`, SHA-256
`4d5431135c95a2c528d287efd2803eaf895a5ec526c9642a570797b02fd47eb7`,
also returns `sat`; WMI Z3 and cvc5 return `unsat`. This is not a regression
introduced by the current rejected parser experiment.

## Root Cause

`materialize_bool_expr` can turn a Boolean term used as a function argument
into a term without allocating a `BoolTerm` CNF atom. Theory validation walks
only `CnfProblem.var_atoms`. Thus `p`, `q`, and `r` above are treated as three
unconstrained EUF-domain terms instead of values in the two-element Boolean
carrier.

A second completeness hazard exists at the SAT boundary: CaDiCaL `DontCare`
values are mapped to zero and the validator ignores zero assignments. A
theory-relevant atom must never be silently omitted from model validation.

## Impact

- The 7,503-instance SMT-LIB campaign remains valid as a performance result on
  that exact corpus because it recorded no answer mismatches.
- It is not evidence of general solver soundness.
- The accepted binary must not be described as sound for the full
  parser-supported QF_UF fragment.
- Performance candidates, including lazy-first refinement and the deep-let
  route, cannot be promoted on top of this defect.

## Required Repair Gate

1. Atomize every Boolean-valued term that can occur as data before CNF
   variables are frozen.
2. Extract a total assignment for every theory-relevant atom; an incomplete or
   `DontCare` assignment must be completed with a proved-safe rule or cause
   abstention and fallback.
3. Validate assignment length and fail closed.
4. Add backend-specific regression tests for eager CaDiCaL, refinement, and
   Varisat paths, including unasserted Boolean arguments.
5. Differential-test generated small Boolean-as-data formulas against Z3 and
   cvc5.
6. Run targeted WMI soundness tests, then the sample, hot, hard-tail, and full
   7,503-instance paired gates before restoring any soundness claim.

The source repair starts only after the rejected commit `5f67b6f` is reverted,
so the fix is based on the accepted `58efe9d` lineage.
