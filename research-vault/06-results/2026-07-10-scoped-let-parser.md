# Scoped Let Parser Optimization

Date: 2026-07-10

Status: implementation and targeted gate passed; full-corpus decision gate
`142745`/`142750` is running.

## Problem

The parser cloned the complete binding `HashMap` at every nested SMT-LIB
`let`. `NEQ027_size11.smt2` contains 2,069 nested lets and caused roughly
eleven million copied bindings. This is frontend work, independent of SAT or
EUF proof search.

## Implementation

- Commit: `b9ce3ec`.
- Baseline binary SHA-256:
  `809132aab91847840ebf3f38ce1776e2d1daa0f45bdfa211c07ca6e80e904f31`.
- Candidate binary SHA-256:
  `e5bae5db3fcf68b671edb3f99d8415ddc86e66237c6a2b00b725a976b1b2f001`.

Bindings are parsed under the pre-let environment, installed in place, and
restored in reverse order by an RAII scope. This preserves SMT-LIB simultaneous
RHS semantics, nested shadowing, and restoration on errors. The intentional
branch-local clone in positive-`or` analysis remains unchanged.

## Results

Seven-repeat WMI gate `142743` used identical solver settings and changed only
the binary:

| Instance | Baseline median | Candidate median | Speedup |
| --- | ---: | ---: | ---: |
| `NEQ027_size10.smt2` | 1.216s | 0.240s | 5.066x |
| `NEQ027_size11.smt2` | 2.017s | 0.334s | 6.041x |
| Aggregate | 3.232s | 0.574s | 5.634x |

Coverage remained 2/2, geometric speedup was 5.532x, and there were no wrong
answers or execution errors.

The 40-case no-regression gate `142744` remained 40/40 but was within noise on
the wrong side of the strict speed threshold: 0.998x total and 0.995x
geometric. Therefore the targeted result alone is not a promotion.

## Artifacts

- `results/wmi/scoped-let-neq027-142743/`.
- `results/wmi/scoped-let-sample40-142744/`.
- Full gate, when complete: `results/wmi/scoped-let-full-142745/`.

## Decision

Keep the implementation while full gate `142745` runs. Accept it only if the
complete paired corpus has no coverage loss and all three speed metrics are at
least 1.0. Otherwise retain the code only behind a structural parser route or
revert it in a follow-up commit.
