# Scoped Let Parser Optimization

Date: 2026-07-10

Status: targeted optimization passed, but unconditional activation failed the
full-corpus gate. A structural `auto` route for deep-let inputs is under test.

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

The complete 7,503-instance gate `142745`/`142750` rejected unconditional
activation:

| Metric | Baseline | Candidate / ratio |
| --- | ---: | ---: |
| Correct | 6,852 | 6,851 |
| All-total speed | - | 1.0023x |
| Common-total speed | - | 1.0016x |
| Geometric speed | - | 0.9963x |

The candidate-only solves had 852, 1,140, and 1,243 lexical `let` occurrences.
The four baseline-only solves had only 4, 5, 15, and 28. A prospective route
therefore retains the original cloned parser below 512 lexical occurrences and
uses scoped restoration at or above 512. That threshold was selected from the
complete gate before measuring the routed binary.

## Artifacts

- `results/wmi/scoped-let-neq027-142743/`.
- `results/wmi/scoped-let-sample40-142744/`.
- Full gate: `results/wmi/scoped-let-full-142745/`.

## Decision

Reject unconditional activation. Keep the scoped implementation behind
`EUF_VIPER_SCOPED_LET=off|auto|on`; promote `auto` only if targeted, sample,
hot, and complete paired gates preserve coverage and keep all three speed
metrics at least 1.0.
