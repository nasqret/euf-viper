# Quotient-JIT finite-family campaign - 2026-07-26

## Scope

This campaign evaluates a standalone Rust QF_UF portfolio at a two-second
cold-process limit. Runtime policy may use only source-formula structure. It
may not use source path, benchmark family/name, content hash, expected status,
or prior runtime. SAT/UNSAT outputs are checked by the existing strict harness;
any wrong answer or process error fails the stage.

The full-family rows use one timing repetition and are discovery scorecards,
not final publication timing. The micro gates use paired repeated schedules.

## Integrated mechanisms

1. Checker-owned root-unit materialization for reduced Fabric CNF.
2. Exact multi-operation rook recognition.
3. Verified finite structural eager routing with domain and CNF-pressure caps.
4. Predicate congruence channeling bounded by Boolean-application pressure.
5. Lex symmetry from domain seven and a narrow source-structural CaDiCaL hint.
6. Focused permutation support: dual value support only after proving a finite
   injection over the complete domain.

Predicate routing is admitted only when all non-Boolean terms are in a verified
finite closure, the domain is in `3..=11`, estimated one-hot clauses are at
most 200,000, Boolean applications are at most 16,384, and the product of
Boolean applications and domain size is at most 100,000.

## Complete family matrix

Coverage and common-correct aggregate speedup of Viper over each comparator:

| Family | Viper | Yices2 | Z3 | cvc5 | Yices2 factor | Z3 factor | cvc5 factor |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| PEQ | 44/47 | 40/47 | 34/47 | 28/47 | `0.851x` | `1.937x` | `5.407x` |
| SEQ | 56/56 | 56/56 | 51/56 | 46/56 | `0.490x` | `0.967x` | `4.710x` |
| NEQ | 48/48 | 44/48 | 41/48 | 39/48 | `2.948x` | `3.753x` | `6.388x` |

Common-correct geometric factors are:

| Family | Yices2 | Z3 | cvc5 |
| --- | ---: | ---: | ---: |
| PEQ | `0.560x` | `1.788x` | `5.579x` |
| SEQ | `0.536x` | `1.114x` | `3.889x` |
| NEQ | `1.504x` | `2.649x` | `6.396x` |

Primary ledgers:

- `fast-cycle/2026-07-26-peq-structural-support-{yices,z3,cvc5}/ledger.json`
- `fast-cycle/2026-07-26-seq-structural-support-{yices,z3,cvc5}/ledger.json`
- `fast-cycle/2026-07-26-neq-structural-support-{yices,z3,cvc5-rerun}/ledger.json`

## Causal result

The last SEQ miss, `SEQ009_size10`, has a verified 10-element domain, two
closed functions, a complete guarded all-different clique, and no Boolean
function applications. Focused permutation support adds implied column-support
clauses to the existing row constraints and disequalities. In five paired
repetitions it changed approximately `2.41s` to `0.013s`, a `183.9x` factor,
and converted the two-second timeout into UNSAT.

The same mechanism improves the complete SEQ panel from 55/56 to 56/56 and
the complete NEQ panel by `1.18x` against the immediate implementation control.
PEQ coverage is unchanged and its one-repeat aggregate effect is within 0.4%
of neutral. It is therefore enabled only on verified structural finite routes;
rook-specialized routing is unchanged and explicit mode `0` disables it.

## Frozen canaries

The default fast-cycle ledger
`fast-cycle/2026-07-26-core-after-structural-support/ledger.json` passes all
stages. QG7 is `1.018x` over Yices2, `3.829x` over Z3, and `8.977x` over cvc5.
The PEQ rook canary is `2.187x` over Yices2 and is uniquely solved at two
seconds against Z3 and cvc5. The representative triad preserves coverage.

Goel remains the principal timing deficit: the frozen `frogs.2` scorecard is
only `0.286x` as fast as Yices2. This prevents an overall-leader claim despite
the finite-family gains.

## Validation and remote gate

- Python: 540 tests passed.
- Rust all features: 643 passed, 10 intentionally ignored, zero failed.
- F0 WMI smoke `169653`: `COMPLETED 0:0`.
- Independent F0 audit: verified two rows, exact bindings, no errors, no
  duplicates, and zero solver-result claims.
- Clean public implementation: `8368d21de96eec77f3bb5f6820c11d1363d3041b`.
- Hosted Campaign contract: run `30207588244`, successful on the exact SHA.
- Fixed PGO/Goel holdout: WMI job `170902`, currently `PENDING` because
  eligible nodes are down, drained, or reserved.

The next valid evidence is the terminal PGO campaign marker and its frozen
adjudication, followed by fixed WMI family/full-corpus campaigns. Promotion
requires repeated timing, long timeouts, a second CPU class, and no coverage
or correctness regression. A queued job is not performance evidence.
