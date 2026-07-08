# 2026-07-08 Local Canary

Environment:

- macOS host, local release binary.
- `euf-viper` revision: initial local scaffold before first commit.
- Z3: `Z3 version 4.16.0 - 64 bit` installed via Homebrew.
- Timeout: 10 seconds per file.
- Harness: `python3 benches/compare_z3.py`.

Fixture results after warm-up:

| file | euf-viper | time | z3 | time |
|---|---:|---:|---:|---:|
| `tests/fixtures/basic_sat.smt2` | sat | 0.0028 | sat | 0.0049 |
| `tests/fixtures/basic_unsat.smt2` | unsat | 0.0024 | unsat | 0.0043 |
| `tests/fixtures/eq_diamond_unsat.smt2` | unsat | 0.0022 | unsat | 0.0040 |
| `tests/fixtures/unsupported_or.smt2` | unsupported | 0.0022 | sat | 0.0045 |

Synthetic results after warm-up:

| file | euf-viper | time | z3 | time |
|---|---:|---:|---:|---:|
| `generated/synthetic/chain1000_sat.smt2` | sat | 0.0029 | sat | 0.0064 |
| `generated/synthetic/chain1000_unsat.smt2` | unsat | 0.0030 | unsat | 0.0062 |
| `generated/synthetic/grid1000x8_unsat.smt2` | unsat | 0.0033 | unsat | 0.0057 |

Interpretation:

The current verifier is faster than Z3 on these synthetic conjunction-heavy
canaries, but this does not imply superiority on full QF_UF.  The positive
disjunction fixture is correctly rejected as unsupported and must wait for the
DPLL(T) milestone.

Cold-start process timings varied during the first run after installing Z3.
The table above uses the immediate warm rerun and should be treated only as a
local smoke benchmark.
