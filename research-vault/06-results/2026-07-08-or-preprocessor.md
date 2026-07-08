# 2026-07-08 OR Preprocessor Improvement

Change:

- Positive `or` handling now parses branch literals instead of only branch
  equalities.
- Same-level `and` formulas are processed in two phases, so surrounding
  disequalities are known before `or` analysis.
- If every branch is inconsistent with surrounding EUF literals, the verifier
  returns `unsat`.
- If some branches remain satisfiable, equalities common to all satisfiable
  branches are added as sound consequences.

Correctness boundary:

- This is still not full DPLL(T).
- If branch analysis cannot decide enough, the formula remains `unsupported`.

Local Z3 comparison:

Command:

```bash
python3 benches/compare_z3_repeat.py generated/or-stress \
  --viper target/release/euf-viper \
  --timeout 30 --repeats 5 --warmups 1 \
  --out results/or_stress_repeat_z3.csv
```

Z3: `Z3 version 4.16.0 - 64 bit`.

Median results:

| file | euf-viper median | Z3 median | speedup |
|---|---:|---:|---:|
| `diamond_b128_d8_unsat.smt2` | 0.003689s | 0.069376s | 18.8x |
| `diamond_b512_d4_unsat.smt2` | 0.004674s | 0.300872s | 64.4x |
| `pruned_or_b512_unsat.smt2` | 0.004012s | 0.006622s | 1.7x |

Larger single-point timing:

- `diamond 2048 4`: `euf-viper` solved in about 0.01s real time; Z3 solved in
  about 5.10s real time.
- `pruned-or 4096`: `euf-viper` solved in about 0.03s real time; Z3 solved in
  about 0.06s real time.

WMI job:

- Job ID: `139146`
- Partition: `cpu_idle`
- Node: `c3n1`
- State: `COMPLETED`
- Elapsed: `00:00:14`
- Exit code: `0:0`
- Synthetic bench: 8 cases, wall `277150166ns`
- OR bench: 8 cases, branches `1024`, depth `4`, wall `217220141ns`
- OR case timings:
  - diamond: about 26.9-37.4ms
  - pruned-or: about 19.2-19.4ms

Raw local/WMI logs are under ignored `results/` paths.
