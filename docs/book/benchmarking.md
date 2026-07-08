# Benchmarking

Superiority over Z3 requires a reproducible benchmark protocol.

Required metadata:

- benchmark corpus name and checksum;
- solver revisions;
- machine and SLURM allocation;
- timeout, memory limit, and parallelism;
- raw per-instance results;
- discrepancy audit.

The local synthetic benchmark is:

```bash
cargo run --release -- bench --cases 20 --size 10000
```

The comparator harness is:

```bash
python3 benches/compare_z3.py path/to/QF_UF --viper target/release/euf-viper
```

For local timing with less process cold-start noise:

```bash
python3 benches/compare_z3_repeat.py generated/or-stress \
  --viper target/release/euf-viper \
  --timeout 30 --repeats 5 --warmups 1
```

## Local Canary

The first local canary compared Z3 4.16.0 against generated conjunction-heavy
inputs after warm-up.  `euf-viper` was faster on those inputs.  One positive
disjunction fixture was intentionally reported as unsupported, while an
equational-diamond `or` fixture was proved unsat through common branch
consequences.

See `research-vault/06-results/2026-07-08-local-canary.md` in the repository
root for the raw table.

The branch-aware `or` preprocessor produced stronger local evidence on
OR-stress canaries: 18.8x and 64.4x median speedups on diamond instances, and
1.7x on a pruned-branch instance, all against Z3 4.16.0.  This remains targeted
evidence, not SMT-COMP coverage.
