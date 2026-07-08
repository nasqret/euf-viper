# Benchmarking

Superiority over Z3 requires a reproducible benchmark protocol.

Required metadata:

- benchmark corpus name and checksum;
- solver revisions;
- machine and SLURM allocation;
- timeout, memory limit, and parallelism;
- raw per-instance results;
- discrepancy audit.

## Official Corpus

The benchmark ingestion script targets the SMT-LIB 2025 non-incremental
benchmark release on Zenodo.  The QF_UF slice is `QF_UF.tar.zst`, MD5
`e185bc80a80116bcfea116df190f87d2`, from DOI `10.5281/zenodo.16740866`.

```bash
scripts/bench/fetch_smtlib_qf_uf.sh
scripts/bench/sample_manifest.py benchmarks/smtlib-2025/qf_uf_manifest.jsonl \
  --limit 40 \
  --seed euf-viper-qf-uf-wmi-20260708 \
  --out benchmarks/smtlib-2025/qf_uf_sample40.jsonl
```

Downloaded corpora and manifests are ignored because manifests contain
machine-local absolute paths.

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

The WMI corpus campaign `139149` ran a 40-instance deterministic sample from
the official QF_UF corpus with `euf-viper`, Z3Py 4.16.0, and cvc5 1.3.4.  Z3
and cvc5 agreed on all non-timeout results; `euf-viper` solved one official
`eq_diamond` instance and explicitly returned `unsupported` on the rest.
