# Benchmarking

Comparisons against Z3, cvc5, and Yices2 require a reproducible benchmark
protocol.

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

The initial WMI sample `139149` exposed the missing Boolean layer. After the
SAT/EUF implementation landed, full campaign `139158` completed all 7,503
instances at two seconds per solver:

| Solver | Correct | Coverage | Median time | Total time |
|---|---:|---:|---:|---:|
| euf-viper | 6276 | 83.65% | 0.1126s | 4069.52s |
| Z3 4.16.0 | 6910 | 92.10% | 0.1676s | 3469.18s |
| cvc5 1.3.4 | 6513 | 86.81% | 0.2939s | 4881.33s |

All decisive answers matched the manifest. The result establishes a fast
median, not an overall win. Accepted smoke `139229` subsequently reached 37/40
and improved common-instance aggregate time by 1.0848x over `139211`.

The next protocol revision adds pinned Yices 2.7.0 and repeats the full corpus
at 60 seconds and competition-style budgets. Family-stratified reporting is
required because QG-classification dominates the corpus.

Yices 2.7.0 is installed from the official `yices-2.7.0` GitHub release. The
Linux x86_64 static-GMP archive is pinned by SHA-256
`49566b6f817692820538df78fe406878400d79810631c9372b2495bc81d3e00a`.
Four-solver WMI smoke `139380` passed before the first full Yices campaign.

Long-timeout runs use `sync_and_submit_sharded_corpus.sh`. Its prepare job
creates an immutable campaign manifest, array tasks assign rows by manifest
offset modulo the shard count, and the dependent merge checks that every
manifest-path and solver pair occurs exactly once before producing aggregate
tables. The submission script refuses a dirty worktree so every campaign is
tied to a committed solver revision.
