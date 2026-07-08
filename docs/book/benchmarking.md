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

Yices 2.7.0 is installed from the official `yices-2.7.0` GitHub release. The
Linux x86_64 static-GMP archive is pinned by SHA-256
`49566b6f817692820538df78fe406878400d79810631c9372b2495bc81d3e00a`.
Four-solver WMI smoke `139380` passed before the first full Yices campaign.

Full four-solver campaign `139381` then completed the corpus at two seconds:

| Solver | Correct | Coverage | Median time | Total time |
|---|---:|---:|---:|---:|
| euf-viper | 6,471 | 86.25% | 0.0886s | 3,668.11s |
| Z3 4.16.0 | 6,911 | 92.11% | 0.1705s | 3,494.35s |
| cvc5 1.3.4 | 6,505 | 86.70% | 0.2956s | 4,909.17s |
| Yices 2.7.0 | 7,394 | 98.55% | 0.0450s | 1,169.43s |

All 30,012 solver-instance rows completed with no wrong answers, execution
errors, or decisive disagreements. `euf-viper` beat Z3 on 5,428/6,437 jointly
correct instances, but Yices beat `euf-viper` on 6,166/6,463. This result
rejects a broad fastest-solver claim.

QG-classification contributes 6,396 instances (85.24%). `euf-viper` covered
86.18% of QG and 86.63% of non-QG; Yices covered 98.91% and 96.48%
respectively. The 60-second and competition-budget runs retain both strata.

Long-timeout runs use `sync_and_submit_sharded_corpus.sh`. Its prepare job
creates an immutable campaign manifest, array tasks assign rows by manifest
offset modulo the shard count, and the dependent merge checks that every
manifest-path and solver pair occurs exactly once before producing aggregate
tables. The submission script refuses a dirty worktree so every campaign is
tied to a committed solver revision.

The dependency-chain smoke used prepare job `139382`, two array tasks under
`139383`, and merge job `139384`. All stages completed. The merged eight-row
sample had zero wrong answers, disagreements, missing rows, and execution
errors; all four solvers covered 7/8 within two seconds.

## Sixty-Second Campaign

The full continuation at 60 seconds used prepare job `139420`, 64 array shards
under `139421` with at most four active allocations, and strict merge job
`139422`. Revision `9c7789339587a75014f5438125f96a6e7a3a739e` produced all
30,012 expected rows with zero wrong answers, disagreements, or execution
errors.

| Solver | Correct | Coverage | Median time | Total time |
|---|---:|---:|---:|---:|
| euf-viper | 7,434 | 99.08% | 0.0666s | 10,082.63s |
| Z3 4.16.0 | 7,486 | 99.77% | 0.1426s | 5,024.91s |
| cvc5 1.3.4 | 7,471 | 99.57% | 0.2293s | 9,694.51s |
| Yices 2.7.0 | 7,500 | 99.96% | 0.0278s | 1,640.91s |

QG-classification accounts for 6,396 instances. On that stratum, `euf-viper`
covered 6,383 and Yices covered all 6,396. On the 1,107 non-QG instances,
coverage was 1,051 and 1,104 respectively. The all-solver oracle leaves only
three expected-UNSAT PEQ instances unresolved.

Competition-budget continuation uses `--resume-from` with
`--retry-result timeout` and, after a solver change, `--retry-solver`. It writes
a new result CSV containing only revision-compatible retained observations plus
new measurements, so the 60-second campaign remains unchanged and the strict
merge still validates a complete matrix. For a new `euf-viper` revision, the
campaign retains 22,457 comparator rows and measures 7,555 rows.

## Competition-Budget Campaign

Revision `1f68ff1cb5f1c9ee951f181a6127427b2e6d3044` ran under prepare job
`139688`, 64-shard array `139689`, and strict merge `139690`. The timeout was
1,200 seconds, at most four allocations were active, and each shard used eight
worker processes. All 30,012 rows completed without wrong answers,
disagreements, or execution errors.

| Solver | Correct | Coverage | Median time | Total time |
|---|---:|---:|---:|---:|
| euf-viper | 7,478 | 99.67% | 0.0910s | 50,674.22s |
| Z3 4.16.0 | 7,500 | 99.96% | 0.1426s | 11,435.55s |
| cvc5 1.3.4 | 7,491 | 99.84% | 0.2293s | 27,875.21s |
| Yices 2.7.0 | 7,503 | 100.00% | 0.0278s | 2,652.64s |

The run retained successful comparator rows from the 60-second campaign and
reran only their 52 timeouts. Every `euf-viper` row was rerun because its
revision changed. On common `euf-viper`/Z3 solves the geometric speedup is
1.069x, but aggregate common time is 20,668.55s versus 5,365.05s. Yices covers
the complete corpus and is fastest on 6,821 instances. This supports a
fast-head front tier, not an overall superiority claim.
