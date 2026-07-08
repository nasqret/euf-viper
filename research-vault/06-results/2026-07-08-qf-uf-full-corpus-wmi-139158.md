# WMI QF_UF Full-Corpus Campaign 139158

Date: 2026-07-08

Status: completed successfully.

Purpose: run the complete SMT-LIB 2025 non-incremental QF_UF corpus through
`euf-viper`, Z3 4.16.0, and cvc5 1.3.4 under one fixed triage budget.

Input state:

- Git HEAD: `ace3e19b5d31d5cbce1d1911c6ce90070513f562`
- Dirty worktree patch SHA-256:
  `5d8cda0e8f037c991490a6a58cfb3c06b081b04b39db627e3a7fe6b24281c216`
- Corpus manifest: `benchmarks/smtlib-2025/qf_uf_manifest.jsonl`
- Instances: `7503`
- Expected statuses: `4361 unsat`, `3142 sat`

SLURM submission:

- Job ID: `139158`
- Job name: `euf-viper-qfuf`
- Partition: `cpu_idle`
- Request: `8 CPUs`, `32 GiB`, `04:00:00`
- Per-solver timeout: `2 seconds`
- Parallel solver processes: `8`
- Corpus limit: `0` (all instances)

Command:

```bash
EUF_VIPER_CORPUS_LIMIT=0 \
EUF_VIPER_CORPUS_TIMEOUT=2 \
EUF_VIPER_CORPUS_JOBS=8 \
bash scripts/wmi/sync_and_submit_corpus.sh
```

Solver identity:

- `euf-viper`: release build from the input state above.
- Z3: native ELF C-API runner linked to the official `z3-solver 4.16.0.0`
  package's `libz3.so.4.16`; no Python interpreter is launched per instance.
- Z3 runner SHA-256:
  `fbaf97b6b6df7792a0c7413fde9c56f1c0a2b28a1b9e27e10690262c4d251ffc`
- `libz3.so.4.16` SHA-256:
  `7d8507589c3f5cd194c156d70bfcdc935a713784f7df36553c8f0b8d22347fc8`
- cvc5: official static 1.3.4 release binary.
- Smoke gate: job `139157`, `COMPLETED`, `00:00:37`, two of two instances
  correct for all three solvers.

Failure handling:

- Raw CSV rows are line-buffered as solver runs finish.
- `qf-uf-corpus-139158.progress.json` is atomically checkpointed.
- Re-execution with the same output resumes completed solver-instance pairs.
- Correctness is checked against both the manifest status and decisive
  cross-solver results.

Results:

| Solver | Correct | Coverage | Timeout | Unsupported | Median | Total |
|---|---:|---:|---:|---:|---:|---:|
| euf-viper | 6276 | 83.65% | 1147 | 80 | 0.1126s | 4069.52s |
| Z3 4.16.0 | 6910 | 92.10% | 593 | 0 | 0.1676s | 3469.18s |
| cvc5 1.3.4 | 6513 | 86.81% | 990 | 0 | 0.2939s | 4881.33s |

All decisive answers matched the manifest; there were zero wrong answers and
no cross-solver SAT/UNSAT disagreement. The result establishes a lower-latency
head for `euf-viper`, but not a coverage or aggregate-time win over Z3.

Fetched artifacts:

- `results/qf-uf-corpus-139158.csv`
- `results/qf-uf-corpus-139158.json`
- `results/qf-uf-corpus-139158.progress.json`
- `results/wmi-corpus-139158.out`
- `results/wmi-corpus-139158.err`
- `results/solvers-139158.log`
- `results/qf-uf-fetch-139158.log`
