# WMI QF_UF Full-Corpus Campaign 139154

Date: 2026-07-08

Status: failed during solver setup; no benchmark rows ran.

Purpose: attempted run of the complete SMT-LIB 2025 non-incremental QF_UF
corpus through `euf-viper`, native Z3 4.16.0, and cvc5 1.3.4 under one fixed
triage budget.

Input state:

- Git HEAD: `ace3e19b5d31d5cbce1d1911c6ce90070513f562`
- Dirty worktree patch SHA-256:
  `a696c6de82b7270f82f863ea6c3a9c65461f3066d56c2a680dc7dfbe3fd4be28`
- Corpus manifest: `benchmarks/smtlib-2025/qf_uf_manifest.jsonl`
- Instances: `7503`
- Expected statuses: `4361 unsat`, `3142 sat`

SLURM submission:

- Job ID: `139154`
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

Reproducibility and failure handling:

- The attempted Z3 source build used tag `z3-4.16.0`, pinned to commit
  `ddb49568d3520e99799e364fb22f35fc67d887b1`.
- Raw CSV rows are line-buffered as solver runs finish.
- `qf-uf-corpus-139154.progress.json` is atomically checkpointed.
- Re-execution with the same job output resumes completed solver-instance
  pairs rather than duplicating them.
- Correctness is checked against both the manifest status and decisive
  cross-solver results.

Failure:

- SLURM state: `FAILED`
- Elapsed: `00:09:24`
- Exit code: `2:0`
- MaxRSS: `3259340K`
- WMI's default GCC 11.4/libstdc++ does not provide the C++20 `<format>`
  header required by Z3 4.16.0.
- The job stopped in solver installation before creating a corpus CSV or
  progress checkpoint.
- Native-library smoke job `139157` validated the replacement setup; the full
  retry is job `139158`.

Expected remote artifacts:

- `results/qf-uf-corpus-139154.csv`
- `results/qf-uf-corpus-139154.json`
- `results/qf-uf-corpus-139154.progress.json`
- `results/wmi-corpus-139154.out`
- `results/wmi-corpus-139154.err`
- `results/solvers-139154.log`
- `results/qf-uf-fetch-139154.log`
