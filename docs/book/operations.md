# Operations

## WMI

Run a live preflight:

```bash
bash scripts/wmi/preflight.sh
```

Submit the synthetic campaign after Rust is available on WMI:

```bash
bash scripts/wmi/sync_and_submit.sh
```

Submit the fixed QF_UF corpus campaign:

```bash
EUF_VIPER_CORPUS_LIMIT=40 \
EUF_VIPER_CORPUS_TIMEOUT=10 \
EUF_VIPER_CORPUS_SEED=euf-viper-qf-uf-wmi-20260708 \
bash scripts/wmi/sync_and_submit_corpus.sh
```

Submit a restartable long-timeout campaign. The default is 64 shards with at
most four active array tasks. A prepare job pins one campaign manifest; a merge
job runs only after every shard succeeds and rejects incomplete result sets.

```bash
EUF_VIPER_CORPUS_LIMIT=0 \
EUF_VIPER_CORPUS_TIMEOUT=60 \
EUF_VIPER_CORPUS_SHARDS=64 \
EUF_VIPER_CORPUS_MAX_ACTIVE=4 \
EUF_VIPER_CORPUS_JOBS=8 \
bash scripts/wmi/sync_and_submit_sharded_corpus.sh
```

Use a bounded sample to smoke-test the complete prepare-array-merge dependency
chain in an isolated remote checkout:

```bash
EUF_VIPER_CORPUS_LIMIT=8 \
EUF_VIPER_CORPUS_TIMEOUT=2 \
EUF_VIPER_CORPUS_SHARDS=2 \
EUF_VIPER_CORPUS_MAX_ACTIVE=2 \
EUF_VIPER_REMOTE='wmicluster:~/euf-viper-sharded-smoke' \
bash scripts/wmi/sync_and_submit_sharded_corpus.sh
```

## Certificates

Install the pinned DRAT checker when it is not already available:

```bash
scripts/cert/install_drat_trim.sh
```

Emit and check an UNSAT certificate:

```bash
cargo build --release --features certificates
target/release/euf-viper certify tests/fixtures/basic_unsat.smt2 \
  --out-prefix results/cert-basic
scripts/cert/check_certificate.py results/cert-basic.euf.json \
  --drat-trim third_party/checkers/bin/drat-trim
```

Run the complete certificate canary collection:

```bash
DRAT_TRIM=third_party/checkers/bin/drat-trim scripts/cert/run_smoke.sh
```

## LTS

Run CAS availability checks:

```bash
bash scripts/lts/preflight.sh
```

Run local CAS syntax/sanity checks where tools are installed:

```bash
bash scripts/lts/check_cas_local.sh
```

Run the Magma quotient artifact on LTS:

```bash
bash scripts/lts/run_magma_remote.sh
```

The local wrapper uses isolated temporary homes for Sage and Julia, with a
writable Julia depot layered before the existing package depot. A missing
Oscar package is reported explicitly; the Julia-only quotient assertions still
run. The remote Magma command uses `magma -n` to avoid user startup files.

Corpus workers write observations as futures complete, so one long-running
early task cannot block checkpoint progress from later tasks. A/B merge output
prints `n/a` when no common-correct timing population exists.

Select a stable timing band or a timeout slice from an existing result CSV:

```bash
scripts/bench/filter_manifest.py \
  benchmarks/smtlib-2025/qf_uf_manifest.jsonl \
  --result-csv results/qf-uf-corpus.csv \
  --solver euf-viper --time-at-least 0.1 --time-at-most 1.0 \
  --out results/qf-uf-stable.jsonl
```

The filter rejects negative or reversed bounds. A/B SLURM workers accept
`EUF_VIPER_BASELINE_AXIOM_ORDER` and `EUF_VIPER_CANDIDATE_AXIOM_ORDER`; record
both values with every campaign because axiom order changes SAT search. The
accepted `141911` gate used `native` for the frozen baseline and `sorted` for
the candidate, matching its CLI default.

Train the structural portfolio candidate from a complete result matrix:

```bash
scripts/bench/train_structural_router.py \
  benchmarks/smtlib-2025/qf_uf_manifest.jsonl \
  results/qf-uf-corpus.csv --out results/structural-router.json
```

Run the explicit Yices-dependent portfolio:

```bash
target/release/euf-viper portfolio \
  --yices third_party/solvers/bin/yices-smt2 input.smt2
```

## T5 Component-Quotient Census

T5 is Linux-only and remains disabled until hosted Linux CI and independent
review pass. Submission creates a unique remote namespace and an explicitly
pending receipt; it does not make a performance or implementation decision.

The full local integration gate is opt-in because it needs the extracted
external corpus and Slurm client binaries. On Linux, from a clean committed
checkout, run:

```bash
EUF_VIPER_T5_E2E_CORPUS=/absolute/path/to/benchmarks/smtlib-2025 \
  python3 -B -m unittest -v tests.test_t5_linux_end_to_end
```

Once the corpus variable is supplied, a missing `/usr/bin/scontrol`,
`/usr/bin/sacct`, exact 7,503-row manifest, procfs semantic, `O_TMPFILE`, mount
inventory, or runtime identity is a failure, not a skip.

```bash
scripts/wmi/submit_component_quotient_census.sh
```

Publication requires unprivileged `O_TMPFILE` in the result filesystem and a
verified procfs `/proc/self/fd/<fd>` symlink linked with
`linkat(AT_SYMLINK_FOLLOW)`. It fails closed if procfs, those symlink semantics,
or the filesystem primitive is unavailable. The bundle records all Linux
capability sets; success does not imply that `CAP_DAC_READ_SEARCH` was present.
After the SLURM job finishes, run the consumer on WMI with the exact pending
receipt and revision checkout:

```bash
python3 -I -B -S scripts/bench/verify_component_quotient_publication.py \
  --submission-receipt /absolute/attempt/results/submission.json \
  --repository-root /absolute/attempt
```

Do not consume `.current` directly. Authority requires scheduler status
`COMPLETED 0:0`, successful consumer exit, fresh no-follow archive and marker
rehashes, exact revision-blob checks, and independent reconstruction from the
captured source members. The consumer also reconstructs complete record and
aggregate bytes, not only promotion fields. Its receipt binds the original
`sbatch --parsable` job/cluster pair and the root `sacct` SLUID, cluster, submit
time, job name, user, workdir, state, and exit code. Stale attempt files and
immutable orphans are expected after failures and must not be deleted by
campaign wrappers.
