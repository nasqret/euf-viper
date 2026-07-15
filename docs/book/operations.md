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

T5 is Linux-only and remains disabled until the mandatory Linux diagnostic,
the separately provisioned semantic integration, and independent review pass.
Submission creates a unique remote namespace and an explicitly pending receipt;
it does not make a performance or implementation decision.

The ordinary hosted diagnostic is mandatory and runs only publication/procfs
tests. Its runner image/version, Python path/version/hash/inode, and platform
identity are emitted as `execution_identity_non_evidence`. Any platform or test
skip fails the job. This diagnostic does not invoke or claim to invoke `sacct`.

The semantic pipeline integration is a distinct, explicitly provisioned job.
It runs only when workflow-dispatch input `t5_corpus_path` is nonempty and uses
a self-hosted runner labeled `t5-corpus`. It exercises all 7,503 sources but
injects a root scheduler row labeled `synthetic_injected_root_row`; it does not
claim that CI queried `sacct`. On Linux, from a clean committed checkout, run:

```bash
EUF_VIPER_T5_E2E_CORPUS=/absolute/path/to/benchmarks/smtlib-2025 \
EUF_VIPER_T5_E2E_SCHEDULER_EVIDENCE=synthetic_injected_root_row \
  python3 -B -m unittest -v tests.test_t5_linux_end_to_end
```

Once the corpus variable is supplied, an incorrect manifest, missing source,
wrong platform, failed procfs semantic, failed `O_TMPFILE`, mount drift, or
runtime identity drift is a failure, not a skip. Real scheduler evidence is
reserved for post-job WMI validation.

Both CI roles require the recorded checked-out `HEAD` to equal `GITHUB_SHA`.
The provisioned role runs the standalone no-solve scanner before the semantic
pipeline and uploads its exact scan receipt, execution identity, final consumer
receipt, and synthetic-scheduler result record as one retained artifact set.

The define-fun regression is independently fixed in both SMT-LIB readers.
Macro bodies receive only their own parameters as lexical bindings; all other
atoms resolve through global declarations, never a caller `let` or outer macro
parameter. A bounded fixture at
`tests/fixtures/define_fun_caller_shadow_unsat.smt2` is genuinely unsatisfiable.
The quoted-symbol `inner -> outer -> let` fixture at
`tests/fixtures/define_fun_transitive_quoted_shadow_unsat.smt2` is also
unsatisfiable and exercises transitive free-global propagation through the
complete visible `define-fun` call graph.
To scan the exact external source set lexically, without encoding or solving:

```bash
python3 -B scripts/bench/scan_define_fun_shadowing.py scan \
  --repository-root "$PWD" \
  --manifest "$PWD/benchmarks/smtlib-2025/qf_uf_manifest.jsonl" \
  --output "$PWD/results/define-fun-shadowing-scan.json"
python3 -B scripts/bench/scan_define_fun_shadowing.py validate \
  --report "$PWD/results/define-fun-shadowing-scan.json"
```

The report schema is
`euf-viper.define-fun-shadowing-corpus-scan.v2`. It retains all 7,503 source
rows with manifest, lexical, canonical path, device, inode, byte count, and
SHA-256 identities. Validation independently rejects path/resolution/inode
aliases, reconstructs the portable source-set digest from that ledger, and
checks complete source/definition/failure accounting. Unsupported top-level
forms, including recursive definitions, are scan failures rather than ignored
commands. The report fixes `solving_performed=false`.

Before any full submission, inspect the two-minute/256 MiB environment-only
canary without submitting:

```bash
scripts/wmi/submit_t5_environment_canary.sh --dry-run
```

Its `--submit` mode is shard-free and cannot enter any source-set or decision
pipeline. It records procfs fd semantics, all capability sets, repository and
output mount/statfs identities, actual one-link mode-0444 `O_TMPFILE`
publication with digest/fsync, Python/runtime identity, and `scontrol`/`sacct`
availability and executable hashes. The submitter requires a clean exact-blob
canary checkout; the job opens the emitter once and executes those bound bytes
through `/proc/self/fd`. It records an in-job root scheduler identity, including
SLUID/name/user/workdir, and the validator requires the same complete identity
in the successful root `sacct` row while rehashing both Slurm tools. The canary
remains nondecisive and non-authoritative.

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

The full census is submitted held. Immediately after `sbatch`, the remote
operation obtains mutually consistent `scontrol` and root `sacct` identities
and persists the complete held state, including hold reason, SLUID, submit time,
cluster, name, user, and workdir. The pending v7 receipt embeds that record and
an exact namespace object whose keys and nonce/path/inode digest relationships
admit no extras. A local EXIT and signal trap is armed before the remote
`sbatch` and owns cancellation until successful release.
Local code first parses the returned canonical bytes, verifies every expected
submission binding, creates the local receipt with `O_EXCL`, fsyncs and seals
it mode `0444`, fsyncs its directory, and reopens it for full validation. Only
then does a separate SSH operation release the job. Immediately before release
or cancellation, remote code re-queries the complete identity and compares it
exactly with the persisted held record. Zero or multiple scheduler rows are
fail-closed errors and never authorize touching a job. Parse, `O_EXCL`, write,
fsync, revalidation, SSH, or release failure enters that guarded cancellation
path without a release attempt.
