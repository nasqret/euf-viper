#!/usr/bin/env bash
#SBATCH --job-name=euf-p0-prepare
#SBATCH --partition=cpu_idle
#SBATCH --cpus-per-task=1
#SBATCH --mem=16G
#SBATCH --time=02:00:00
#SBATCH --output=results/p0-prepare-%j.out
#SBATCH --error=results/p0-prepare-%j.err

set -euo pipefail

cd "${SLURM_SUBMIT_DIR:-$PWD}"
export PATH="$PWD/third_party/solvers/bin:$HOME/.cargo/bin:$HOME/.local/bin:$PATH"
export LANG=C
export LC_ALL=C
export TZ=UTC

EXPECTED_REVISION="${EUF_VIPER_EXPECTED_REVISION:?set EUF_VIPER_EXPECTED_REVISION}"
SHARDS="${EUF_VIPER_LOCKED_SHARDS:-64}"
RUN_ROOT="$PWD/results/p0-${SLURM_JOB_ID}"
OFFICIAL_CACHE="$RUN_ROOT/source/results-sq-2025.json.gz"
mkdir -p "$RUN_ROOT/source" "$RUN_ROOT/taxonomy" "$RUN_ROOT/locks"

ACTUAL_REVISION="$(git rev-parse HEAD)"
if [ "$ACTUAL_REVISION" != "$EXPECTED_REVISION" ]; then
  echo "revision mismatch: expected $EXPECTED_REVISION, got $ACTUAL_REVISION" >&2
  exit 2
fi
if [ -n "$(git status --porcelain=v1 --untracked-files=no)" ]; then
  echo "tracked repository state is dirty before preparation" >&2
  exit 2
fi

python3 scripts/bench/validate_campaign_spec.py \
  campaigns/best-overall-qf-uf-2026-07.json \
  --out "$RUN_ROOT/validated-campaign.json"

cargo build --release
scripts/bench/install_solvers.sh "$PWD/third_party/solvers" \
  > "$RUN_ROOT/install-solvers.log" 2>&1
SHARED_CORPUS="${EUF_VIPER_SHARED_CORPUS:-$HOME/euf-viper/benchmarks/smtlib-2025}"
if [ ! -e "$PWD/benchmarks/smtlib-2025" ] && \
   [ -s "$SHARED_CORPUS/qf_uf_manifest.jsonl" ]; then
  ln -s "$SHARED_CORPUS" "$PWD/benchmarks/smtlib-2025"
fi
if [ ! -s "$PWD/benchmarks/smtlib-2025/qf_uf_manifest.jsonl" ]; then
  scripts/bench/fetch_smtlib_qf_uf.sh "$PWD/benchmarks/smtlib-2025" \
    > "$RUN_ROOT/fetch-corpus.log" 2>&1
else
  printf 'shared_corpus=%s\n' "$(readlink -f "$PWD/benchmarks/smtlib-2025")" \
    > "$RUN_ROOT/fetch-corpus.log"
fi

FULL_MANIFEST="$PWD/benchmarks/smtlib-2025/qf_uf_manifest.jsonl"
OFFICIAL_MANIFEST="$PWD/benchmarks/smtcomp-2025/qf_uf_manifest.jsonl"
RECONSTRUCTED_OFFICIAL="$RUN_ROOT/reconstructed-official.jsonl"
python3 scripts/bench/ingest_smtcomp_2025_qf_uf.py \
  --full-manifest "$FULL_MANIFEST" \
  --official-results "$OFFICIAL_CACHE" \
  --download \
  --out "$RECONSTRUCTED_OFFICIAL" \
  --metadata "$RUN_ROOT/reconstructed-official-metadata.json"
cmp "$OFFICIAL_MANIFEST" "$RECONSTRUCTED_OFFICIAL"

python3 scripts/bench/build_family_manifest.py "$FULL_MANIFEST" \
  --taxonomy-out "$RUN_ROOT/taxonomy/full.jsonl" \
  --split-out "$RUN_ROOT/taxonomy/full-split.json"
python3 scripts/bench/build_family_manifest.py "$OFFICIAL_MANIFEST" \
  --taxonomy-out "$RUN_ROOT/taxonomy/official.jsonl" \
  --split-out "$RUN_ROOT/taxonomy/official-split.json"

VIPER_VERSION="0.1.0+$ACTUAL_REVISION"
python3 scripts/bench/record_solver_config.py \
  --campaign campaigns/best-overall-qf-uf-2026-07.json \
  --viper target/release/euf-viper \
  --viper-version "$VIPER_VERSION" \
  --z3 third_party/solvers/bin/z3 \
  --cvc5 third_party/solvers/bin/cvc5 \
  --yices2 third_party/solvers/bin/yices-smt2 \
  --opensmt third_party/solvers/bin/opensmt \
  --smoke-instance generated/synthetic/chain1000_sat.smt2 \
  --smoke-expected sat \
  --out "$RUN_ROOT/solver-config.json" \
  > "$RUN_ROOT/solver-config-summary.json"

CORPUS_ROOT="$PWD/benchmarks/smtlib-2025/QF_UF"
python3 scripts/bench/freeze_campaign.py \
  campaigns/best-overall-qf-uf-2026-07.json \
  --manifest "$FULL_MANIFEST" \
  --taxonomy "$RUN_ROOT/taxonomy/full.jsonl" \
  --solver-config "$RUN_ROOT/solver-config.json" \
  --repository "$PWD" \
  --corpus-root "$CORPUS_ROOT" \
  --cpu-id 0 \
  --memory-bytes 8589934592 \
  --order balanced_latin_square \
  --budget 2 \
  --output-directory "$RUN_ROOT/full-2s" \
  --out "$RUN_ROOT/locks/full-parent.json" \
  > "$RUN_ROOT/locks/full-parent-summary.json"

python3 scripts/bench/freeze_campaign.py \
  campaigns/best-overall-qf-uf-2026-07.json \
  --manifest "$OFFICIAL_MANIFEST" \
  --taxonomy "$RUN_ROOT/taxonomy/official.jsonl" \
  --solver-config "$RUN_ROOT/solver-config.json" \
  --repository "$PWD" \
  --corpus-root "$CORPUS_ROOT" \
  --cpu-id 0 \
  --memory-bytes 8589934592 \
  --order balanced_latin_square \
  --budget 2 \
  --output-directory "$RUN_ROOT/official-2s" \
  --out "$RUN_ROOT/locks/official-parent.json" \
  > "$RUN_ROOT/locks/official-parent-summary.json"

python3 scripts/bench/shard_campaign_lock.py \
  "$RUN_ROOT/locks/full-parent.json" \
  --count "$SHARDS" \
  --out-dir "$RUN_ROOT/locks/full" \
  > "$RUN_ROOT/locks/full-shards-summary.json"
python3 scripts/bench/shard_campaign_lock.py \
  "$RUN_ROOT/locks/official-parent.json" \
  --count "$SHARDS" \
  --out-dir "$RUN_ROOT/locks/official" \
  > "$RUN_ROOT/locks/official-shards-summary.json"

python3 - "$RUN_ROOT/prepare.json" <<'PY'
import hashlib
import json
import os
import platform
import sys
from pathlib import Path

out = Path(sys.argv[1])
root = out.parent
payload = {
    "schema_version": 1,
    "status": "prepared",
    "job_id": int(os.environ["SLURM_JOB_ID"]),
    "revision": os.environ["EUF_VIPER_EXPECTED_REVISION"],
    "hostname": platform.node(),
    "shards": int(os.environ.get("EUF_VIPER_LOCKED_SHARDS", "64")),
    "artifacts": {},
}
for name in (
    "solver-config.json",
    "taxonomy/full.jsonl",
    "taxonomy/full-split.json",
    "taxonomy/official.jsonl",
    "taxonomy/official-split.json",
    "locks/full-parent.json",
    "locks/official-parent.json",
):
    path = root / name
    payload["artifacts"][name] = hashlib.sha256(path.read_bytes()).hexdigest()
temporary = out.with_name(f".{out.name}.tmp")
temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
temporary.replace(out)
PY

printf 'run_root=%s\n' "$RUN_ROOT"
printf 'revision=%s\n' "$ACTUAL_REVISION"
printf 'shards=%s\n' "$SHARDS"
