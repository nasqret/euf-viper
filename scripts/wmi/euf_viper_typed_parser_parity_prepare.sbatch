#!/usr/bin/env bash
#SBATCH --job-name=euf-parser-prepare
#SBATCH --partition=cpu_idle
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=1
#SBATCH --mem=8G
#SBATCH --time=00:30:00
#SBATCH --output=results/typed-parser-prepare-%j.out
#SBATCH --error=results/typed-parser-prepare-%j.err

set -euo pipefail

cd "${SLURM_SUBMIT_DIR:-$PWD}"
export LANG=C
export LC_ALL=C
export TZ=UTC
export CARGO_BUILD_JOBS="${SLURM_CPUS_PER_TASK:-1}"

EXPECTED_REVISION="${EUF_VIPER_EXPECTED_REVISION:?set EUF_VIPER_EXPECTED_REVISION}"
CAMPAIGN_ROOT="${EUF_VIPER_TYPED_PARSER_ROOT:?set EUF_VIPER_TYPED_PARSER_ROOT}"
EXPECTED_SOURCES="${EUF_VIPER_TYPED_PARSER_EXPECTED_SOURCES:-7503}"
SHARDS="${EUF_VIPER_TYPED_PARSER_SHARDS:-128}"
TIMEOUT_SECONDS="${EUF_VIPER_TYPED_PARSER_TIMEOUT_SECONDS:-60}"
for value in "$EXPECTED_SOURCES" "$SHARDS" "$TIMEOUT_SECONDS"; do
  case "$value" in
    ''|0|0*|*[!0-9]*) echo "campaign integers must be canonical and positive" >&2; exit 2 ;;
  esac
done

ACTUAL_REVISION="$(git rev-parse HEAD)"
if [ "$ACTUAL_REVISION" != "$EXPECTED_REVISION" ]; then
  echo "revision mismatch: expected $EXPECTED_REVISION, got $ACTUAL_REVISION" >&2
  exit 2
fi
if [ -n "$(git status --porcelain=v1 --untracked-files=no)" ]; then
  echo "tracked repository state is dirty" >&2
  exit 2
fi

SHARED_CORPUS="${EUF_VIPER_SHARED_CORPUS:-$HOME/euf-viper/benchmarks/smtlib-2025}"
if [ ! -e "$PWD/benchmarks/smtlib-2025" ] && [ -s "$SHARED_CORPUS/qf_uf_manifest.jsonl" ]; then
  ln -s "$SHARED_CORPUS" "$PWD/benchmarks/smtlib-2025"
fi
MANIFEST="${EUF_VIPER_TYPED_PARSER_MANIFEST:-$PWD/benchmarks/smtlib-2025/qf_uf_manifest.jsonl}"
if [ ! -s "$MANIFEST" ]; then
  echo "missing nonempty parity manifest: $MANIFEST" >&2
  exit 2
fi
if [ -e "$CAMPAIGN_ROOT/prepare.json" ]; then
  echo "campaign root is already prepared: $CAMPAIGN_ROOT" >&2
  exit 2
fi
mkdir -p "$CAMPAIGN_ROOT"

cargo build --release --locked
BINARY="$PWD/target/release/euf-viper"
test -x "$BINARY"
"$BINARY" parse-check tests/fixtures/parser_parity/bool_data_mixed_sorts.smt2 \
  > "$CAMPAIGN_ROOT/preflight.json"
python3 - "$CAMPAIGN_ROOT/preflight.json" <<'PY'
import json
import sys
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text(encoding="ascii"))
if payload.get("schema") != "euf-viper.typed-parser-parity.v1":
    raise SystemExit("typed parser preflight schema mismatch")
required = {
    "status": "match",
    "tree_well_sorted": True,
    "stream_well_sorted": True,
    "fallback": False,
}
for key, expected in required.items():
    if payload.get(key) != expected:
        raise SystemExit(f"typed parser preflight failed: {key}={payload.get(key)!r}")
PY

python3 scripts/bench/typed_parser_parity.py prepare \
  --manifest "$MANIFEST" \
  --repository-root "$PWD" \
  --binary "$BINARY" \
  --revision "$EXPECTED_REVISION" \
  --expected-sources "$EXPECTED_SOURCES" \
  --shards "$SHARDS" \
  --timeout-seconds "$TIMEOUT_SECONDS" \
  --output-root "$CAMPAIGN_ROOT"

printf 'typed_parser_campaign_root=%s\n' "$CAMPAIGN_ROOT"
printf 'revision=%s\n' "$ACTUAL_REVISION"
