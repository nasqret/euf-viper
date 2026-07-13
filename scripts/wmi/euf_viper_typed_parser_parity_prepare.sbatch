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

CARGO="${EUF_VIPER_CARGO:-$HOME/.cargo/bin/cargo}"
EXPECTED_CARGO_SHA256="${EUF_VIPER_CARGO_SHA256:?set EUF_VIPER_CARGO_SHA256}"
EXPECTED_CARGO_VERSION="${EUF_VIPER_CARGO_VERSION:?set EUF_VIPER_CARGO_VERSION}"
case "$CARGO" in
  /*) ;;
  *) echo "EUF_VIPER_CARGO must be an absolute path: $CARGO" >&2; exit 127 ;;
esac
if [ ! -f "$CARGO" ] || [ ! -x "$CARGO" ]; then
  echo "pinned cargo is not an executable file: $CARGO" >&2
  exit 127
fi
if [ "${#EXPECTED_CARGO_SHA256}" -ne 64 ]; then
  echo "EUF_VIPER_CARGO_SHA256 must be a lowercase SHA-256" >&2
  exit 2
fi
case "$EXPECTED_CARGO_SHA256" in
  *[!0-9a-f]*) echo "EUF_VIPER_CARGO_SHA256 must be a lowercase SHA-256" >&2; exit 2 ;;
esac
ACTUAL_CARGO_SHA256="$(sha256sum "$CARGO" | awk '{print $1}')"
if [ "$ACTUAL_CARGO_SHA256" != "$EXPECTED_CARGO_SHA256" ]; then
  echo "cargo hash mismatch: expected $EXPECTED_CARGO_SHA256, got $ACTUAL_CARGO_SHA256" >&2
  exit 2
fi
ACTUAL_CARGO_VERSION="$("$CARGO" --version)"
if [ "$ACTUAL_CARGO_VERSION" != "$EXPECTED_CARGO_VERSION" ]; then
  echo "cargo version mismatch: expected $EXPECTED_CARGO_VERSION, got $ACTUAL_CARGO_VERSION" >&2
  exit 2
fi

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

printf '%s\n' "$ACTUAL_CARGO_VERSION" > "$CAMPAIGN_ROOT/cargo-version.txt"
printf '%s  %s\n' "$ACTUAL_CARGO_SHA256" "$CARGO" \
  > "$CAMPAIGN_ROOT/cargo-sha256.txt"
"$CARGO" build --release --locked
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
