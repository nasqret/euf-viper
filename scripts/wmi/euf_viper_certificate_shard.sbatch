#!/usr/bin/env bash
#SBATCH --job-name=euf-cert-shard
#SBATCH --partition=cpu_idle
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=1
#SBATCH --mem=8G
#SBATCH --time=24:00:00
#SBATCH --output=results/certificate-shard-%A_%a.out
#SBATCH --error=results/certificate-shard-%A_%a.err

set -euo pipefail
umask 077

cd "${SLURM_SUBMIT_DIR:-$PWD}"
export PATH="$HOME/.cargo/bin:$HOME/.local/bin:/usr/local/bin:/usr/bin:/bin"
export LANG=C
export LC_ALL=C
export TZ=UTC
export OMP_NUM_THREADS=1
export OPENBLAS_NUM_THREADS=1
export RAYON_NUM_THREADS=1

EXPECTED_REVISION="${EUF_VIPER_CERT_EXPECTED_REVISION:?set EUF_VIPER_CERT_EXPECTED_REVISION}"
RUN_ROOT="${EUF_VIPER_CERT_RUN_ROOT:?set EUF_VIPER_CERT_RUN_ROOT}"
SHARDS="${EUF_VIPER_CERT_SHARDS:?set EUF_VIPER_CERT_SHARDS}"
CHECKER_SHA256="${EUF_VIPER_CERT_CHECKER_SHA256:?set EUF_VIPER_CERT_CHECKER_SHA256}"
DRAT_TRIM_SHA256="${EUF_VIPER_CERT_DRAT_TRIM_SHA256:?set EUF_VIPER_CERT_DRAT_TRIM_SHA256}"
INDEX="${SLURM_ARRAY_TASK_ID:?certificate work must run as an array}"

case "$SHARDS" in
  ''|0|0*|*[!0-9]*)
    echo "EUF_VIPER_CERT_SHARDS must be a canonical positive integer" >&2
    exit 2
    ;;
esac
case "$INDEX" in
  ''|*[!0-9]*)
    echo "SLURM_ARRAY_TASK_ID must be a non-negative integer" >&2
    exit 2
    ;;
esac
if [ "$INDEX" -ge "$SHARDS" ]; then
  echo "certificate shard index is outside the frozen array" >&2
  exit 2
fi
if [ "${SLURM_CPUS_PER_TASK:-1}" != 1 ]; then
  echo "certificate shard requires exactly one allocated core" >&2
  exit 2
fi
if [ "$(git rev-parse HEAD)" != "$EXPECTED_REVISION" ]; then
  echo "repository revision drift in certificate shard" >&2
  exit 2
fi
if [ -n "$(git status --porcelain=v1 --untracked-files=all)" ]; then
  echo "repository must be completely clean in certificate shard" >&2
  exit 2
fi

mapfile -t CONFIG < <(
  python3 - \
    "$RUN_ROOT/prepare.json" \
    "$EXPECTED_REVISION" \
    "$SHARDS" \
    "$INDEX" \
    "$CHECKER_SHA256" \
    "$DRAT_TRIM_SHA256" <<'PY_SHARD_CONFIG'
import importlib.util
import sys
from pathlib import Path


ROOT = Path.cwd().resolve()
manifest_raw, revision, shard_count_raw, index_raw, checker_hash, drat_hash = (
    sys.argv[1:]
)

spec = importlib.util.spec_from_file_location(
    "certificate_shadow_shard", ROOT / "scripts" / "cert" / "shadow_campaign.py"
)
if spec is None or spec.loader is None:
    raise RuntimeError("cannot import certificate shadow runner")
shadow = importlib.util.module_from_spec(spec)
spec.loader.exec_module(shadow)

manifest_path = Path(manifest_raw).expanduser()
if manifest_path.is_symlink() or not manifest_path.is_file():
    raise RuntimeError("prepare manifest is missing or is a symlink")
raw = manifest_path.read_bytes()
try:
    text = raw.decode("ascii")
except UnicodeDecodeError as error:
    raise RuntimeError("prepare manifest is not ASCII") from error
manifest = shadow._strict_json(text, "prepare manifest")
if shadow.canonical_bytes(manifest) != raw:
    raise RuntimeError("prepare manifest is not canonical immutable JSON")
if manifest.get("schema_version") != 1 or manifest.get("status") != "validated":
    raise RuntimeError("prepare manifest is not a validated schema-v1 manifest")
if manifest.get("revision") != revision:
    raise RuntimeError("prepare manifest revision mismatch")

shard_count = int(shard_count_raw)
index = int(index_raw)
configuration = manifest.get("configuration", {})
if configuration.get("certificate_shards") != shard_count:
    raise RuntimeError("prepare manifest shard count mismatch")
shards = manifest.get("base", {}).get("shards", [])
if len(shards) != shard_count:
    raise RuntimeError("prepare manifest has an incomplete shard list")
record = shards[index]
if record.get("index") != index:
    raise RuntimeError("prepare manifest shard ordering mismatch")
if type(record.get("selected_instances")) is not int or record["selected_instances"] < 0:
    raise RuntimeError("certificate shard has an invalid frozen work count")

checker = manifest.get("tools", {}).get("checker", {})
drat_trim = manifest.get("tools", {}).get("drat_trim", {})
if checker.get("sha256") != checker_hash:
    raise RuntimeError("checker hash differs from submitted pin")
if drat_trim.get("sha256") != drat_hash:
    raise RuntimeError("drat-trim hash differs from submitted pin")

for path_field, hash_field, label in (
    (record.get("lock"), record.get("lock_file_sha256"), "base shard lock"),
    (record.get("raw"), record.get("raw_sha256"), "base shard raw results"),
    (record.get("binary"), record.get("binary_sha256"), "euf-viper binary"),
    (checker.get("path"), checker_hash, "certificate checker"),
    (drat_trim.get("path"), drat_hash, "drat-trim"),
):
    path = Path(path_field).resolve(strict=True)
    if not path.is_file() or shadow.sha256_file(path) != hash_field:
        raise RuntimeError(f"{label} path or SHA-256 drift")
    if "\n" in str(path) or "\r" in str(path):
        raise RuntimeError(f"{label} path contains a line break")

corpus_root = configuration.get("corpus_root")
if corpus_root is not None:
    corpus = Path(corpus_root).resolve(strict=True)
    if not corpus.is_dir():
        raise RuntimeError("frozen corpus root is not a directory")
    corpus_root = str(corpus)

values = (
    record["lock"],
    record["raw"],
    record["binary"],
    checker["path"],
    drat_trim["path"],
    corpus_root or "",
    str(configuration["timeout_s"]),
    str(configuration["checker_timeout_s"]),
    str(configuration["timeout_grace_s"]),
)
for value in values:
    if "\n" in value or "\r" in value:
        raise RuntimeError("frozen configuration contains a line break")
    print(value)
PY_SHARD_CONFIG
)

if [ "${#CONFIG[@]}" -ne 9 ]; then
  echo "could not load the exact frozen shard configuration" >&2
  exit 2
fi

LOCK="${CONFIG[0]}"
RAW="${CONFIG[1]}"
BINARY="${CONFIG[2]}"
CHECKER="${CONFIG[3]}"
DRAT_TRIM="${CONFIG[4]}"
CORPUS_ROOT="${CONFIG[5]}"
TIMEOUT_S="${CONFIG[6]}"
CHECKER_TIMEOUT_S="${CONFIG[7]}"
TIMEOUT_GRACE_S="${CONFIG[8]}"

PADDED="$(printf '%04d' "$INDEX")"
SHARD_OUTPUT="$RUN_ROOT/shards/source-shard-$PADDED"
mkdir -p "$SHARD_OUTPUT"

COMMAND=(
  python3 scripts/cert/shadow_campaign.py
  "$LOCK"
  "$RAW"
  --output-dir "$SHARD_OUTPUT"
  --binary "$BINARY"
  --checker "$CHECKER"
  --drat-trim "$DRAT_TRIM"
  --timeout "$TIMEOUT_S"
  --checker-timeout "$CHECKER_TIMEOUT_S"
  --timeout-grace "$TIMEOUT_GRACE_S"
  --shard-index 0
  --shard-count 1
)
if [ -n "$CORPUS_ROOT" ]; then
  COMMAND+=(--corpus-root "$CORPUS_ROOT")
fi

"${COMMAND[@]}"
