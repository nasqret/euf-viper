#!/bin/bash
#SBATCH --job-name=euf-p0-shard
#SBATCH --partition=cpu_idle
#SBATCH --cpus-per-task=1
#SBATCH --mem=10G
#SBATCH --time=02:00:00
#SBATCH --output=/dev/null
#SBATCH --error=/dev/null

set -euo pipefail
umask 077

ATTEMPT_ID="${EUF_VIPER_ATTEMPT_ID:?set EUF_VIPER_ATTEMPT_ID}"
ATTEMPT_ROOT="${EUF_VIPER_ATTEMPT_ROOT:?set EUF_VIPER_ATTEMPT_ROOT}"
CHECKOUT="${EUF_VIPER_CHECKOUT:?set EUF_VIPER_CHECKOUT}"
EXPECTED_REVISION="${EUF_VIPER_EXPECTED_REVISION:?set EUF_VIPER_EXPECTED_REVISION}"
PYTHON_BIN="${EUF_VIPER_PYTHON:?set EUF_VIPER_PYTHON}"
PYTHON_SHA256="${EUF_VIPER_PYTHON_SHA256:?set EUF_VIPER_PYTHON_SHA256}"
SHA256SUM_BIN="${EUF_VIPER_SHA256SUM:?set EUF_VIPER_SHA256SUM}"
PROVENANCE_HELPER_SHA256="${EUF_VIPER_PROVENANCE_HELPER_SHA256:?set EUF_VIPER_PROVENANCE_HELPER_SHA256}"
SUBMISSION_MANIFEST="${EUF_VIPER_SUBMISSION_MANIFEST:?set EUF_VIPER_SUBMISSION_MANIFEST}"
SUBMISSION_MANIFEST_SHA256="${EUF_VIPER_SUBMISSION_MANIFEST_SHA256:?set EUF_VIPER_SUBMISSION_MANIFEST_SHA256}"
PREPARE_JOB_ID="${EUF_VIPER_PREPARE_JOB_ID:?set EUF_VIPER_PREPARE_JOB_ID}"
CORPUS_KIND="${EUF_VIPER_CORPUS_KIND:?set EUF_VIPER_CORPUS_KIND}"
PROVENANCE_HELPER="$CHECKOUT/scripts/wmi/hermetic_provenance.py"

case "$CORPUS_KIND" in
  full|official) ;;
  *) echo "EUF_VIPER_CORPUS_KIND must be full or official" >&2; exit 2 ;;
esac
case "$PREPARE_JOB_ID" in *[!0-9]*|'') echo "invalid prepare job id" >&2; exit 2 ;; esac

hash_file() {
  local OUTPUT
  OUTPUT="$("$SHA256SUM_BIN" "$1")"
  printf '%s' "${OUTPUT%% *}"
}
if [ "$(hash_file "$PYTHON_BIN")" != "$PYTHON_SHA256" ] || \
   [ "$(hash_file "$PROVENANCE_HELPER")" != "$PROVENANCE_HELPER_SHA256" ] || \
   [ "$(hash_file "$SUBMISSION_MANIFEST")" != "$SUBMISSION_MANIFEST_SHA256" ]; then
  echo "receipt-bound shard bootstrap SHA-256 mismatch" >&2
  exit 2
fi

VERIFIED_PROVENANCE="$("$PYTHON_BIN" -B -I -S "$PROVENANCE_HELPER" verify \
  --manifest "$SUBMISSION_MANIFEST" \
  --expected-sha256 "$SUBMISSION_MANIFEST_SHA256" \
  --stage shard)"
EXECUTION_FIELDS="$("$PYTHON_BIN" -B -I -S -c '
import json, sys
value = json.loads(sys.argv[1]); environment = value["execution_environment"]
fields = [environment[name] for name in (
    "HOME", "PATH", "RUSTUP_HOME", "CARGO_TARGET_DIR", "TMPDIR",
    "XDG_CACHE_HOME", "XDG_CONFIG_HOME",
)]
fields.append(value["runtime_tools"]["env"]["realpath"])
if any("\t" in item or "\n" in item for item in fields): raise SystemExit("unsafe environment")
print("\t".join(fields))
' "$VERIFIED_PROVENANCE")"
IFS=$'\t' read -r PRIVATE_HOME RUNTIME_PATH RUSTUP_HOME CARGO_TARGET_DIR \
  PRIVATE_TMP XDG_CACHE_HOME XDG_CONFIG_HOME ENV_BIN <<<"$EXECUTION_FIELDS"

clean_env() {
  "$ENV_BIN" -i HOME="$PRIVATE_HOME" LANG=C LC_ALL=C PATH="$RUNTIME_PATH" \
    RUSTUP_HOME="$RUSTUP_HOME" CARGO_TARGET_DIR="$CARGO_TARGET_DIR" \
    TMPDIR="$PRIVATE_TMP" TZ=UTC XDG_CACHE_HOME="$XDG_CACHE_HOME" \
    XDG_CONFIG_HOME="$XDG_CONFIG_HOME" "$@"
}
python_clean() {
  clean_env "$PYTHON_BIN" -B -I -S "$@"
}

cd "$CHECKOUT"
RUN_ROOT="$ATTEMPT_ROOT/results/p0-${PREPARE_JOB_ID}"
PREPARE_RECEIPT="$RUN_ROOT/prepare.json"
PREPARATION_BINDING="$(python_clean "$PROVENANCE_HELPER" verify-preparation-receipt \
  --receipt "$PREPARE_RECEIPT" \
  --provenance "$VERIFIED_PROVENANCE" \
  --run-root "$RUN_ROOT" \
  --prepare-job "$PREPARE_JOB_ID")"

INDEX="$(printf '%04d' "$SLURM_ARRAY_TASK_ID")"
PREPARED_LOCK="$RUN_ROOT/locks/$CORPUS_KIND/lock-$INDEX.json"
BOUND_LOCK="$RUN_ROOT/locks/$CORPUS_KIND/bound-$INDEX.json"
python_clean scripts/bench/bind_campaign_cpu.py "$PREPARED_LOCK" \
  --out "$BOUND_LOCK" \
  >"$RUN_ROOT/locks/$CORPUS_KIND/binding-$INDEX.json"
python_clean scripts/bench/run_locked_campaign.py "$BOUND_LOCK"

FINAL_PROVENANCE="$("$PYTHON_BIN" -B -I -S "$PROVENANCE_HELPER" verify \
  --manifest "$SUBMISSION_MANIFEST" \
  --expected-sha256 "$SUBMISSION_MANIFEST_SHA256" \
  --stage shard)"
if [ "$FINAL_PROVENANCE" != "$VERIFIED_PROVENANCE" ]; then
  echo "provenance changed during shard execution" >&2
  exit 2
fi
