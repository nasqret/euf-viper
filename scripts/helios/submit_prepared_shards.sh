#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SSH_TARGET="${EUF_VIPER_HELIOS_SSH_TARGET:-helios}"
ACCOUNT="${EUF_VIPER_HELIOS_ACCOUNT:-plgccaiautore2026-cpu}"
PARTITION="${EUF_VIPER_HELIOS_PARTITION:-plgrid}"
RUN_ID=""
CONCURRENCY="${EUF_VIPER_HELIOS_ARRAY_CONCURRENCY:-32}"
WALL_TIME="${EUF_VIPER_HELIOS_SHARD_WALL_TIME:-06:00:00}"
MEMORY="${EUF_VIPER_HELIOS_MEMORY:-10G}"
MODE=test-only

die() {
  printf '%s\n' "$*" >&2
  exit 2
}

usage() {
  cat <<'USAGE'
usage: submit_prepared_shards.sh --run-id ID [--submit] [options]

Options:
  --test-only          scheduler validation only (default)
  --submit             submit the array and dependent final audit
  --concurrency COUNT  maximum simultaneous one-core shards (default 32)
  --wall-time HH:MM:SS per-shard wall time
  --memory SIZE        per-shard memory request
USAGE
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --run-id)
      [ "$#" -ge 2 ] || die "--run-id requires an ID"
      RUN_ID="$2"
      shift 2
      ;;
    --concurrency)
      [ "$#" -ge 2 ] || die "--concurrency requires a count"
      CONCURRENCY="$2"
      shift 2
      ;;
    --wall-time)
      [ "$#" -ge 2 ] || die "--wall-time requires a value"
      WALL_TIME="$2"
      shift 2
      ;;
    --memory)
      [ "$#" -ge 2 ] || die "--memory requires a value"
      MEMORY="$2"
      shift 2
      ;;
    --test-only)
      [ "$MODE" = test-only ] || die "--test-only conflicts with --submit"
      shift
      ;;
    --submit)
      [ "$MODE" = test-only ] || die "--submit was specified twice"
      MODE=submit
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage >&2
      die "unknown argument: $1"
      ;;
  esac
done

[[ "$RUN_ID" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || die "unsafe or missing run ID"
[[ "$CONCURRENCY" =~ ^[1-9][0-9]*$ ]] || die "concurrency must be positive"
[ "$CONCURRENCY" -le 256 ] || die "concurrency cannot exceed 256"
[[ "$WALL_TIME" =~ ^[0-9][0-9]:[0-5][0-9]:[0-5][0-9]$ ]] || \
  die "wall time must use canonical HH:MM:SS"
[[ "$MEMORY" =~ ^[1-9][0-9]*[KMGT]$ ]] || die "invalid memory request"
for value in "$SSH_TARGET" "$ACCOUNT" "$PARTITION"; do
  [[ "$value" =~ ^[A-Za-z0-9_.@+-]+$ ]] || die "unsafe setting: $value"
done
for program in git mktemp shasum ssh; do
  command -v "$program" >/dev/null || die "$program is required"
done

cd "$ROOT"
[ -z "$(git status --porcelain=v1 --untracked-files=all)" ] || \
  die "repository must be clean before shard submission"
LOCAL_REVISION="$(git rev-parse --verify 'HEAD^{commit}')"

PREFLIGHT="$(mktemp "${TMPDIR:-/tmp}/euf-viper-shards.XXXXXX")"
trap 'rm -f -- "$PREFLIGHT"' EXIT HUP INT TERM
"$ROOT/scripts/helios/preflight.sh" > "$PREFLIGHT"
REMOTE_ROOT="$(awk -F '\t' '$1 == "fact" && $2 == "remote_root" {print $3}' "$PREFLIGHT")"
PREPARATION_ROOT="$REMOTE_ROOT/runs/$RUN_ID"
CAMPAIGN_ROOT="$REMOTE_ROOT/campaigns/$RUN_ID"

PREPARATION_REPORT="$(ssh -o BatchMode=yes -o ConnectTimeout=15 "$SSH_TARGET" \
  "PREPARATION_ROOT='$PREPARATION_ROOT' EXPECTED_CAMPAIGN_ROOT='$CAMPAIGN_ROOT' bash -l -s" <<'REMOTE'
set -euo pipefail
receipt="$PREPARATION_ROOT/receipt.tsv"
preparation="$PREPARATION_ROOT/preparation.tsv"
column() {
  awk -F '\t' -v key="$2" '
    NR == 1 { for (i = 1; i <= NF; i++) if ($i == key) column = i; next }
    NR == 2 && column { print $column }
  ' "$1"
}
field() { awk -F '\t' -v key="$2" '$1 == key {print $2}' "$1"; }
test -f "$receipt" && test ! -L "$receipt"
test -f "$preparation" && test ! -L "$preparation"
test "$(column "$receipt" status)" = complete
test "$(column "$receipt" execution_mode)" = prepare-sharded
test "$(field "$preparation" execution_mode)" = prepare-sharded
test "$(field "$preparation" campaign_root)" = "$EXPECTED_CAMPAIGN_ROOT"
printf 'preparation_receipt_sha256\t%s\n' "$(sha256sum "$receipt" | awk '{print $1}')"
printf 'orchestration_checkout\t%s\n' "$(column "$receipt" orchestration_checkout)"
printf 'orchestration_revision\t%s\n' "$(column "$receipt" orchestration_revision)"
printf 'solver_revision\t%s\n' "$(column "$receipt" solver_revision)"
printf 'toolchain_sha256\t%s\n' "$(column "$receipt" toolchain_sha256)"
printf 'shard_count\t%s\n' "$(field "$preparation" shard_count)"
REMOTE
)"

report_value() {
  printf '%s\n' "$PREPARATION_REPORT" | \
    awk -F '\t' -v key="$1" '$1 == key {print $2}'
}
PREPARATION_RECEIPT_SHA256="$(report_value preparation_receipt_sha256)"
ORCHESTRATION_CHECKOUT="$(report_value orchestration_checkout)"
ORCHESTRATION_REVISION="$(report_value orchestration_revision)"
SOLVER_REVISION="$(report_value solver_revision)"
TOOLCHAIN_SHA256="$(report_value toolchain_sha256)"
SHARD_COUNT="$(report_value shard_count)"
for digest in "$PREPARATION_RECEIPT_SHA256" "$TOOLCHAIN_SHA256"; do
  [[ "$digest" =~ ^[0-9a-f]{64}$ ]] || die "invalid preparation digest"
done
[[ "$ORCHESTRATION_REVISION" =~ ^[0-9a-f]{40}$ ]] || die "invalid orchestration revision"
[[ "$SOLVER_REVISION" =~ ^[0-9a-f]{40}$ ]] || die "invalid solver revision"
[[ "$SHARD_COUNT" =~ ^[1-9][0-9]*$ ]] && [ "$SHARD_COUNT" -ge 2 ] || \
  die "invalid prepared shard count"
[ "$LOCAL_REVISION" = "$ORCHESTRATION_REVISION" ] || \
  die "local HEAD differs from prepared orchestration revision"
[ "$CONCURRENCY" -le "$SHARD_COUNT" ] || CONCURRENCY="$SHARD_COUNT"
LAST_INDEX="$((SHARD_COUNT - 1))"

remote_submit() {
  local action="$1"
  local submit_mode="$2"
  local dependency="${3:-}"
  ssh -o BatchMode=yes -o ConnectTimeout=15 "$SSH_TARGET" \
    "ACTION='$action' SUBMIT_MODE='$submit_mode' DEPENDENCY='$dependency' ACCOUNT='$ACCOUNT' PARTITION='$PARTITION' WALL_TIME='$WALL_TIME' MEMORY='$MEMORY' REMOTE_ROOT='$REMOTE_ROOT' PREPARATION_ROOT='$PREPARATION_ROOT' CAMPAIGN_ROOT='$CAMPAIGN_ROOT' ORCHESTRATION_CHECKOUT='$ORCHESTRATION_CHECKOUT' ORCHESTRATION_REVISION='$ORCHESTRATION_REVISION' SOLVER_REVISION='$SOLVER_REVISION' PREPARATION_RECEIPT_SHA256='$PREPARATION_RECEIPT_SHA256' TOOLCHAIN_SHA256='$TOOLCHAIN_SHA256' SHARD_COUNT='$SHARD_COUNT' LAST_INDEX='$LAST_INDEX' CONCURRENCY='$CONCURRENCY' RUN_ID='$RUN_ID' bash -l -s" <<'REMOTE'
set -euo pipefail
exports="EUF_VIPER_HELIOS_ORCHESTRATION_CHECKOUT=$ORCHESTRATION_CHECKOUT,EUF_VIPER_HELIOS_PREPARATION_ROOT=$PREPARATION_ROOT,EUF_VIPER_HELIOS_CAMPAIGN_ROOT=$CAMPAIGN_ROOT,EUF_VIPER_HELIOS_PREPARATION_RECEIPT_SHA256=$PREPARATION_RECEIPT_SHA256,EUF_VIPER_HELIOS_ORCHESTRATION_REVISION=$ORCHESTRATION_REVISION,EUF_VIPER_HELIOS_SOLVER_REVISION=$SOLVER_REVISION,EUF_VIPER_HELIOS_TOOLCHAIN_SHA256=$TOOLCHAIN_SHA256,EUF_VIPER_HELIOS_SHARD_COUNT=$SHARD_COUNT"
common=(
  --account="$ACCOUNT" --partition="$PARTITION" --nodes=1 --ntasks=1
  --cpus-per-task=1 --hint=nomultithread --mem="$MEMORY"
  --chdir="$REMOTE_ROOT" --export="$exports"
)
if [ "$ACTION" = array ]; then
  arguments=(
    "${common[@]}" --time="$WALL_TIME" --array="0-$LAST_INDEX%$CONCURRENCY"
    --output="$REMOTE_ROOT/logs/euf-viper-$RUN_ID-shard-%A_%a.out"
    --error="$REMOTE_ROOT/logs/euf-viper-$RUN_ID-shard-%A_%a.err"
  )
  script="$ORCHESTRATION_CHECKOUT/slurm/helios/euf_viper_shard.sbatch"
else
  arguments=(
    "${common[@]}" --time=02:00:00
    --output="$REMOTE_ROOT/logs/euf-viper-$RUN_ID-final-%j.out"
    --error="$REMOTE_ROOT/logs/euf-viper-$RUN_ID-final-%j.err"
  )
  [ -z "$DEPENDENCY" ] || \
    arguments+=(--dependency="afterok:$DEPENDENCY" --kill-on-invalid-dep=yes)
  script="$ORCHESTRATION_CHECKOUT/slurm/helios/euf_viper_finalize.sbatch"
fi
if [ "$SUBMIT_MODE" = test-only ]; then
  sbatch --test-only "${arguments[@]}" "$script"
else
  sbatch --parsable "${arguments[@]}" "$script"
fi
REMOTE
}

printf '%s\n' "$(remote_submit array test-only)"
printf '%s\n' "$(remote_submit final test-only)"
if [ "$MODE" = test-only ]; then
  printf 'mode=test-only run_id=%s shards=%s concurrency=%s preparation_receipt_sha256=%s\n' \
    "$RUN_ID" "$SHARD_COUNT" "$CONCURRENCY" "$PREPARATION_RECEIPT_SHA256"
  exit 0
fi

ssh -o BatchMode=yes -o ConnectTimeout=15 "$SSH_TARGET" \
  "CAMPAIGN_ROOT='$CAMPAIGN_ROOT' bash -l -s" <<'REMOTE'
set -euo pipefail
test ! -e "$CAMPAIGN_ROOT"
mkdir "$CAMPAIGN_ROOT"
mkdir "$CAMPAIGN_ROOT"/{bound-locks,results,tasks}
REMOTE

ARRAY_OUTPUT="$(remote_submit array submit)"
ARRAY_JOB_ID="${ARRAY_OUTPUT%%;*}"
[[ "$ARRAY_JOB_ID" =~ ^[1-9][0-9]*$ ]] || die "invalid array job ID"
if ! FINAL_OUTPUT="$(remote_submit final submit "$ARRAY_JOB_ID")"; then
  ssh -o BatchMode=yes -o ConnectTimeout=15 "$SSH_TARGET" \
    "scancel '$ARRAY_JOB_ID'"
  die "finalizer submission failed; cancelled array $ARRAY_JOB_ID"
fi
FINAL_JOB_ID="${FINAL_OUTPUT%%;*}"
[[ "$FINAL_JOB_ID" =~ ^[1-9][0-9]*$ ]] || die "invalid finalizer job ID"

ssh -o BatchMode=yes -o ConnectTimeout=15 "$SSH_TARGET" \
  "CAMPAIGN_ROOT='$CAMPAIGN_ROOT' ARRAY_JOB_ID='$ARRAY_JOB_ID' FINAL_JOB_ID='$FINAL_JOB_ID' SHARD_COUNT='$SHARD_COUNT' PREPARATION_RECEIPT_SHA256='$PREPARATION_RECEIPT_SHA256' bash -l -s" <<'REMOTE'
set -euo pipefail
temporary="$CAMPAIGN_ROOT/.dispatch.tsv.$$"
{
  printf 'schema_version\tstatus\tarray_job_id\tfinalizer_job_id\tshard_count\tpreparation_receipt_sha256\n'
  printf '1\tsubmitted\t%s\t%s\t%s\t%s\n' \
    "$ARRAY_JOB_ID" "$FINAL_JOB_ID" "$SHARD_COUNT" "$PREPARATION_RECEIPT_SHA256"
} > "$temporary"
chmod 0444 "$temporary"
ln "$temporary" "$CAMPAIGN_ROOT/dispatch.tsv"
rm -f "$temporary"
REMOTE

RECEIPT_ROOT="${EUF_VIPER_HELIOS_SHARD_RECEIPT_ROOT:-${XDG_STATE_HOME:-$HOME/.local/state}/euf-viper/helios-shards}"
mkdir -p "$RECEIPT_ROOT"
RECEIPT="$RECEIPT_ROOT/$RUN_ID.tsv"
test ! -e "$RECEIPT"
printf 'schema_version\tstatus\trun_id\tarray_job_id\tfinalizer_job_id\tshard_count\tconcurrency\tpreparation_receipt_sha256\tcampaign_root\n1\tsubmitted\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
  "$RUN_ID" "$ARRAY_JOB_ID" "$FINAL_JOB_ID" "$SHARD_COUNT" "$CONCURRENCY" \
  "$PREPARATION_RECEIPT_SHA256" "$CAMPAIGN_ROOT" > "$RECEIPT"
chmod 0444 "$RECEIPT"
printf 'submitted array_job=%s finalizer_job=%s campaign=%s receipt=%s\n' \
  "$ARRAY_JOB_ID" "$FINAL_JOB_ID" "$CAMPAIGN_ROOT" "$RECEIPT"
