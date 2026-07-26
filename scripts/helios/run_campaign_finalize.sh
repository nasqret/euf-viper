#!/usr/bin/env bash
set -euo pipefail

ORCHESTRATION_CHECKOUT="${EUF_VIPER_HELIOS_ORCHESTRATION_CHECKOUT:?set orchestration checkout}"
PREPARATION_ROOT="${EUF_VIPER_HELIOS_PREPARATION_ROOT:?set preparation root}"
CAMPAIGN_ROOT="${EUF_VIPER_HELIOS_CAMPAIGN_ROOT:?set campaign root}"
EXPECTED_PREPARATION_RECEIPT_SHA256="${EUF_VIPER_HELIOS_PREPARATION_RECEIPT_SHA256:?set preparation receipt hash}"
SHARD_COUNT="${EUF_VIPER_HELIOS_SHARD_COUNT:?set shard count}"

die() {
  printf '%s\n' "$*" >&2
  exit 2
}

hash_file() {
  sha256sum "$1" | awk '{print $1}'
}

[[ "$SHARD_COUNT" =~ ^[1-9][0-9]*$ ]] && [ "$SHARD_COUNT" -ge 2 ] || \
  die "finalizer requires at least two shards"
[ "$(hash_file "$PREPARATION_ROOT/receipt.tsv")" = \
  "$EXPECTED_PREPARATION_RECEIPT_SHA256" ] || die "preparation receipt drifted"
test ! -e "$CAMPAIGN_ROOT/analysis.json"
test ! -e "$CAMPAIGN_ROOT/audit-index.json"
test ! -e "$CAMPAIGN_ROOT/final-receipt.tsv"

module --force purge
module load GCCcore/14.3.0 Rust/1.88.0
export LANG=C LC_ALL=C TZ=UTC PYTHONDONTWRITEBYTECODE=1

set +e
python3 "$ORCHESTRATION_CHECKOUT/scripts/bench/analyze_campaign.py" \
  --parent-lock "$PREPARATION_ROOT/campaign-lock.json" \
  --shard-lock-dir "$CAMPAIGN_ROOT/bound-locks" \
  --shard-results-root "$CAMPAIGN_ROOT/results" \
  --candidate euf-viper \
  --baseline yices2 \
  --baseline z3-default \
  --baseline z3-sat-euf \
  --baseline cvc5 \
  --baseline opensmt \
  --bootstrap-replicates 10000 \
  --out "$CAMPAIGN_ROOT/analysis.json"
ANALYZER_STATUS="$?"
set -e
case "$ANALYZER_STATUS" in
  0|1) ;;
  *) die "campaign analysis rejected its inputs (exit $ANALYZER_STATUS)" ;;
esac

python3 "$ORCHESTRATION_CHECKOUT/scripts/helios/audit_sharded_campaign.py" \
  --preparation-root "$PREPARATION_ROOT" \
  --campaign-root "$CAMPAIGN_ROOT" \
  --shard-count "$SHARD_COUNT" \
  --analysis "$CAMPAIGN_ROOT/analysis.json" \
  --out "$CAMPAIGN_ROOT/audit-index.json" \
  > "$CAMPAIGN_ROOT/audit-summary.json"

ANALYSIS_STATUS="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["status"])' "$CAMPAIGN_ROOT/analysis.json")"
TEMPORARY="$CAMPAIGN_ROOT/.final-receipt.tsv.${SLURM_JOB_ID}"
{
  printf 'schema_version\tstatus\tjob_id\tshard_count\tpreparation_receipt_sha256\tanalysis_status\tanalysis_sha256\taudit_index_sha256\n'
  printf '1\tcomplete\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$SLURM_JOB_ID" "$SHARD_COUNT" "$EXPECTED_PREPARATION_RECEIPT_SHA256" \
    "$ANALYSIS_STATUS" "$(hash_file "$CAMPAIGN_ROOT/analysis.json")" \
    "$(hash_file "$CAMPAIGN_ROOT/audit-index.json")"
} > "$TEMPORARY"
chmod 0444 "$TEMPORARY"
ln "$TEMPORARY" "$CAMPAIGN_ROOT/final-receipt.tsv"
rm -f "$TEMPORARY"
chmod -R a-w "$CAMPAIGN_ROOT"
