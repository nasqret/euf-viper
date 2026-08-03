#!/usr/bin/env bash
#SBATCH --job-name=euf-atlas
#SBATCH --partition=cpu_idle
#SBATCH --cpus-per-task=2
#SBATCH --mem=16G
#SBATCH --time=02:00:00

set -euo pipefail

export LANG=C
export LC_ALL=C
export TZ=UTC

CAMPAIGN_ROOT="${EUF_VIPER_CAMPAIGN_ROOT:?set EUF_VIPER_CAMPAIGN_ROOT}"
ANALYSIS_TOOLS="${EUF_VIPER_ANALYSIS_TOOLS:?set EUF_VIPER_ANALYSIS_TOOLS}"
OUTPUT_ROOT="${EUF_VIPER_ATLAS_OUTPUT_ROOT:?set EUF_VIPER_ATLAS_OUTPUT_ROOT}"
BASE_PREPARE_JOB_ID="${EUF_VIPER_BASE_PREPARE_JOB_ID:?set EUF_VIPER_BASE_PREPARE_JOB_ID}"
CHAIN_ID="${EUF_VIPER_CONTINUATION_CHAIN_ID:?set EUF_VIPER_CONTINUATION_CHAIN_ID}"
CORPUS_KIND="${EUF_VIPER_CORPUS_KIND:-full}"
BOOTSTRAP_REPLICATES="${EUF_VIPER_ATLAS_BOOTSTRAP_REPLICATES:-32}"

case "$CORPUS_KIND" in full|official) ;; *) echo "invalid corpus kind" >&2; exit 2 ;; esac
for VALUE in "$BASE_PREPARE_JOB_ID" "$CHAIN_ID" "$BOOTSTRAP_REPLICATES"; do
  case "$VALUE" in ''|0|0*|*[!0-9]*) echo "invalid positive integer: $VALUE" >&2; exit 2 ;; esac
done
for DIRECTORY in "$CAMPAIGN_ROOT" "$ANALYSIS_TOOLS"; do
  if [ ! -d "$DIRECTORY" ]; then
    echo "required directory does not exist: $DIRECTORY" >&2
    exit 2
  fi
done
if [ -e "$OUTPUT_ROOT" ] || [ -L "$OUTPUT_ROOT" ]; then
  echo "refuse to reuse opportunity-atlas output root: $OUTPUT_ROOT" >&2
  exit 2
fi

RUN_ROOT="$CAMPAIGN_ROOT/results/p0-$BASE_PREPARE_JOB_ID"
CHAIN_ROOT="$RUN_ROOT/continuations/chain-$CHAIN_ID"
mkdir -p "$OUTPUT_ROOT"
REPORT_TEMPORARY="$OUTPUT_ROOT/staged-analysis.json.tmp"
REPORT="$OUTPUT_ROOT/staged-analysis.json"

set +e
python3 "$ANALYSIS_TOOLS/analyze_staged_campaign.py" \
  --base-parent-lock "$RUN_ROOT/locks/$CORPUS_KIND-parent.json" \
  --base-shard-lock-dir "$RUN_ROOT/locks/$CORPUS_KIND" \
  --base-shard-results-root "$RUN_ROOT/$CORPUS_KIND-2s" \
  --stage "$CHAIN_ROOT/$CORPUS_KIND-60s/index.json" \
    "$CHAIN_ROOT/$CORPUS_KIND-60s/locks" \
    "$CHAIN_ROOT/$CORPUS_KIND-60s" \
  --stage "$CHAIN_ROOT/$CORPUS_KIND-1200s/index.json" \
    "$CHAIN_ROOT/$CORPUS_KIND-1200s/locks" \
    "$CHAIN_ROOT/$CORPUS_KIND-1200s" \
  --candidate euf-viper \
  --baseline yices2 \
  --bootstrap-replicates "$BOOTSTRAP_REPLICATES" \
  --confidence-level 0.95 \
  --out "$REPORT_TEMPORARY"
ANALYSIS_STATUS=$?
set -e
if [ "$ANALYSIS_STATUS" -ne 0 ] && [ "$ANALYSIS_STATUS" -ne 1 ]; then
  exit "$ANALYSIS_STATUS"
fi
mv "$REPORT_TEMPORARY" "$REPORT"

for BUDGET in 60 1200; do
  python3 "$ANALYSIS_TOOLS/analyze_yices_opportunity.py" \
    "$REPORT" \
    --input-format staged-analysis \
    --budget "$BUDGET" \
    --viper-solver euf-viper \
    --yices-solver yices2 \
    --out "$OUTPUT_ROOT/yices-opportunity-$BUDGET.json"
done

sha256sum "$REPORT" "$OUTPUT_ROOT"/yices-opportunity-*.json \
  > "$OUTPUT_ROOT/SHA256SUMS"
printf 'output_root=%s\n' "$OUTPUT_ROOT"
