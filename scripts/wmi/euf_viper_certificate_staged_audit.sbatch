#!/usr/bin/env bash
#SBATCH --job-name=euf-cert-staged
#SBATCH --partition=cpu_idle
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=1
#SBATCH --mem=12G
#SBATCH --time=04:00:00
#SBATCH --output=results/certificate-staged-audit-%j.out
#SBATCH --error=results/certificate-staged-audit-%j.err

set -euo pipefail
umask 077

cd "${SLURM_SUBMIT_DIR:-$PWD}"
export PATH="$HOME/.cargo/bin:$HOME/.local/bin:/usr/local/bin:/usr/bin:/bin"
export LANG=C
export LC_ALL=C
export TZ=UTC

EXPECTED_REVISION="${EUF_VIPER_CERT_EXPECTED_REVISION:?set EUF_VIPER_CERT_EXPECTED_REVISION}"
ANALYSIS="${EUF_VIPER_CERT_STAGED_ANALYSIS:?set EUF_VIPER_CERT_STAGED_ANALYSIS}"
STAGE_AUDITS="${EUF_VIPER_CERT_STAGE_AUDITS:?set colon-separated physical-stage audits}"
OUTPUT="${EUF_VIPER_CERT_STAGED_OUTPUT:?set EUF_VIPER_CERT_STAGED_OUTPUT}"

if [ "${SLURM_CPUS_PER_TASK:-1}" != 1 ]; then
  echo "staged certificate audit requires exactly one allocated core" >&2
  exit 2
fi
if [ "$(git rev-parse HEAD)" != "$EXPECTED_REVISION" ]; then
  echo "repository revision drift in staged certificate audit" >&2
  exit 2
fi
if [ -n "$(git status --porcelain=v1 --untracked-files=all)" ]; then
  echo "repository state is dirty in staged certificate audit" >&2
  exit 2
fi
case "$ANALYSIS:$OUTPUT" in /*:/*) ;; *) echo "analysis and output paths must be absolute" >&2; exit 2 ;; esac
case "$STAGE_AUDITS" in *[!A-Za-z0-9_./:-]*) echo "stage audit paths contain unsafe characters" >&2; exit 2 ;; esac

IFS=: read -r -a AUDITS <<< "$STAGE_AUDITS"
if [ "${#AUDITS[@]}" -lt 1 ]; then
  echo "at least one physical-stage certificate audit is required" >&2
  exit 2
fi
COMMAND=(
  python3 scripts/cert/audit_staged_shadow_campaign.py
  --analysis "$ANALYSIS"
  --candidate euf-viper
  --out "$OUTPUT"
)
for AUDIT in "${AUDITS[@]}"; do
  case "$AUDIT" in /*) ;; *) echo "stage audit path must be absolute: $AUDIT" >&2; exit 2 ;; esac
  test -s "$AUDIT"
  COMMAND+=(--stage-audit "$AUDIT")
done

"${COMMAND[@]}"
