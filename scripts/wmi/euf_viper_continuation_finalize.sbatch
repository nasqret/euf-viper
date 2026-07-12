#!/usr/bin/env bash
#SBATCH --job-name=euf-cont-finalize
#SBATCH --partition=cpu_idle
#SBATCH --cpus-per-task=1
#SBATCH --mem=4G
#SBATCH --time=00:30:00
#SBATCH --output=results/continuation-finalize-%j.out
#SBATCH --error=results/continuation-finalize-%j.err

set -euo pipefail

cd "${SLURM_SUBMIT_DIR:-$PWD}"
export PATH="$HOME/.cargo/bin:$HOME/.local/bin:$PATH"
export LANG=C
export LC_ALL=C
export TZ=UTC

EXPECTED_REVISION="${EUF_VIPER_EXPECTED_REVISION:?set EUF_VIPER_EXPECTED_REVISION}"
BASE_PREPARE_JOB_ID="${EUF_VIPER_BASE_PREPARE_JOB_ID:?set EUF_VIPER_BASE_PREPARE_JOB_ID}"
BASE_AUDIT_JOB_ID="${EUF_VIPER_BASE_AUDIT_JOB_ID:?set EUF_VIPER_BASE_AUDIT_JOB_ID}"
CHAIN_ID="${EUF_VIPER_CONTINUATION_CHAIN_ID:?set EUF_VIPER_CONTINUATION_CHAIN_ID}"

for VALUE in "$BASE_PREPARE_JOB_ID" "$BASE_AUDIT_JOB_ID" "$CHAIN_ID"; do
  case "$VALUE" in ''|0|0*|*[!0-9]*) echo "invalid positive integer: $VALUE" >&2; exit 2 ;; esac
done
if [ "$(git rev-parse HEAD)" != "$EXPECTED_REVISION" ]; then
  echo "repository revision drift in continuation finalizer" >&2
  exit 2
fi
if [ -n "$(git status --porcelain=v1 --untracked-files=no)" ]; then
  echo "tracked repository state is dirty in continuation finalizer" >&2
  exit 2
fi

CHAIN_ROOT="$PWD/results/p0-$BASE_PREPARE_JOB_ID/continuations/chain-$CHAIN_ID"
OUTPUT="$CHAIN_ROOT/analysis/index.json"
python3 - \
  "$OUTPUT" "$EXPECTED_REVISION" "$BASE_PREPARE_JOB_ID" \
  "$BASE_AUDIT_JOB_ID" "$CHAIN_ID" "$SLURM_JOB_ID" \
  "$CHAIN_ROOT/submissions/60.json" "$CHAIN_ROOT/submissions/1200.json" \
  "$CHAIN_ROOT/analysis/full.json" "$CHAIN_ROOT/analysis/official.json" <<'PY'
import hashlib
import json
import os
import sys
from pathlib import Path

(
    output_raw, revision, base_prepare, base_audit, chain_id, finalizer_job,
    submission_60_raw, submission_1200_raw, full_raw, official_raw,
) = sys.argv[1:]

def load(path_raw: str, context: str) -> tuple[Path, dict, str]:
    path = Path(path_raw).resolve()
    try:
        raw = path.read_bytes()
        payload = json.loads(raw)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise SystemExit(f"cannot read {context} {path}: {error}")
    if not isinstance(payload, dict):
        raise SystemExit(f"{context} must be a JSON object")
    return path, payload, hashlib.sha256(raw).hexdigest()

submission_60_path, submission_60, submission_60_hash = load(submission_60_raw, "60-second submission")
submission_1200_path, submission_1200, submission_1200_hash = load(submission_1200_raw, "1200-second submission")
for target, submission in ((60, submission_60), (1200, submission_1200)):
    if submission.get("schema_version") != 1 or submission.get("status") != "submitted":
        raise SystemExit(f"{target}-second submission index is invalid")
    if submission.get("revision") != revision or submission.get("chain_id") != int(chain_id):
        raise SystemExit(f"{target}-second submission lineage mismatch")
    if submission.get("target_budget_s") != target:
        raise SystemExit(f"{target}-second submission target mismatch")

corpora = {}
for kind, path_raw in (("full", full_raw), ("official", official_raw)):
    path, report, digest = load(path_raw, f"{kind} staged analysis")
    if report.get("schema_version") != 1 or report.get("status") not in {"promoted", "rejected"}:
        raise SystemExit(f"{kind} staged analysis status is invalid")
    inputs = report.get("inputs")
    assumptions = report.get("assumptions")
    if not isinstance(inputs, dict) or inputs.get("budgets_s") != [2.0, 60.0, 1200.0]:
        raise SystemExit(f"{kind} staged analysis budget ladder is incomplete")
    if not isinstance(assumptions, dict) or assumptions.get("complete_declared_budget_ladder") is not True:
        raise SystemExit(f"{kind} staged analysis is not globally complete")
    corpora[kind] = {
        "path": str(path),
        "sha256": digest,
        "status": report["status"],
        "promoted": report.get("promoted"),
        "instances": inputs.get("instances"),
        "physical_raw_records": inputs.get("physical_raw_records"),
        "carried_forward_observations": inputs.get("carried_forward_observations"),
        "stages": inputs.get("stages"),
    }

payload = {
    "schema_version": 1,
    "status": "complete",
    "revision": revision,
    "base_prepare_job_id": int(base_prepare),
    "base_audit_job_id": int(base_audit),
    "chain_id": int(chain_id),
    "finalizer_job_id": int(finalizer_job),
    "raw_artifact_policy": "immutable per-shard raw.jsonl; staged analysis is read-only",
    "submissions": {
        "60": {"path": str(submission_60_path), "sha256": submission_60_hash},
        "1200": {"path": str(submission_1200_path), "sha256": submission_1200_hash},
    },
    "corpora": corpora,
}
output = Path(output_raw)
encoded = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")
if output.exists() or output.is_symlink():
    if output.read_bytes() != encoded:
        raise SystemExit(f"refuse to replace final analysis index {output}")
else:
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(f".{output.name}.{os.getpid()}.tmp")
    temporary.write_bytes(encoded)
    temporary.replace(output)
print(json.dumps(payload, indent=2, sort_keys=True))
PY
