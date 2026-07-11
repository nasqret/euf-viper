#!/usr/bin/env bash
#SBATCH --job-name=euf-viper-qg7-rtxc
#SBATCH --partition=cpu_idle
#SBATCH --cpus-per-task=1
#SBATCH --mem=8G
#SBATCH --time=01:00:00
#SBATCH --output=results/wmi-qg7-rtxc-census-%j.out
#SBATCH --error=results/wmi-qg7-rtxc-census-%j.err

set -euo pipefail

ROOT_INPUT="${EUF_VIPER_ROOT:-${SLURM_SUBMIT_DIR:-$PWD}}"
QG7_DIR_INPUT="${EUF_VIPER_QG7_CENSUS_DIR:?set EUF_VIPER_QG7_CENSUS_DIR}"
LIMIT="${EUF_VIPER_QG7_CENSUS_LIMIT:-512}"
OFFSET="${EUF_VIPER_QG7_CENSUS_OFFSET:-0}"
EXPECTED="${EUF_VIPER_QG7_CENSUS_EXPECTED:?set EUF_VIPER_QG7_CENSUS_EXPECTED to the positive exact record count}"
REQUESTED_REVISION="${EUF_VIPER_GIT_REVISION:?set EUF_VIPER_GIT_REVISION to the exact 40-character commit}"
JOB_ID="${SLURM_JOB_ID:?SLURM_JOB_ID is required}"
RUN_ID="${EUF_VIPER_QG7_CENSUS_RUN_ID:-$JOB_ID}"
OUTPUT_INPUT="${EUF_VIPER_QG7_CENSUS_OUTPUT:-}"
SCRATCH_ROOT="${SLURM_TMPDIR:-/tmp/${USER:?}/euf-viper-$JOB_ID}"

if [[ ! "$LIMIT" =~ ^[1-9][0-9]*$ ]] || ((LIMIT > 512)); then
  printf 'EUF_VIPER_QG7_CENSUS_LIMIT must be an integer in 1..512, got %q\n' "$LIMIT" >&2
  exit 2
fi
if [[ ! "$OFFSET" =~ ^(0|[1-9][0-9]*)$ ]]; then
  printf 'EUF_VIPER_QG7_CENSUS_OFFSET must be a nonnegative integer, got %q\n' "$OFFSET" >&2
  exit 2
fi
if [[ ! "$EXPECTED" =~ ^[1-9][0-9]*$ ]] || ((EXPECTED > LIMIT)); then
  printf 'EUF_VIPER_QG7_CENSUS_EXPECTED must be an integer in 1..%s, got %q\n' "$LIMIT" "$EXPECTED" >&2
  exit 2
fi
if [[ ! "$REQUESTED_REVISION" =~ ^[0-9a-fA-F]{40}$ ]]; then
  printf 'EUF_VIPER_GIT_REVISION must be an exact 40-character commit, got %q\n' \
    "$REQUESTED_REVISION" >&2
  exit 2
fi
if [[ ! "$RUN_ID" =~ ^[A-Za-z0-9._-]+$ ]]; then
  printf 'EUF_VIPER_QG7_CENSUS_RUN_ID contains unsafe characters: %q\n' "$RUN_ID" >&2
  exit 2
fi

for tool in cargo git python3 sha256sum tar; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    printf 'required tool is unavailable: %s\n' "$tool" >&2
    exit 2
  fi
done

cd "$ROOT_INPUT"
ROOT="$(pwd -P)"
test -d "$QG7_DIR_INPUT"
QG7_DIR="$(cd "$QG7_DIR_INPUT" && pwd -P)"
if [[ -n "$OUTPUT_INPUT" ]]; then
  OUTPUT="$OUTPUT_INPUT"
else
  OUTPUT="$ROOT/results/qg7-rtxc-census-$RUN_ID.jsonl"
fi
case "$OUTPUT" in
  *.jsonl) ;;
  *)
    printf 'EUF_VIPER_QG7_CENSUS_OUTPUT must end in .jsonl, got %q\n' "$OUTPUT" >&2
    exit 2
    ;;
esac
mkdir -p "$(dirname "$OUTPUT")"
OUTPUT_DIR="$(cd "$(dirname "$OUTPUT")" && pwd -P)"
OUTPUT_BASE="$(basename "$OUTPUT")"
OUTPUT="$OUTPUT_DIR/$OUTPUT_BASE"
case "$OUTPUT" in
  "$ROOT"/results/*) ;;
  "$ROOT"/*)
    printf 'repo-local census output is allowed only below %s/results, got %s\n' \
      "$ROOT" "$OUTPUT" >&2
    exit 2
    ;;
esac

# Remove the final name before any fallible source/build work. Until the atomic
# rename below succeeds, absence of OUTPUT means this run has not published.
rm -f -- "$OUTPUT"

RUN_SCRATCH=""
PUBLISH_TMP=""
cleanup() {
  status=$?
  trap - EXIT
  set +e
  if [[ -n "$PUBLISH_TMP" ]]; then
    rm -f -- "$PUBLISH_TMP"
  fi
  if [[ -n "$RUN_SCRATCH" ]]; then
    rm -rf -- "$RUN_SCRATCH"
  fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

REVISION="$(git rev-parse --verify "${REQUESTED_REVISION}^{commit}")"
HEAD_REVISION="$(git rev-parse --verify HEAD)"
if [[ "$REVISION" != "$HEAD_REVISION" ]]; then
  printf 'requested revision %s does not match checked-out revision %s\n' \
    "$REVISION" "$HEAD_REVISION" >&2
  exit 2
fi

# `results/` and `target/` are the normal repo-local output/build dirs and are
# ignored. Every tracked or non-ignored untracked path is relevant and is
# rejected. Compilation still uses an archive below, so ignored files cannot
# enter the build either.
WORKTREE_STATUS="$(git status --porcelain --untracked-files=all)"
if [[ -n "$WORKTREE_STATUS" ]]; then
  printf 'refusing census from a dirty worktree:\n%s\n' "$WORKTREE_STATUS" >&2
  exit 2
fi

mkdir -p "$SCRATCH_ROOT"
RUN_SCRATCH="$(mktemp -d "$SCRATCH_ROOT/qg7-census.$RUN_ID.XXXXXX")"
SOURCE_ARCHIVE="$RUN_SCRATCH/source.tar"
SOURCE_DIR="$RUN_SCRATCH/source"
TARGET_DIR="$RUN_SCRATCH/target"
RAW_OUTPUT="$RUN_SCRATCH/census.raw.log"
mkdir -p "$SOURCE_DIR"

git archive --format=tar --output="$SOURCE_ARCHIVE" "$REVISION"
ARCHIVE_REVISION="$(git get-tar-commit-id <"$SOURCE_ARCHIVE")"
if [[ "$ARCHIVE_REVISION" != "$REVISION" ]]; then
  printf 'git archive commit %s does not match requested revision %s\n' \
    "$ARCHIVE_REVISION" "$REVISION" >&2
  exit 2
fi
SOURCE_TREE="$(git rev-parse --verify "${REVISION}^{tree}")"
SOURCE_ARCHIVE_SHA256="$(sha256sum "$SOURCE_ARCHIVE" | awk '{print $1}')"
tar -xf "$SOURCE_ARCHIVE" -C "$SOURCE_DIR"

EXECUTING_WRAPPER_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
EXECUTING_WRAPPER="$EXECUTING_WRAPPER_DIR/$(basename "${BASH_SOURCE[0]}")"
ARCHIVED_WRAPPER="$SOURCE_DIR/scripts/wmi/euf_viper_qg7_rtxc_census.sbatch"
test -f "$ARCHIVED_WRAPPER"
EXECUTING_WRAPPER_SHA256="$(sha256sum "$EXECUTING_WRAPPER" | awk '{print $1}')"
ARCHIVED_WRAPPER_SHA256="$(sha256sum "$ARCHIVED_WRAPPER" | awk '{print $1}')"
if [[ "$EXECUTING_WRAPPER_SHA256" != "$ARCHIVED_WRAPPER_SHA256" ]]; then
  printf 'executing wrapper does not match archived revision %s\n' "$REVISION" >&2
  exit 2
fi

export PATH="$HOME/.cargo/bin:$PATH"
export CARGO_TARGET_DIR="$TARGET_DIR"
export CARGO_INCREMENTAL=0
export RUST_MIN_STACK="${EUF_VIPER_QG7_CENSUS_STACK_BYTES:-67108864}"
export EUF_VIPER_QG7_CENSUS_DIR="$QG7_DIR"
export EUF_VIPER_QG7_CENSUS_LIMIT="$LIMIT"
export EUF_VIPER_QG7_CENSUS_OFFSET="$OFFSET"
export EUF_VIPER_QG7_CENSUS_EXPECTED="$EXPECTED"
export EUF_VIPER_GIT_REVISION="$REVISION"

printf 'revision=%s\n' "$REVISION"
printf 'source_tree=%s\n' "$SOURCE_TREE"
printf 'source_archive_sha256=%s\n' "$SOURCE_ARCHIVE_SHA256"
printf 'qg7_dir=%s\n' "$QG7_DIR"
printf 'limit=%s offset=%s expected=%s output=%s\n' "$LIMIT" "$OFFSET" "$EXPECTED" "$OUTPUT"

cd "$SOURCE_DIR"
cargo test --locked --release --all-features \
  forbidden_orbit_probe::tests::bounded_qg7_partial_pattern_census \
  -- --ignored --exact --nocapture >"$RAW_OUTPUT"

PUBLISH_TMP="$(mktemp "$OUTPUT_DIR/.$OUTPUT_BASE.tmp.XXXXXX")"
python3 - \
  "$RAW_OUTPUT" \
  "$PUBLISH_TMP" \
  "$EXPECTED" \
  "$REVISION" \
  "$SOURCE_TREE" \
  "$SOURCE_ARCHIVE_SHA256" \
  "$ARCHIVE_REVISION" \
  "$ARCHIVED_WRAPPER_SHA256" \
  "$QG7_DIR" \
  "$OFFSET" \
  "$LIMIT" <<'PY'
import json
import os
import sys

(
    raw_path,
    publish_path,
    expected_text,
    revision,
    source_tree,
    archive_sha256,
    archive_revision,
    wrapper_sha256,
    qg7_dir,
    offset_text,
    limit_text,
) = sys.argv[1:]
expected = int(expected_text)
offset = int(offset_text)
limit = int(limit_text)
marker = "QG7_CENSUS_JSON:"
records = []

with open(raw_path, encoding="utf-8") as raw:
    for line_number, line in enumerate(raw, 1):
        marker_at = line.find(marker)
        if marker_at < 0:
            continue
        payload = line[marker_at + len(marker):].strip()
        try:
            record = json.loads(payload)
        except json.JSONDecodeError as error:
            raise SystemExit(f"invalid census JSON on raw line {line_number}: {error}")
        if not isinstance(record, dict):
            raise SystemExit(f"census JSON on raw line {line_number} is not an object")
        records.append(record)

provenance = [record for record in records if record.get("record_type") == "provenance"]
cases = [record for record in records if record.get("record_type") == "case"]
if len(provenance) != 1:
    raise SystemExit(f"expected one provenance record, found {len(provenance)}")
if len(cases) != expected:
    raise SystemExit(f"expected {expected} case records, found {len(cases)}")
if len(records) != expected + 1:
    raise SystemExit(f"expected {expected + 1} total records, found {len(records)}")
if records[0] is not provenance[0]:
    raise SystemExit("provenance record must be first")

source_provenance = provenance[0]
required = {
    "revision": revision,
    "directory": qg7_dir,
    "offset": offset,
    "limit": limit,
    "expected_records": expected,
    "selected_records": expected,
}
for key, value in required.items():
    if source_provenance.get(key) != value:
        raise SystemExit(
            f"provenance {key} mismatch: expected {value!r}, "
            f"found {source_provenance.get(key)!r}"
        )

case_paths = [record.get("path") for record in cases]
if any(not isinstance(path, str) or not path for path in case_paths):
    raise SystemExit("every case record must have a nonempty string path")
if len(set(case_paths)) != len(case_paths):
    raise SystemExit("duplicate case paths in census output")

source_provenance.update(
    {
        "source_materialization": "git_archive",
        "source_revision": revision,
        "source_tree": source_tree,
        "source_archive_commit": archive_revision,
        "source_archive_sha256": archive_sha256,
        "wrapper_sha256": wrapper_sha256,
        "worktree_status": "clean",
    }
)

with open(publish_path, "w", encoding="utf-8", newline="\n") as output:
    for record in records:
        output.write(json.dumps(record, sort_keys=True, separators=(",", ":")))
        output.write("\n")
    output.flush()
    os.fsync(output.fileno())

with open(publish_path, encoding="utf-8") as candidate:
    published = [json.loads(line) for line in candidate if line.strip()]
if len(published) != expected + 1:
    raise SystemExit("published JSONL record count changed during validation")
if sum(record.get("record_type") == "provenance" for record in published) != 1:
    raise SystemExit("published JSONL provenance count is not one")
if sum(record.get("record_type") == "case" for record in published) != expected:
    raise SystemExit("published JSONL case count does not match expected")
PY

test -s "$PUBLISH_TMP"
mv -f -- "$PUBLISH_TMP" "$OUTPUT"
PUBLISH_TMP=""

printf 'records=%s\n' "$EXPECTED"
printf 'output_sha256=%s\n' "$(sha256sum "$OUTPUT" | awk '{print $1}')"
