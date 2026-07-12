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
OUTPUT_INPUT="${EUF_VIPER_QG7_CENSUS_OUTPUT:-}"
JOB_ID_INPUT="${SLURM_JOB_ID:-}"
RUN_ID_INPUT="${EUF_VIPER_QG7_CENSUS_RUN_ID:-}"

ROOT=""
ROOT_RESOLVED=0
OUTPUT=""
OUTPUT_DIR=""
OUTPUT_BASE=""
OUTPUT_READY=0
RUN_SCRATCH=""
PUBLISH_TMP=""
PUBLICATION_COMPLETE=0

fsync_directory() {
  python3 - "$1" <<'PY'
import os
import sys

directory = sys.argv[1]
flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
descriptor = os.open(directory, flags)
try:
    os.fsync(descriptor)
finally:
    os.close(descriptor)
PY
}

canonical_output_path() {
  python3 - "$1" "$2" <<'PY'
import os
import sys

path, base = sys.argv[1:]
if not os.path.isabs(path):
    path = os.path.join(base, path)
path = os.path.abspath(path)
parent = os.path.realpath(os.path.dirname(path))
print(os.path.join(parent, os.path.basename(path)))
PY
}

is_recognized_census_output() {
  python3 - "$1" <<'PY'
import json
import sys

records = []
with open(sys.argv[1], encoding="utf-8") as source:
    for line in source:
        if line.strip():
            record = json.loads(line)
            if not isinstance(record, dict):
                raise SystemExit(1)
            records.append(record)

if not records:
    raise SystemExit(1)
if records[0].get("record_type") != "provenance":
    raise SystemExit(1)
if records[0].get("schema") != "euf-viper.qg7-rtxc-census.v1":
    raise SystemExit(1)
if sum(record.get("record_type") == "provenance" for record in records) != 1:
    raise SystemExit(1)
if any(record.get("record_type") not in {"provenance", "case"} for record in records):
    raise SystemExit(1)
PY
}

reject_repo_local_output() {
  case "$OUTPUT" in
    "$ROOT"/results/*) return 1 ;;
    "$ROOT"/*) return 0 ;;
    *) return 1 ;;
  esac
}

authorize_existing_explicit_output() {
  if [[ ! -e "$OUTPUT" && ! -L "$OUTPUT" ]]; then
    return
  fi
  if [[ -L "$OUTPUT" || ! -f "$OUTPUT" ]]; then
    printf 'refusing to replace non-regular explicit census output: %s\n' "$OUTPUT" >&2
    exit 2
  fi
  if ! is_recognized_census_output "$OUTPUT"; then
    printf 'refusing to remove unrecognized explicit census output: %s\n' "$OUTPUT" >&2
    exit 2
  fi
}

invalidate_output() {
  OUTPUT_READY=1
  rm -f -- "$OUTPUT"
  fsync_directory "$OUTPUT_DIR"
}

cleanup() {
  status=$?
  trap - EXIT
  set +e
  if ((OUTPUT_READY && !PUBLICATION_COMPLETE)); then
    rm -f -- "$OUTPUT"
    if command -v python3 >/dev/null 2>&1; then
      fsync_directory "$OUTPUT_DIR"
    fi
  fi
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

if [[ -n "${HOME:-}" ]]; then
  export PATH="$HOME/.cargo/bin:$PATH"
fi

if ! command -v python3 >/dev/null 2>&1; then
  printf 'required tool is unavailable: python3\n' >&2
  exit 2
fi

if ROOT="$(cd "$ROOT_INPUT" 2>/dev/null && pwd -P)"; then
  ROOT_RESOLVED=1
fi

if [[ -n "$OUTPUT_INPUT" ]]; then
  case "$OUTPUT_INPUT" in
    *.jsonl) ;;
    *)
      printf 'EUF_VIPER_QG7_CENSUS_OUTPUT must end in .jsonl, got %q\n' \
        "$OUTPUT_INPUT" >&2
      exit 2
      ;;
  esac
  if [[ "$OUTPUT_INPUT" != /* && "$ROOT_RESOLVED" -ne 1 ]]; then
    printf 'cannot resolve relative census output without EUF_VIPER_ROOT\n' >&2
    exit 2
  fi
  OUTPUT="$(canonical_output_path "$OUTPUT_INPUT" "${ROOT:-$PWD}")"
  OUTPUT_DIR="$(dirname "$OUTPUT")"
  OUTPUT_BASE="$(basename "$OUTPUT")"

  if ((ROOT_RESOLVED)) && reject_repo_local_output; then
    printf 'repo-local census output is allowed only below %s/results, got %s\n' \
      "$ROOT" "$OUTPUT" >&2
    exit 2
  fi

  if ((!ROOT_RESOLVED)); then
    authorize_existing_explicit_output
    if [[ -d "$OUTPUT_DIR" ]]; then
      invalidate_output
    fi
    printf 'cannot resolve EUF_VIPER_ROOT: %s\n' "$ROOT_INPUT" >&2
    exit 2
  fi

  mkdir -p "$OUTPUT_DIR"
  OUTPUT_DIR="$(cd "$OUTPUT_DIR" && pwd -P)"
  OUTPUT="$OUTPUT_DIR/$OUTPUT_BASE"
  if reject_repo_local_output; then
    printf 'repo-local census output is allowed only below %s/results, got %s\n' \
      "$ROOT" "$OUTPUT" >&2
    exit 2
  fi
  authorize_existing_explicit_output
else
  if ((!ROOT_RESOLVED)); then
    printf 'cannot resolve EUF_VIPER_ROOT: %s\n' "$ROOT_INPUT" >&2
    exit 2
  fi
  OUTPUT_RUN_ID="${RUN_ID_INPUT:-$JOB_ID_INPUT}"
  if [[ -z "$OUTPUT_RUN_ID" ]]; then
    printf 'SLURM_JOB_ID is required when EUF_VIPER_QG7_CENSUS_OUTPUT is unset\n' >&2
    exit 2
  fi
  if [[ ! "$OUTPUT_RUN_ID" =~ ^[A-Za-z0-9._-]+$ ]]; then
    printf 'cannot derive a safe default census output from run id %q\n' \
      "$OUTPUT_RUN_ID" >&2
    exit 2
  fi
  OUTPUT_DIR="$ROOT/results"
  OUTPUT_BASE="qg7-rtxc-census-$OUTPUT_RUN_ID.jsonl"
  mkdir -p "$OUTPUT_DIR"
  OUTPUT_DIR="$(cd "$OUTPUT_DIR" && pwd -P)"
  OUTPUT="$OUTPUT_DIR/$OUTPUT_BASE"
fi

# The explicit target is either absent or a recognized prior census, and any
# repo-local target has passed policy checks before parent creation. Arm cleanup
# and durably invalidate the final name before all remaining run preflights.
invalidate_output
cd "$ROOT"

QG7_DIR_INPUT="${EUF_VIPER_QG7_CENSUS_DIR:-}"
LIMIT="${EUF_VIPER_QG7_CENSUS_LIMIT:-512}"
OFFSET="${EUF_VIPER_QG7_CENSUS_OFFSET:-0}"
EXPECTED="${EUF_VIPER_QG7_CENSUS_EXPECTED:-}"
REQUESTED_REVISION="${EUF_VIPER_GIT_REVISION:-}"
JOB_ID="$JOB_ID_INPUT"
RUN_ID="${RUN_ID_INPUT:-$JOB_ID}"

if [[ -z "$JOB_ID" ]]; then
  printf 'SLURM_JOB_ID is required\n' >&2
  exit 2
fi
if [[ -z "$QG7_DIR_INPUT" ]]; then
  printf 'set EUF_VIPER_QG7_CENSUS_DIR\n' >&2
  exit 2
fi
if [[ -z "$EXPECTED" ]]; then
  printf 'set EUF_VIPER_QG7_CENSUS_EXPECTED to the positive exact record count\n' >&2
  exit 2
fi
if [[ -z "$REQUESTED_REVISION" ]]; then
  printf 'set EUF_VIPER_GIT_REVISION to the exact 40-character commit\n' >&2
  exit 2
fi
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

test -d "$QG7_DIR_INPUT"
QG7_DIR="$(cd "$QG7_DIR_INPUT" && pwd -P)"
if [[ -n "${SLURM_TMPDIR:-}" ]]; then
  SCRATCH_ROOT="$SLURM_TMPDIR"
elif [[ -n "${USER:-}" ]]; then
  SCRATCH_ROOT="/tmp/$USER/euf-viper-$JOB_ID"
else
  printf 'USER is required when SLURM_TMPDIR is unset\n' >&2
  exit 2
fi

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
fsync_directory "$OUTPUT_DIR"
PUBLICATION_COMPLETE=1

printf 'records=%s\n' "$EXPECTED"
printf 'output_sha256=%s\n' "$(sha256sum "$OUTPUT" | awk '{print $1}')"
