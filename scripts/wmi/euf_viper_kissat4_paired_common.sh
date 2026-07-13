#!/usr/bin/env bash

# Immutable evidence from WMI validation job 144945.
readonly KISSAT4_VALIDATION_REVISION="d7c14dac90615717b06e063274c42296a46e01a3"
readonly KISSAT4_VALIDATION_JOB_ID="144945"
readonly KISSAT4_DEFAULT_VALIDATION_ROOT="/home/bnaskrecki/euf-viper-campaigns/f513c33-modern-kissat/results/kissat4-validation-144945"
readonly KISSAT4_SC2021_NAME="euf-viper-kissat-sc2021"
readonly KISSAT4_MODERN_NAME="euf-viper-kissat-4.0.4"
readonly KISSAT4_SC2021_SHA256="d7321602b8cc86683ccb41e90bea7b843a5059caad62d1eba347bb3e69c70362"
readonly KISSAT4_MODERN_SHA256="ecbcfebb1f39c725c1d0266442c7dcc80083b8347e3b77d90bfb5646bd4ea6b6"
readonly KISSAT4_SC2021_VERSION="euf-viper 0.1.0 (sat=kissat-sc2021)"
readonly KISSAT4_MODERN_VERSION="euf-viper 0.1.0 (sat=kissat-4.0.4)"

# These values are passed to both binaries verbatim. The clean environment used
# by the runner prevents ambient EUF_VIPER_* values from changing either arm.
readonly -a KISSAT4_RUNTIME_SETTINGS=(
  "EUF_VIPER_AUTO_CADICAL_APP_THRESHOLD=1000"
  "EUF_VIPER_AXIOM_ORDER=native"
  "EUF_VIPER_AXIOM_SEED=11400714819323198485"
  "EUF_VIPER_BACKEND=kissat"
  "EUF_VIPER_CADICAL_CONFLICT_LIMIT="
  "EUF_VIPER_CADICAL_MODE=plain"
  "EUF_VIPER_CADICAL_OPTIONS="
  "EUF_VIPER_CADICAL_SEARCH_MODE=auto"
  "EUF_VIPER_CHORDAL_MAX_FILL=1000000"
  "EUF_VIPER_CHORDAL_TRANSITIVITY=off"
  "EUF_VIPER_CONGRUENCE_MODE=auto"
  "EUF_VIPER_DIRECT_NEGATED_ROOT=0"
  "EUF_VIPER_DIRECT_ROOT_CNF=1"
  "EUF_VIPER_EAGER_CONGRUENCE=auto"
  "EUF_VIPER_EQ_ABSTRACTION=off"
  "EUF_VIPER_EQ_ABSTRACTION_FRESH=0"
  "EUF_VIPER_EQ_ABSTRACTION_MAX_FACTS=4096"
  "EUF_VIPER_EQ_ABSTRACTION_MAX_FRESH_FACTS=256"
  "EUF_VIPER_FINITE_DOMAIN=0"
  "EUF_VIPER_FINITE_DOMAIN_MAX=11"
  "EUF_VIPER_FINITE_EQUALITY_CHANNELING=value-only"
  "EUF_VIPER_FINITE_LEX_MIN_DOMAIN=8"
  "EUF_VIPER_FINITE_PERMUTATION_CLIQUE_LIMIT=4096"
  "EUF_VIPER_FINITE_PERMUTATION_SUPPORT=0"
  "EUF_VIPER_FINITE_PREDICATE_CHANNELING=0"
  "EUF_VIPER_FINITE_SYMMETRY=hybrid"
  "EUF_VIPER_FINITE_SYMMETRY_MIN_APPS=1000"
  "EUF_VIPER_FULL_ACKERMANN=auto"
  "EUF_VIPER_INVALID_MODEL_FALLBACK=cadical-refine"
  "EUF_VIPER_KISSAT_MODE=default"
  "EUF_VIPER_KISSAT_OPTIONS="
  "EUF_VIPER_LEGACY_PREPROCESS_TERM_LIMIT=1024"
  "EUF_VIPER_MAX_THEORY_ROUNDS=10000"
  "EUF_VIPER_REFINEMENT_MODE=current"
  "EUF_VIPER_SCOPED_LET=auto"
)

# Presence enables profiling/tracing or test-only corpus probes, so these must
# remain absent from the sanitized solver environment.
readonly -a KISSAT4_EXPLICITLY_UNSET=(
  "EUF_VIPER_MDD_PROBE_CASE"
  "EUF_VIPER_NOVELTY_CENSUS_MANIFEST"
  "EUF_VIPER_NOVELTY_CENSUS_OUTPUT"
  "EUF_VIPER_ORBIT_PROBE_CASE"
  "EUF_VIPER_PORTFOLIO_TRACE"
  "EUF_VIPER_PROFILE"
)

readonly -a KISSAT4_CAMPAIGN_SCRIPTS=(
  "scripts/wmi/euf_viper_kissat4_paired_common.sh"
  "scripts/wmi/euf_viper_kissat4_paired.sbatch"
  "scripts/wmi/euf_viper_kissat4_paired_merge.sbatch"
  "scripts/wmi/submit_kissat4_paired.sh"
  "scripts/bench/compare_viper_ab.py"
  "scripts/bench/shard_manifest.py"
  "scripts/bench/merge_viper_ab.py"
  "scripts/bench/paired_promotion_gate.py"
)

kissat4_die() {
  printf 'kissat4-paired: %s\n' "$*" >&2
  exit 2
}

kissat4_require_positive_int() {
  local name="$1"
  local value="$2"
  case "$value" in
    ''|0|0*|*[!0-9]*) kissat4_die "$name must be a canonical positive integer" ;;
  esac
}

kissat4_require_nonnegative_int() {
  local name="$1"
  local value="$2"
  case "$value" in
    ''|*[!0-9]*) kissat4_die "$name must be a canonical non-negative integer" ;;
    0|[1-9]|[1-9][0-9]*) ;;
    *) kissat4_die "$name must be a canonical non-negative integer" ;;
  esac
}

kissat4_require_positive_decimal() {
  local name="$1"
  local value="$2"
  case "$value" in
    ''|*[!0-9.]*|*.*.*) kissat4_die "$name must be a positive decimal" ;;
  esac
  [[ "$value" =~ ^(0|[1-9][0-9]*)(\.[0-9]+)?$ ]] || \
    kissat4_die "$name must be a canonical positive decimal"
  awk -v value="$value" 'BEGIN { exit !(value > 0) }' || \
    kissat4_die "$name must be greater than zero"
}

kissat4_require_probability() {
  local name="$1"
  local value="$2"
  case "$value" in
    ''|*[!0-9.]*|*.*.*) kissat4_die "$name must be a decimal in [0, 1]" ;;
  esac
  [[ "$value" =~ ^(0|1)(\.[0-9]+)?$ ]] || \
    kissat4_die "$name must be a canonical decimal in [0, 1]"
  awk -v value="$value" 'BEGIN { exit !(value >= 0 && value <= 1) }' || \
    kissat4_die "$name must be in [0, 1]"
}

kissat4_require_safe_remote_value() {
  local name="$1"
  local value="$2"
  [ -n "$value" ] || kissat4_die "$name cannot be empty"
  case "$value" in
    *[!A-Za-z0-9_./:@+-]*) kissat4_die "$name contains unsafe shell or sbatch characters" ;;
  esac
}

kissat4_sha256() {
  sha256sum "$1" | awk '{print $1}'
}

kissat4_emit_script_hashes() {
  local path
  for path in "${KISSAT4_CAMPAIGN_SCRIPTS[@]}"; do
    [ -f "$path" ] || kissat4_die "missing campaign script: $path"
    printf '%s  %s\n' "$(kissat4_sha256 "$path")" "$path"
  done
}

kissat4_script_bundle_sha256() {
  kissat4_emit_script_hashes | sha256sum | awk '{print $1}'
}

kissat4_check_repository() {
  local expected_revision="$1"
  local actual_revision
  local dirty
  actual_revision="$(git rev-parse HEAD)"
  [ "$actual_revision" = "$expected_revision" ] || \
    kissat4_die "revision mismatch: expected $expected_revision, got $actual_revision"
  git merge-base --is-ancestor "$KISSAT4_VALIDATION_REVISION" "$expected_revision" || \
    kissat4_die "revision is not descended from validated revision $KISSAT4_VALIDATION_REVISION"
  git diff --quiet "$KISSAT4_VALIDATION_REVISION" "$expected_revision" -- . \
    ':(exclude)scripts/wmi/**' ':(exclude)tests/**' || \
    kissat4_die "revision changes files outside scripts/wmi and tests since validation"
  # The WMI checkout carries one generated corpus symlink at this ignored-tree
  # location. Its manifest and every selected source are hash-checked separately.
  dirty="$(git status --porcelain=v1 --untracked-files=all -- . \
    ':(exclude)benchmarks/smtlib-2025')"
  [ -z "$dirty" ] || kissat4_die "repository worktree is not clean"
}

kissat4_check_script_bundle() {
  local expected_sha256="$1"
  local actual_sha256
  actual_sha256="$(kissat4_script_bundle_sha256)"
  [ "$actual_sha256" = "$expected_sha256" ] || \
    kissat4_die "campaign script bundle mismatch: expected $expected_sha256, got $actual_sha256"
}

kissat4_check_binaries() {
  local validation_root="$1"
  local sc2021="$validation_root/$KISSAT4_SC2021_NAME"
  local modern="$validation_root/$KISSAT4_MODERN_NAME"
  local actual
  [ -f "$sc2021" ] && [ -x "$sc2021" ] || \
    kissat4_die "missing validated binary: $sc2021"
  [ -f "$modern" ] && [ -x "$modern" ] || \
    kissat4_die "missing validated binary: $modern"
  [ ! "$sc2021" -ef "$modern" ] || kissat4_die "validated binaries resolve to the same file"
  actual="$(kissat4_sha256 "$sc2021")"
  [ "$actual" = "$KISSAT4_SC2021_SHA256" ] || \
    kissat4_die "$KISSAT4_SC2021_NAME SHA-256 mismatch: $actual"
  actual="$(kissat4_sha256 "$modern")"
  [ "$actual" = "$KISSAT4_MODERN_SHA256" ] || \
    kissat4_die "$KISSAT4_MODERN_NAME SHA-256 mismatch: $actual"
  actual="$("$sc2021" --version 2>&1)"
  [ "$actual" = "$KISSAT4_SC2021_VERSION" ] || \
    kissat4_die "$KISSAT4_SC2021_NAME backend identity mismatch: $actual"
  actual="$("$modern" --version 2>&1)"
  [ "$actual" = "$KISSAT4_MODERN_VERSION" ] || \
    kissat4_die "$KISSAT4_MODERN_NAME backend identity mismatch: $actual"
  KISSAT4_SC2021_BIN="$sc2021"
  KISSAT4_MODERN_BIN="$modern"
  export KISSAT4_SC2021_BIN KISSAT4_MODERN_BIN
}

kissat4_verify_manifest() {
  local manifest="$1"
  local expected_sha256="$2"
  local summary="$3"
  local actual_sha256
  actual_sha256="$(kissat4_sha256 "$manifest")"
  [ "$actual_sha256" = "$expected_sha256" ] || \
    kissat4_die "manifest SHA-256 mismatch: expected $expected_sha256, got $actual_sha256"
  python3 - "$manifest" "$summary" <<'PY_MANIFEST'
import hashlib
import json
import sys
from pathlib import Path

manifest = Path(sys.argv[1])
summary = Path(sys.argv[2])
rows = []
seen = set()
for line_number, line in enumerate(manifest.read_text(encoding="utf-8").splitlines(), 1):
    if not line.strip():
        continue
    try:
        row = json.loads(line)
    except json.JSONDecodeError as error:
        raise SystemExit(f"{manifest}:{line_number}: invalid JSON: {error}")
    for key in ("path", "relative_path", "sha256", "status"):
        if not isinstance(row.get(key), str) or not row[key]:
            raise SystemExit(f"{manifest}:{line_number}: missing string field {key}")
    if row["status"] not in {"sat", "unsat"}:
        raise SystemExit(f"{manifest}:{line_number}: non-decisive status")
    if row["relative_path"] in seen:
        raise SystemExit(f"{manifest}:{line_number}: duplicate relative_path")
    seen.add(row["relative_path"])
    source = Path(row["path"])
    if source.is_absolute() or ".." in source.parts:
        raise SystemExit(f"{manifest}:{line_number}: unsafe source path")
    if not source.is_file():
        raise SystemExit(f"{manifest}:{line_number}: missing source {source}")
    digest_builder = hashlib.sha256()
    with source.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest_builder.update(chunk)
    digest = digest_builder.hexdigest()
    if digest != row["sha256"]:
        raise SystemExit(f"{manifest}:{line_number}: source SHA-256 mismatch")
    rows.append(row)
if not rows:
    raise SystemExit(f"{manifest}: no benchmark rows")
payload = {
    "schema_version": 1,
    "manifest": str(manifest.resolve()),
    "manifest_sha256": hashlib.sha256(manifest.read_bytes()).hexdigest(),
    "instances": len(rows),
    "sat": sum(row["status"] == "sat" for row in rows),
    "unsat": sum(row["status"] == "unsat" for row in rows),
    "sources_verified": len(rows),
}
summary.parent.mkdir(parents=True, exist_ok=True)
temporary = summary.with_name(f".{summary.name}.tmp")
temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
temporary.replace(summary)
PY_MANIFEST
}

kissat4_make_sample_manifest() {
  local source="$1"
  local limit="$2"
  local seed="$3"
  local output="$4"
  python3 - "$source" "$limit" "$seed" "$output" <<'PY_SAMPLE'
import hashlib
import json
import sys
from pathlib import Path

source = Path(sys.argv[1])
limit = int(sys.argv[2])
seed = sys.argv[3]
output = Path(sys.argv[4])
rows = [json.loads(line) for line in source.read_text(encoding="utf-8").splitlines() if line.strip()]
if not 0 < limit <= len(rows):
    raise SystemExit(f"sample limit {limit} is outside [1, {len(rows)}]")
ranked = sorted(
    rows,
    key=lambda row: (
        hashlib.sha256(f"{seed}\0{row['relative_path']}".encode("utf-8")).digest(),
        row["relative_path"],
    ),
)
selected = ranked[:limit]
output.parent.mkdir(parents=True, exist_ok=True)
output.write_text(
    "".join(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n" for row in selected),
    encoding="utf-8",
)
PY_SAMPLE
}

kissat4_rebind_manifest_sources() {
  local manifest="$1"
  python3 - "$manifest" <<'PY_REBIND'
import json
import os
import sys
import tempfile
from pathlib import Path, PurePosixPath

manifest = Path(sys.argv[1])
rows = []
for line_number, line in enumerate(manifest.read_text(encoding="utf-8").splitlines(), 1):
    if not line.strip():
        continue
    try:
        row = json.loads(line)
    except json.JSONDecodeError as error:
        raise SystemExit(f"{manifest}:{line_number}: invalid JSON: {error}")
    relative_raw = row.get("relative_path")
    if not isinstance(relative_raw, str) or not relative_raw:
        raise SystemExit(f"{manifest}:{line_number}: missing relative_path")
    relative = PurePosixPath(relative_raw)
    if (
        relative.is_absolute()
        or not relative.parts
        or relative.parts[0] != "QF_UF"
        or any(part in {"", ".", ".."} for part in relative.parts)
    ):
        raise SystemExit(f"{manifest}:{line_number}: unsafe relative_path")
    # The release archive keeps its own QF_UF directory below QF_UF.tar.zst.
    rebound = Path("benchmarks/smtlib-2025/QF_UF").joinpath(*relative.parts)
    row["path"] = rebound.as_posix()
    rows.append(row)
if not rows:
    raise SystemExit(f"{manifest}: no benchmark rows")

payload = "".join(
    json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n"
    for row in rows
).encode("utf-8")
descriptor, temporary_raw = tempfile.mkstemp(
    prefix=f".{manifest.name}.", suffix=".tmp", dir=manifest.parent
)
temporary = Path(temporary_raw)
try:
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, manifest)
finally:
    temporary.unlink(missing_ok=True)
PY_REBIND
}
