#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
REMOTE_HOST="${EUF_VIPER_WMI_HOST:-wmicluster}"
REPOSITORY_URL="${EUF_VIPER_PGO_REPOSITORY_URL:-https://github.com/nasqret/euf-viper.git}"
PUBLISHED_REF="${EUF_VIPER_PGO_PUBLISHED_REF:-refs/heads/perf-viper-fabric-next}"
WORK_ROOT="${EUF_VIPER_PGO_WORK_ROOT:-}"
CORPUS_ROOT="${EUF_VIPER_PGO_CORPUS_ROOT:-}"
PARTITION="${EUF_VIPER_PGO_PARTITION:-cpu_idle}"
WALL_TIME="${EUF_VIPER_PGO_WALL_TIME:-18:00:00}"
RUN_ID="${EUF_VIPER_PGO_RUN_ID:-}"
EXPECTED_CARGO_SHA256=9548937d530bf439ff1ba47a3b2bd26eeb9c3aff1961c20c01798613de922578
EXPECTED_RUSTC_SHA256=d32249a7c3bfcfc67b471460386e46323accae7125e344567a12d5664d99bb57
EXPECTED_LLVM_PROFDATA_SHA256=ca4b4344f2bca8fbab8ef1f7f5527070059969f76b3838d7ccf916de4fdbb6f3
EXPECTED_PYTHON_SHA256=7d51cd6b48b521277f5caa4610a82126e315fa2be4df069823a8b1eeb5bd4a86
EXPECTED_Z3_SHA256=a06c2a851d58c5f5a7c1e5de188fd0e1b1135e778112aee83ffd1a433685516b
EXPECTED_YICES_SHA256=eab7efbff2a6f0cce2fcd2c25cb4a94e0e048c902d8ef9e6fd7d7989aa54c501
EXPECTED_CVC5_SHA256=7562a8b0b835e3eaad5f1a7b4616cd762350cf567b6be03d7e8ee24fa5ced5ee
EXPECTED_COMPETITOR_RECEIPT_SHA256=2eb96f2868de7e661855b33a41f0213f51251a694669812c25839c52cbd8525a

die() {
  printf '%s\n' "$*" >&2
  exit 2
}

usage() {
  cat >&2 <<'USAGE'
usage: submit_pgo_holdout.sh [--run-id ID]

Submits the fixed source-family-disjoint PGO/Goel holdout campaign. The local
revision must be clean and published. Remote work and corpus roots are always
explicit; solver/tool executables are discovered once, canonicalized, hashed,
and bound into the Slurm environment and local submission receipt.
USAGE
}

safe_value() {
  [[ "$1" =~ ^[A-Za-z0-9_./:@%+-]+$ ]]
}

absolute_remote_path() {
  case "$1" in
    /*) ;;
    *) return 1 ;;
  esac
  case "$1" in
    *'/../'*|*/..) return 1 ;;
  esac
  safe_value "$1"
}

validate_wall_time() {
  local hours minutes seconds rest
  [[ "$1" =~ ^[0-9][0-9]:[0-5][0-9]:[0-5][0-9]$ ]] || return 1
  hours="${1%%:*}"
  rest="${1#*:}"
  minutes="${rest%%:*}"
  seconds="${rest##*:}"
  ((10#$hours * 3600 + 10#$minutes * 60 + 10#$seconds > 0))
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --run-id)
      [ "$#" -ge 2 ] || { usage; die "--run-id requires an ID"; }
      [ -z "$RUN_ID" ] || die "run ID was specified twice"
      RUN_ID="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage
      die "unknown argument: $1"
      ;;
  esac
done

[ "${EUF_VIPER_PGO_HOLDOUT_ENABLE:-0}" = 1 ] || \
  die "PGO holdout submission is default-off; set EUF_VIPER_PGO_HOLDOUT_ENABLE=1"
[ -n "$WORK_ROOT" ] || die "set EUF_VIPER_PGO_WORK_ROOT to an absolute /work path"
[ -n "$CORPUS_ROOT" ] || die "set EUF_VIPER_PGO_CORPUS_ROOT explicitly"
absolute_remote_path "$WORK_ROOT" || die "work root is not a conservative absolute path"
absolute_remote_path "$CORPUS_ROOT" || die "corpus root is not a conservative absolute path"
case "$WORK_ROOT" in
  /work/*) ;;
  *) die "work root must be below /work" ;;
esac
safe_value "$REMOTE_HOST" || die "remote host contains unsafe characters"
safe_value "$REPOSITORY_URL" || die "repository URL contains unsafe characters"
safe_value "$PUBLISHED_REF" || die "published ref contains unsafe characters"
case "$PUBLISHED_REF" in
  refs/heads/*) ;;
  *) die "published ref must be an explicit refs/heads/* name" ;;
esac
case "$PARTITION" in
  ''|*[!A-Za-z0-9_-]*) die "partition contains unsafe characters" ;;
esac
validate_wall_time "$WALL_TIME" || die "wall time must be canonical positive HH:MM:SS"

cd "$ROOT"
for program in git ssh python3; do
  command -v "$program" >/dev/null || die "$program is required"
done
[ -z "$(git status --porcelain=v1 --untracked-files=all)" ] || \
  die "repository must be completely clean before PGO holdout submission"
REVISION="$(git rev-parse --verify 'HEAD^{commit}')"
[[ "$REVISION" =~ ^[0-9a-f]{40}$ ]] || die "HEAD is not a full lowercase revision"
PUBLISHED_LINE="$(git ls-remote --exit-code "$REPOSITORY_URL" "$PUBLISHED_REF")"
case "$PUBLISHED_LINE" in
  *$'\n'*) die "published ref resolved to multiple revisions" ;;
esac
PUBLISHED_REVISION="${PUBLISHED_LINE%%$'\t'*}"
[ "$PUBLISHED_REVISION" = "$REVISION" ] || \
  die "HEAD $REVISION is not published at $PUBLISHED_REF ($PUBLISHED_REVISION)"

REMOTE_HOME="$(ssh "$REMOTE_HOST" 'readlink -f -- "$HOME"')"
absolute_remote_path "$REMOTE_HOME" || die "cannot resolve remote HOME"
REMOTE_WORK_ROOT="$(ssh "$REMOTE_HOST" "set -euo pipefail; mkdir -p '$WORK_ROOT'; test -w '$WORK_ROOT'; readlink -f -- '$WORK_ROOT'")"
absolute_remote_path "$REMOTE_WORK_ROOT" || die "cannot resolve remote work root"
case "$REMOTE_WORK_ROOT" in
  /work/*) ;;
  *) die "canonical remote work root escaped /work" ;;
esac
case "$REMOTE_WORK_ROOT" in
  "$REMOTE_HOME"|"$REMOTE_HOME"/*) die "remote work root must be outside HOME" ;;
esac
REMOTE_CORPUS_ROOT="$(ssh "$REMOTE_HOST" "set -euo pipefail; test -d '$CORPUS_ROOT'; test ! -L '$CORPUS_ROOT'; test -r '$CORPUS_ROOT'; test -x '$CORPUS_ROOT'; readlink -f -- '$CORPUS_ROOT'")"
absolute_remote_path "$REMOTE_CORPUS_ROOT" || die "cannot resolve remote corpus root"
case "$REMOTE_WORK_ROOT" in
  "$REMOTE_CORPUS_ROOT"|"$REMOTE_CORPUS_ROOT"/*) die "work root overlaps corpus root" ;;
esac

REQUESTED_CARGO="${EUF_VIPER_PGO_REMOTE_CARGO:-$REMOTE_HOME/.rustup/toolchains/1.93.0-x86_64-unknown-linux-gnu/bin/cargo}"
REQUESTED_RUSTC="${EUF_VIPER_PGO_REMOTE_RUSTC:-$REMOTE_HOME/.rustup/toolchains/1.93.0-x86_64-unknown-linux-gnu/bin/rustc}"
REQUESTED_PYTHON="${EUF_VIPER_PGO_REMOTE_PYTHON:-/usr/bin/python3}"
REQUESTED_LLVM_PROFDATA="${EUF_VIPER_PGO_REMOTE_LLVM_PROFDATA:-$REMOTE_HOME/.rustup/toolchains/1.93.0-x86_64-unknown-linux-gnu/lib/rustlib/x86_64-unknown-linux-gnu/bin/llvm-profdata}"
REQUESTED_Z3="${EUF_VIPER_PGO_REMOTE_Z3:-$REMOTE_HOME/.local/bin/z3}"
COMPETITOR_BUNDLE="$REMOTE_WORK_ROOT/tools/competitors-yices-2.7.0-cvc5-1.3.4"
REQUESTED_COMPETITOR_RECEIPT="$COMPETITOR_BUNDLE/receipt.json"
REQUESTED_YICES="${EUF_VIPER_PGO_REMOTE_YICES:-$COMPETITOR_BUNDLE/packages/yices2/yices-2.7.0/bin/yices-smt2}"
REQUESTED_CVC5="${EUF_VIPER_PGO_REMOTE_CVC5:-$COMPETITOR_BUNDLE/packages/cvc5/cvc5-Linux-x86_64-static/bin/cvc5}"
for value in "$REQUESTED_CARGO" "$REQUESTED_RUSTC" "$REQUESTED_PYTHON"; do
  absolute_remote_path "$value" || die "core remote tool path is unsafe: $value"
done
for value in "$REQUESTED_LLVM_PROFDATA" "$REQUESTED_Z3" "$REQUESTED_YICES" "$REQUESTED_CVC5"; do
  if [ -n "$value" ]; then
    absolute_remote_path "$value" || die "optional remote tool path is unsafe: $value"
  fi
done
absolute_remote_path "$REQUESTED_COMPETITOR_RECEIPT" || \
  die "competitor receipt path is unsafe: $REQUESTED_COMPETITOR_RECEIPT"

TOOL_INFO="$(ssh "$REMOTE_HOST" bash -s -- \
  "$REQUESTED_CARGO" \
  "$REQUESTED_RUSTC" \
  "$REQUESTED_PYTHON" \
  "$REQUESTED_LLVM_PROFDATA" \
  "$REQUESTED_Z3" \
  "$REQUESTED_YICES" \
  "$REQUESTED_CVC5" <<'REMOTE_TOOLS'
set -euo pipefail

resolve_required() {
  local requested="$1"
  local fallback="$2"
  local label="$3"
  local found

  if [ -n "$requested" ]; then
    found="$requested"
  else
    found="$(command -v "$fallback")" || {
      printf 'missing remote %s; set its EUF_VIPER_PGO_REMOTE_* path\n' "$label" >&2
      exit 2
    }
  fi
  found="$(readlink -f -- "$found")"
  test -f "$found" && test -x "$found" && test ! -L "$found"
  printf '%s' "$found"
}

cargo="$(resolve_required "$1" cargo cargo)"
rustc="$(resolve_required "$2" rustc rustc)"
python="$(resolve_required "$3" python3 python)"
llvm_profdata="$(resolve_required "$4" llvm-profdata llvm-profdata)"
z3="$(resolve_required "$5" z3 Z3)"
yices="$(resolve_required "$6" yices-smt2 Yices2)"
cvc5="$(resolve_required "$7" cvc5 cvc5)"
for path in "$cargo" "$rustc" "$python" "$llvm_profdata" "$z3" "$yices" "$cvc5"; do
  hash="$(sha256sum "$path" | awk '{print $1}')"
  printf '%s\t%s\n' "$path" "$hash"
done
REMOTE_TOOLS
)"
[ "$(printf '%s\n' "$TOOL_INFO" | wc -l | tr -d ' ')" = 7 ] || \
  die "remote tool preflight did not return seven exact pins"
read -r REMOTE_CARGO CARGO_SHA256 <<<"$(printf '%s\n' "$TOOL_INFO" | sed -n '1p')"
read -r REMOTE_RUSTC RUSTC_SHA256 <<<"$(printf '%s\n' "$TOOL_INFO" | sed -n '2p')"
read -r REMOTE_PYTHON PYTHON_SHA256 <<<"$(printf '%s\n' "$TOOL_INFO" | sed -n '3p')"
read -r REMOTE_LLVM_PROFDATA LLVM_PROFDATA_SHA256 <<<"$(printf '%s\n' "$TOOL_INFO" | sed -n '4p')"
read -r REMOTE_Z3 Z3_SHA256 <<<"$(printf '%s\n' "$TOOL_INFO" | sed -n '5p')"
read -r REMOTE_YICES YICES_SHA256 <<<"$(printf '%s\n' "$TOOL_INFO" | sed -n '6p')"
read -r REMOTE_CVC5 CVC5_SHA256 <<<"$(printf '%s\n' "$TOOL_INFO" | sed -n '7p')"
for binding in \
  "cargo:$CARGO_SHA256:$EXPECTED_CARGO_SHA256" \
  "rustc:$RUSTC_SHA256:$EXPECTED_RUSTC_SHA256" \
  "llvm-profdata:$LLVM_PROFDATA_SHA256:$EXPECTED_LLVM_PROFDATA_SHA256" \
  "python:$PYTHON_SHA256:$EXPECTED_PYTHON_SHA256" \
  "Z3:$Z3_SHA256:$EXPECTED_Z3_SHA256" \
  "Yices2:$YICES_SHA256:$EXPECTED_YICES_SHA256" \
  "cvc5:$CVC5_SHA256:$EXPECTED_CVC5_SHA256"; do
  label="${binding%%:*}"
  remainder="${binding#*:}"
  actual="${remainder%%:*}"
  expected="${remainder##*:}"
  [ "$actual" = "$expected" ] || \
    die "$label does not match the frozen campaign hash: expected $expected, got $actual"
done
COMPETITOR_RECEIPT_INFO="$(ssh "$REMOTE_HOST" "set -euo pipefail
test -f '$REQUESTED_COMPETITOR_RECEIPT'
test ! -L '$REQUESTED_COMPETITOR_RECEIPT'
resolved=\$(readlink -f -- '$REQUESTED_COMPETITOR_RECEIPT')
test \"\$resolved\" = '$REQUESTED_COMPETITOR_RECEIPT'
printf '%s\\t%s\\n' \"\$resolved\" \"\$(sha256sum \"\$resolved\" | awk '{print \$1}')\"")"
read -r REMOTE_COMPETITOR_RECEIPT COMPETITOR_RECEIPT_SHA256 <<<"$COMPETITOR_RECEIPT_INFO"
[ "$COMPETITOR_RECEIPT_SHA256" = "$EXPECTED_COMPETITOR_RECEIPT_SHA256" ] || \
  die "competitor receipt does not match the frozen campaign hash"

SHORT_REVISION="${REVISION:0:12}"
REMOTE_CHECKOUT="$REMOTE_WORK_ROOT/checkouts/$SHORT_REVISION"
ssh "$REMOTE_HOST" "set -euo pipefail
mkdir -p '$REMOTE_WORK_ROOT/checkouts' '$REMOTE_WORK_ROOT/runs'
if [ ! -d '$REMOTE_CHECKOUT/.git' ]; then
  git clone --quiet '$REPOSITORY_URL' '$REMOTE_CHECKOUT'
fi
git -C '$REMOTE_CHECKOUT' fetch --quiet origin '$REVISION'
git -C '$REMOTE_CHECKOUT' checkout --quiet --detach '$REVISION'
test \"\$(git -C '$REMOTE_CHECKOUT' rev-parse --verify 'HEAD^{commit}')\" = '$REVISION'
test -z \"\$(git -C '$REMOTE_CHECKOUT' status --porcelain=v1 --untracked-files=all)\"
test -f '$REMOTE_CHECKOUT/scripts/wmi/euf_viper_pgo_holdout.sbatch'
test ! -L '$REMOTE_CHECKOUT/scripts/wmi/euf_viper_pgo_holdout.sbatch'
mkdir -p '$REMOTE_CHECKOUT/results'"

if [ -z "$RUN_ID" ]; then
  RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)-$SHORT_REVISION"
fi
[[ "$RUN_ID" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || die "run ID contains unsafe characters"
REMOTE_RUN_ROOT="$REMOTE_WORK_ROOT/runs/pgo-holdout-$RUN_ID"
ssh "$REMOTE_HOST" "test ! -e '$REMOTE_RUN_ROOT' && test ! -L '$REMOTE_RUN_ROOT'"

RECEIPT_DIRECTORY="$ROOT/results/pgo-holdout-submissions"
RECEIPT="$RECEIPT_DIRECTORY/$RUN_ID.json"
mkdir -p "$RECEIPT_DIRECTORY"
[ ! -e "$RECEIPT" ] || die "submission receipt already exists: $RECEIPT"

SBATCH_OUTPUT="$(ssh "$REMOTE_HOST" "cd '$REMOTE_CHECKOUT' && sbatch --parsable \
  --partition='$PARTITION' \
  --time='$WALL_TIME' \
  --export=ALL,EUF_VIPER_PGO_HOLDOUT_ENABLE=1,EUF_VIPER_PGO_WORK_ROOT='$REMOTE_WORK_ROOT',EUF_VIPER_PGO_RUN_ROOT='$REMOTE_RUN_ROOT',EUF_VIPER_PGO_CORPUS_ROOT='$REMOTE_CORPUS_ROOT',EUF_VIPER_PGO_EXPECTED_REVISION='$REVISION',EUF_VIPER_PGO_CARGO='$REMOTE_CARGO',EUF_VIPER_PGO_CARGO_SHA256='$CARGO_SHA256',EUF_VIPER_PGO_RUSTC='$REMOTE_RUSTC',EUF_VIPER_PGO_RUSTC_SHA256='$RUSTC_SHA256',EUF_VIPER_PGO_LLVM_PROFDATA='$REMOTE_LLVM_PROFDATA',EUF_VIPER_PGO_LLVM_PROFDATA_SHA256='$LLVM_PROFDATA_SHA256',EUF_VIPER_PGO_PYTHON='$REMOTE_PYTHON',EUF_VIPER_PGO_PYTHON_SHA256='$PYTHON_SHA256',EUF_VIPER_PGO_Z3='$REMOTE_Z3',EUF_VIPER_PGO_Z3_SHA256='$Z3_SHA256',EUF_VIPER_PGO_YICES='$REMOTE_YICES',EUF_VIPER_PGO_YICES_SHA256='$YICES_SHA256',EUF_VIPER_PGO_CVC5='$REMOTE_CVC5',EUF_VIPER_PGO_CVC5_SHA256='$CVC5_SHA256',EUF_VIPER_PGO_COMPETITOR_RECEIPT='$REMOTE_COMPETITOR_RECEIPT',EUF_VIPER_PGO_COMPETITOR_RECEIPT_SHA256='$COMPETITOR_RECEIPT_SHA256' \
  scripts/wmi/euf_viper_pgo_holdout.sbatch")"
JOB_ID="${SBATCH_OUTPUT%%;*}"
[[ "$JOB_ID" =~ ^[1-9][0-9]*$ ]] || die "sbatch returned an invalid job ID: $SBATCH_OUTPUT"

python3 - \
  "$RECEIPT" \
  "$RUN_ID" \
  "$JOB_ID" \
  "$REVISION" \
  "$PUBLISHED_REF" \
  "$REMOTE_HOST" \
  "$REMOTE_CHECKOUT" \
  "$REMOTE_RUN_ROOT" \
  "$REMOTE_CORPUS_ROOT" \
  "$PARTITION" \
  "$WALL_TIME" \
  "$TOOL_INFO" \
  "$REMOTE_COMPETITOR_RECEIPT" \
  "$COMPETITOR_RECEIPT_SHA256" <<'PY_RECEIPT'
import json
import os
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

(
    receipt_raw,
    run_id,
    job_id,
    revision,
    published_ref,
    remote_host,
    checkout,
    run_root,
    corpus_root,
    partition,
    wall_time,
    tool_info,
    competitor_receipt,
    competitor_receipt_sha256,
) = sys.argv[1:]
tools = {}
for label, line in zip(
    ("cargo", "rustc", "python", "llvm_profdata", "z3", "yices2", "cvc5"),
    tool_info.splitlines(),
    strict=True,
):
    path, sha256 = line.split("\t")
    tools[label] = {"path": path, "sha256": sha256}
payload = {
    "schema_version": "euf-viper.pgo-holdout-submission.v1",
    "status": "submitted",
    "submitted_at": datetime.now(timezone.utc).isoformat(),
    "run_id": run_id,
    "slurm_job_id": int(job_id),
    "git_revision": revision,
    "published_ref": published_ref,
    "remote_host": remote_host,
    "remote_checkout": checkout,
    "remote_run_root": run_root,
    "remote_corpus_root": corpus_root,
    "partition": partition,
    "wall_time": wall_time,
    "tools": tools,
    "competitor_bundle_receipt": {
        "path": competitor_receipt,
        "sha256": competitor_receipt_sha256,
    },
}
data = (json.dumps(payload, ensure_ascii=True, separators=(",", ":"), sort_keys=True) + "\n").encode("ascii")
receipt = Path(receipt_raw)
descriptor, temporary = tempfile.mkstemp(prefix=f".{receipt.name}.", dir=receipt.parent)
try:
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, receipt)
except BaseException:
    try:
        os.unlink(temporary)
    except FileNotFoundError:
        pass
    raise
PY_RECEIPT

printf 'submitted job=%s run=%s receipt=%s\n' "$JOB_ID" "$REMOTE_RUN_ROOT" "$RECEIPT"
