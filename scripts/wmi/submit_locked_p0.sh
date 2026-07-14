#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
REMOTE_HOST="${EUF_VIPER_WMI_HOST:-wmicluster}"
REMOTE_PARENT="${EUF_VIPER_WMI_CAMPAIGN_ROOT:-}"
SHARDS="${EUF_VIPER_LOCKED_SHARDS:-64}"
MAX_ACTIVE="${EUF_VIPER_LOCKED_MAX_ACTIVE:-16}"
REMOTE_SHARED_CORPUS="${EUF_VIPER_SHARED_CORPUS:-}"

case "$SHARDS" in
  ''|0|0*|*[!0-9]*)
    echo "shards and max-active must be positive integers" >&2
    exit 2
    ;;
esac
case "$MAX_ACTIVE" in
  ''|0|0*|*[!0-9]*)
    echo "shards and max-active must be positive integers" >&2
    exit 2
    ;;
esac
case "$REMOTE_HOST" in
  ''|*[!A-Za-z0-9_.@-]*)
    echo "remote host contains unsafe characters" >&2
    exit 2
    ;;
esac

cd "$ROOT"
python3 -B -I -S scripts/wmi/hermetic_provenance.py audit-submit-environment >/dev/null
if [ -n "$(git status --porcelain=v1 --untracked-files=all --ignored=matching)" ]; then
  echo "tracked, untracked, and ignored repository state must be empty before submission" >&2
  exit 2
fi
while IFS= read -r INDEX_ENTRY; do
  case "$INDEX_ENTRY" in
    'H '*) ;;
    *)
      echo "skip-worktree, assume-unchanged, or abnormal index entry: $INDEX_ENTRY" >&2
      exit 2
      ;;
  esac
done < <(git ls-files -v)

REVISION="$(git rev-parse HEAD)"
REMOTE_MAIN="$(git rev-parse origin/main)"
if [ "$REVISION" != "$REMOTE_MAIN" ]; then
  echo "HEAD $REVISION is not published as origin/main $REMOTE_MAIN" >&2
  exit 2
fi
case "$REVISION" in
  *[!0-9a-f]*|'') echo "revision is not a full hexadecimal object id" >&2; exit 2 ;;
esac

REMOTE_HOME="$(ssh "$REMOTE_HOST" 'printf %s "$HOME"')"
if [ -z "$REMOTE_PARENT" ]; then
  REMOTE_PARENT="$REMOTE_HOME/euf-viper-campaigns"
fi
if [ -z "$REMOTE_SHARED_CORPUS" ]; then
  REMOTE_SHARED_CORPUS="$REMOTE_HOME/euf-viper/benchmarks/smtlib-2025"
fi
for REMOTE_PATH in "$REMOTE_PARENT" "$REMOTE_SHARED_CORPUS"; do
  case "$REMOTE_PATH" in
    /*) ;;
    *) echo "remote paths must be absolute" >&2; exit 2 ;;
  esac
  case "$REMOTE_PATH" in
    *[!A-Za-z0-9_./-]*|*/../*|*/..|*//*|*,*)
      echo "remote path contains unsafe or ambiguous components: $REMOTE_PATH" >&2
      exit 2
      ;;
  esac
done

ATTEMPT_ID="$(python3 -B -I -S -c 'import secrets; print(secrets.token_hex(16))')"
case "$ATTEMPT_ID" in
  *[!0-9a-f]*|'') echo "failed to generate attempt identity" >&2; exit 2 ;;
esac

printf -v Q_REMOTE_PARENT '%q' "$REMOTE_PARENT"
printf -v Q_ATTEMPT_ID '%q' "$ATTEMPT_ID"
printf -v Q_REVISION '%q' "$REVISION"
printf -v Q_SHARDS '%q' "$SHARDS"
printf -v Q_REMOTE_SHARED_CORPUS '%q' "$REMOTE_SHARED_CORPUS"

REMOTE_SETUP="$(ssh "$REMOTE_HOST" "/bin/bash -s -- $Q_REMOTE_PARENT $Q_ATTEMPT_ID $Q_REVISION $Q_SHARDS $Q_REMOTE_SHARED_CORPUS" <<'REMOTE_BOOTSTRAP'
set -euo pipefail
umask 077

REMOTE_PARENT="$1"
ATTEMPT_ID="$2"
REVISION="$3"
SHARDS="$4"
SHARED_CORPUS="$5"
ORIGINAL_HOME="$HOME"
BOOTSTRAP_PATH="$ORIGINAL_HOME/.cargo/bin:$ORIGINAL_HOME/.local/bin:/usr/local/bin:/usr/bin:/bin"

mkdir -p "$REMOTE_PARENT"
test ! -L "$REMOTE_PARENT"
ATTEMPT_ROOT="$(mktemp -d "$REMOTE_PARENT/attempt-$ATTEMPT_ID-XXXXXXXX")"
chmod 0700 "$ATTEMPT_ROOT"
CHECKOUT="$ATTEMPT_ROOT/checkout"
PRIVATE_HOME="$ATTEMPT_ROOT/home"
EMPTY_TEMPLATE="$ATTEMPT_ROOT/empty-git-template"
mkdir -m 0700 "$PRIVATE_HOME" "$EMPTY_TEMPLATE" "$ATTEMPT_ROOT/logs" "$ATTEMPT_ROOT/build"

GIT_BIN="$(PATH="$BOOTSTRAP_PATH" command -v git)"
PYTHON_BIN="$(PATH="$BOOTSTRAP_PATH" command -v python3)"
CARGO_BIN="$(PATH="$BOOTSTRAP_PATH" command -v cargo)"
RUSTC_BIN="$(PATH="$BOOTSTRAP_PATH" command -v rustc)"
SBATCH_BIN="$(PATH="$BOOTSTRAP_PATH" command -v sbatch)"
BASH_BIN="/bin/bash"

env -i HOME="$ORIGINAL_HOME" LANG=C LC_ALL=C PATH="$BOOTSTRAP_PATH" \
  GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null \
  "$GIT_BIN" -c core.hooksPath=/dev/null clone --quiet --no-hardlinks \
  --template="$EMPTY_TEMPLATE" https://github.com/nasqret/euf-viper.git "$CHECKOUT"
env -i HOME="$ORIGINAL_HOME" LANG=C LC_ALL=C PATH="$BOOTSTRAP_PATH" \
  GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null \
  "$GIT_BIN" -C "$CHECKOUT" fetch --quiet origin "$REVISION"
env -i HOME="$ORIGINAL_HOME" LANG=C LC_ALL=C PATH="$BOOTSTRAP_PATH" \
  GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null \
  "$GIT_BIN" -C "$CHECKOUT" checkout --quiet --detach "$REVISION"

tool() {
  PATH="$BOOTSTRAP_PATH" command -v "$1"
}
RUNTIME_PATH="$ORIGINAL_HOME/.cargo/bin:$ORIGINAL_HOME/.local/bin:/usr/local/bin:/usr/bin:/bin"
RUSTUP_HOME="$ORIGINAL_HOME/.rustup"
CARGO_TARGET_DIR="$ATTEMPT_ROOT/build/target"
PRIVATE_TMP="$ATTEMPT_ROOT/tmp"
XDG_CACHE_HOME="$ATTEMPT_ROOT/cache"
XDG_CONFIG_HOME="$ATTEMPT_ROOT/config"
mkdir -m 0700 "$PRIVATE_TMP" "$XDG_CACHE_HOME" "$XDG_CONFIG_HOME"
MANIFEST="$ATTEMPT_ROOT/submission-provenance.json"

env -i HOME="$ORIGINAL_HOME" LANG=C LC_ALL=C PATH="$BOOTSTRAP_PATH" \
  "$PYTHON_BIN" -B -I -S "$CHECKOUT/scripts/wmi/hermetic_provenance.py" create \
  --attempt-id "$ATTEMPT_ID" \
  --attempt-root "$ATTEMPT_ROOT" \
  --checkout "$CHECKOUT" \
  --revision "$REVISION" \
  --tool "ar=$(tool ar)" \
  --tool "bash=$BASH_BIN" \
  --tool "cargo=$CARGO_BIN" \
  --tool "cc=$(tool cc)" \
  --tool "chmod=$(tool chmod)" \
  --tool "cmp=$(tool cmp)" \
  --tool "curl=$(tool curl)" \
  --tool "cxx=$(tool c++)" \
  --tool "env=$(tool env)" \
  --tool "find=$(tool find)" \
  --tool "git=$GIT_BIN" \
  --tool "mkdir=$(tool mkdir)" \
  --tool "python=$PYTHON_BIN" \
  --tool "ranlib=$(tool ranlib)" \
  --tool "rustc=$RUSTC_BIN" \
  --tool "sbatch=$SBATCH_BIN" \
  --tool "sha256sum=$(tool sha256sum)" \
  --tool "tar=$(tool tar)" \
  --tool "unzip=$(tool unzip)" \
  --execution-env "CARGO_TARGET_DIR=$CARGO_TARGET_DIR" \
  --execution-env "HOME=$PRIVATE_HOME" \
  --execution-env "LANG=C" \
  --execution-env "LC_ALL=C" \
  --execution-env "PATH=$RUNTIME_PATH" \
  --execution-env "PYTHON_FLAGS=-B -I -S" \
  --execution-env "RUSTUP_HOME=$RUSTUP_HOME" \
  --execution-env "TMPDIR=$PRIVATE_TMP" \
  --execution-env "TZ=UTC" \
  --execution-env "XDG_CACHE_HOME=$XDG_CACHE_HOME" \
  --execution-env "XDG_CONFIG_HOME=$XDG_CONFIG_HOME" \
  --parameter "shared_corpus=$SHARED_CORPUS" \
  --parameter "shards=$SHARDS" \
  --out "$MANIFEST"
REMOTE_BOOTSTRAP
)"

SETUP_FIELDS="$(python3 -B -I -S -c '
import json, sys
value = json.loads(sys.argv[1])
tools = value["runtime_tools"]
fields = [
    value["attempt"]["root"], value["attempt"]["checkout"], value["manifest"],
    value["manifest_sha256"], tools["python"]["path"], tools["sbatch"]["path"],
    tools["python"]["sha256"], tools["sha256sum"]["path"],
    value["provenance_helper_sha256"], str(value["source_blob_count"]),
    value["source_blobs_sha256"], value["source_tree"],
]
if any("\t" in item or "\n" in item for item in fields):
    raise SystemExit("unsafe provenance field")
print("\t".join(fields))
' "$REMOTE_SETUP")"
IFS=$'\t' read -r REMOTE_ATTEMPT_ROOT REMOTE_CHECKOUT SUBMISSION_MANIFEST \
  SUBMISSION_MANIFEST_SHA256 REMOTE_PYTHON REMOTE_SBATCH REMOTE_PYTHON_SHA256 \
  REMOTE_SHA256SUM PROVENANCE_HELPER_SHA256 SOURCE_BLOB_COUNT \
  SOURCE_BLOBS_SHA256 SOURCE_TREE <<<"$SETUP_FIELDS"

if [ "$REMOTE_CHECKOUT" != "$REMOTE_ATTEMPT_ROOT/checkout" ]; then
  echo "remote checkout escaped attempt root" >&2
  exit 2
fi
case "$REMOTE_ATTEMPT_ROOT" in
  "$REMOTE_PARENT"/attempt-"$ATTEMPT_ID"-*) ;;
  *) echo "remote attempt root identity mismatch" >&2; exit 2 ;;
esac
for VALUE in "$REMOTE_ATTEMPT_ROOT" "$REMOTE_CHECKOUT" "$SUBMISSION_MANIFEST" \
  "$REMOTE_PYTHON" "$REMOTE_SBATCH" "$REMOTE_SHA256SUM"; do
  case "$VALUE" in
    *','*|*$'\n'*|*$'\t'*) echo "receipt-bound path is not export-safe" >&2; exit 2 ;;
  esac
done

COMMON_EXPORTS="EUF_VIPER_ATTEMPT_ID=$ATTEMPT_ID,EUF_VIPER_ATTEMPT_ROOT=$REMOTE_ATTEMPT_ROOT,EUF_VIPER_CHECKOUT=$REMOTE_CHECKOUT,EUF_VIPER_EXPECTED_REVISION=$REVISION,EUF_VIPER_PYTHON=$REMOTE_PYTHON,EUF_VIPER_PYTHON_SHA256=$REMOTE_PYTHON_SHA256,EUF_VIPER_PROVENANCE_HELPER_SHA256=$PROVENANCE_HELPER_SHA256,EUF_VIPER_SHA256SUM=$REMOTE_SHA256SUM,EUF_VIPER_SUBMISSION_MANIFEST=$SUBMISSION_MANIFEST,EUF_VIPER_SUBMISSION_MANIFEST_SHA256=$SUBMISSION_MANIFEST_SHA256"
PREPARE_EXPORTS="$COMMON_EXPORTS,EUF_VIPER_LOCKED_SHARDS=$SHARDS,EUF_VIPER_SHARED_CORPUS=$REMOTE_SHARED_CORPUS"

printf -v Q_REMOTE_CHECKOUT '%q' "$REMOTE_CHECKOUT"
printf -v Q_REMOTE_SBATCH '%q' "$REMOTE_SBATCH"
printf -v Q_PREPARE_EXPORTS '%q' "$PREPARE_EXPORTS"
printf -v Q_PREPARE_STDOUT '%q' "$REMOTE_ATTEMPT_ROOT/logs/prepare-%j.out"
printf -v Q_PREPARE_STDERR '%q' "$REMOTE_ATTEMPT_ROOT/logs/prepare-%j.err"
PREPARE_SUBMISSION="$(ssh "$REMOTE_HOST" "cd $Q_REMOTE_CHECKOUT && $Q_REMOTE_SBATCH --parsable --kill-on-invalid-dep=yes --chdir=$Q_REMOTE_CHECKOUT --output=$Q_PREPARE_STDOUT --error=$Q_PREPARE_STDERR --export=$Q_PREPARE_EXPORTS scripts/wmi/euf_viper_locked_prepare.sbatch")"
PREPARE_JOB="${PREPARE_SUBMISSION%%;*}"
case "$PREPARE_JOB" in *[!0-9]*|'') echo "invalid prepare job id: $PREPARE_SUBMISSION" >&2; exit 2 ;; esac

FULL_EXPORTS="$COMMON_EXPORTS,EUF_VIPER_PREPARE_JOB_ID=$PREPARE_JOB,EUF_VIPER_CORPUS_KIND=full"
OFFICIAL_EXPORTS="$COMMON_EXPORTS,EUF_VIPER_PREPARE_JOB_ID=$PREPARE_JOB,EUF_VIPER_CORPUS_KIND=official"
printf -v Q_FULL_EXPORTS '%q' "$FULL_EXPORTS"
printf -v Q_OFFICIAL_EXPORTS '%q' "$OFFICIAL_EXPORTS"
printf -v Q_FULL_STDOUT '%q' "$REMOTE_ATTEMPT_ROOT/logs/full-%A_%a.out"
printf -v Q_FULL_STDERR '%q' "$REMOTE_ATTEMPT_ROOT/logs/full-%A_%a.err"
printf -v Q_OFFICIAL_STDOUT '%q' "$REMOTE_ATTEMPT_ROOT/logs/official-%A_%a.out"
printf -v Q_OFFICIAL_STDERR '%q' "$REMOTE_ATTEMPT_ROOT/logs/official-%A_%a.err"

FULL_SUBMISSION="$(ssh "$REMOTE_HOST" "cd $Q_REMOTE_CHECKOUT && $Q_REMOTE_SBATCH --parsable --kill-on-invalid-dep=yes --dependency=afterok:$PREPARE_JOB --array=0-$((SHARDS - 1))%$MAX_ACTIVE --chdir=$Q_REMOTE_CHECKOUT --output=$Q_FULL_STDOUT --error=$Q_FULL_STDERR --export=$Q_FULL_EXPORTS scripts/wmi/euf_viper_locked_shard.sbatch")"
FULL_JOB="${FULL_SUBMISSION%%;*}"
case "$FULL_JOB" in *[!0-9]*|'') echo "invalid full job id: $FULL_SUBMISSION" >&2; exit 2 ;; esac

OFFICIAL_SUBMISSION="$(ssh "$REMOTE_HOST" "cd $Q_REMOTE_CHECKOUT && $Q_REMOTE_SBATCH --parsable --kill-on-invalid-dep=yes --dependency=afterok:$PREPARE_JOB --array=0-$((SHARDS - 1))%$MAX_ACTIVE --chdir=$Q_REMOTE_CHECKOUT --output=$Q_OFFICIAL_STDOUT --error=$Q_OFFICIAL_STDERR --export=$Q_OFFICIAL_EXPORTS scripts/wmi/euf_viper_locked_shard.sbatch")"
OFFICIAL_JOB="${OFFICIAL_SUBMISSION%%;*}"
case "$OFFICIAL_JOB" in *[!0-9]*|'') echo "invalid official job id: $OFFICIAL_SUBMISSION" >&2; exit 2 ;; esac

AUDIT_EXPORTS="$COMMON_EXPORTS,EUF_VIPER_PREPARE_JOB_ID=$PREPARE_JOB,EUF_VIPER_LOCKED_SHARDS=$SHARDS"
printf -v Q_AUDIT_EXPORTS '%q' "$AUDIT_EXPORTS"
printf -v Q_AUDIT_STDOUT '%q' "$REMOTE_ATTEMPT_ROOT/logs/audit-%j.out"
printf -v Q_AUDIT_STDERR '%q' "$REMOTE_ATTEMPT_ROOT/logs/audit-%j.err"
AUDIT_SUBMISSION="$(ssh "$REMOTE_HOST" "cd $Q_REMOTE_CHECKOUT && $Q_REMOTE_SBATCH --parsable --kill-on-invalid-dep=yes --dependency=afterok:$FULL_JOB:$OFFICIAL_JOB --chdir=$Q_REMOTE_CHECKOUT --output=$Q_AUDIT_STDOUT --error=$Q_AUDIT_STDERR --export=$Q_AUDIT_EXPORTS scripts/wmi/euf_viper_locked_audit.sbatch")"
AUDIT_JOB="${AUDIT_SUBMISSION%%;*}"
case "$AUDIT_JOB" in *[!0-9]*|'') echo "invalid audit job id: $AUDIT_SUBMISSION" >&2; exit 2 ;; esac

RECEIPT="$ROOT/results/locked-p0-attempt-$ATTEMPT_ID.json"
python3 -B -I -S - "$RECEIPT" "$REMOTE_SETUP" "$REMOTE_HOST" "$REMOTE_PARENT" \
  "$REMOTE_SHARED_CORPUS" "$REVISION" "$SHARDS" "$MAX_ACTIVE" \
  "$PREPARE_EXPORTS" "$FULL_EXPORTS" "$OFFICIAL_EXPORTS" "$AUDIT_EXPORTS" \
  "$PREPARE_JOB" "$FULL_JOB" "$OFFICIAL_JOB" "$AUDIT_JOB" <<'PY'
import json
import os
import sys
from pathlib import Path

(
    raw_path, raw_provenance, remote_host, remote_parent, shared_corpus,
    revision, shards, max_active, prepare_exports, full_exports,
    official_exports, audit_exports, prepare_job, full_job, official_job,
    audit_job,
) = sys.argv[1:]
path = Path(raw_path)
provenance = json.loads(raw_provenance)

def export_map(value):
    result = {}
    for binding in value.split(","):
        name, separator, item = binding.partition("=")
        if not separator or name in result:
            raise SystemExit("invalid submission export binding")
        result[name] = item
    return dict(sorted(result.items()))

attempt = provenance["attempt"]
payload = {
    "schema": "euf-viper.locked-p0-submission.v2",
    "status": "submitted",
    "attempt": attempt,
    "jobs": {
        "audit": audit_job,
        "full": full_job,
        "official": official_job,
        "prepare": prepare_job,
    },
    "log_paths": {
        "audit": f"{attempt['root']}/logs/audit-%j.out",
        "full": f"{attempt['root']}/logs/full-%A_%a.out",
        "official": f"{attempt['root']}/logs/official-%A_%a.out",
        "prepare": f"{attempt['root']}/logs/prepare-%j.out",
    },
    "max_active": int(max_active),
    "provenance": provenance,
    "remote_host": remote_host,
    "remote_parent": remote_parent,
    "revision": revision,
    "shards": int(shards),
    "shared_corpus": shared_corpus,
    "submission_environment": {
        "audit": export_map(audit_exports),
        "full": export_map(full_exports),
        "official": export_map(official_exports),
        "prepare": export_map(prepare_exports),
    },
}
path.parent.mkdir(parents=True, exist_ok=True)
encoded = (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode()
descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
try:
    with os.fdopen(descriptor, "wb", closefd=False) as handle:
        handle.write(encoded)
        handle.flush()
        os.fsync(handle.fileno())
finally:
    os.close(descriptor)
directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
try:
    os.fsync(directory)
finally:
    os.close(directory)
print(json.dumps(payload, indent=2, sort_keys=True))
PY
