#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SSH_TARGET="${EUF_VIPER_HELIOS_SSH_TARGET:-helios}"
SOURCE_ROOT="${EUF_VIPER_HELIOS_CORPUS_SOURCE:-/Users/airbartek/codex/z3/benchmarks}"
MANIFEST_RELATIVE=""
MANIFEST_SOURCE=""
INSTANCE_ROOT_RELATIVE="smtlib-2025/QF_UF"
PREFLIGHT_REPORT=""

die() {
  printf '%s\n' "$*" >&2
  exit 2
}

usage() {
  cat <<'USAGE'
usage: sync_corpus.sh --manifest RELATIVE [options]

Options:
  --source-root PATH       local corpus root
  --manifest-source PATH   explicit local manifest file
  --instance-root RELATIVE root joined with each manifest relative_path
  --preflight-report PATH  reuse a preflight.sh TSV report

The corpus is inventoried byte-for-byte, rsynced to a content-addressed
scratch directory, verified remotely, and made read-only. The selected
manifest is rewritten to exact Helios paths without changing row order or IDs.
USAGE
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --manifest)
      [ "$#" -ge 2 ] || die "--manifest requires a relative path"
      MANIFEST_RELATIVE="$2"
      shift 2
      ;;
    --source-root)
      [ "$#" -ge 2 ] || die "--source-root requires a path"
      SOURCE_ROOT="$2"
      shift 2
      ;;
    --manifest-source)
      [ "$#" -ge 2 ] || die "--manifest-source requires a path"
      MANIFEST_SOURCE="$2"
      shift 2
      ;;
    --instance-root)
      [ "$#" -ge 2 ] || die "--instance-root requires a relative path"
      INSTANCE_ROOT_RELATIVE="$2"
      shift 2
      ;;
    --preflight-report)
      [ "$#" -ge 2 ] || die "--preflight-report requires a path"
      PREFLIGHT_REPORT="$2"
      shift 2
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

[ -n "$MANIFEST_RELATIVE" ] || { usage >&2; die "--manifest is required"; }
for value in "$MANIFEST_RELATIVE" "$INSTANCE_ROOT_RELATIVE"; do
  [[ "$value" =~ ^[A-Za-z0-9_./+-]+$ ]] || die "unsafe relative corpus path: $value"
  case "/$value/" in
    /*/../*|//*|/*/./*) die "corpus paths must be canonical and relative" ;;
  esac
  case "$value" in
    /*) die "corpus paths must be relative" ;;
  esac
done
[ -d "$SOURCE_ROOT" ] || die "missing local corpus root: $SOURCE_ROOT"
if [ -z "$MANIFEST_SOURCE" ]; then
  if [ -f "$ROOT/$MANIFEST_RELATIVE" ]; then
    MANIFEST_SOURCE="$ROOT/$MANIFEST_RELATIVE"
  else
    MANIFEST_SOURCE="$SOURCE_ROOT/$MANIFEST_RELATIVE"
  fi
fi
[ -f "$MANIFEST_SOURCE" ] || die "missing selected manifest: $MANIFEST_SOURCE"
for program in mktemp python3 rsync shasum ssh; do
  command -v "$program" >/dev/null || die "$program is required"
done

TEMPORARY="$(mktemp -d "${TMPDIR:-/tmp}/euf-viper-corpus.XXXXXX")"
cleanup() {
  rm -rf -- "$TEMPORARY"
}
trap cleanup EXIT HUP INT TERM

if [ -z "$PREFLIGHT_REPORT" ]; then
  PREFLIGHT_REPORT="$TEMPORARY/preflight.tsv"
  "$ROOT/scripts/helios/preflight.sh" > "$PREFLIGHT_REPORT"
fi
[ -f "$PREFLIGHT_REPORT" ] || die "missing preflight report: $PREFLIGHT_REPORT"
REMOTE_ROOT="$(awk -F '\t' '$1 == "fact" && $2 == "remote_root" {print $3}' \
  "$PREFLIGHT_REPORT")"
REPORT_TARGET="$(awk -F '\t' '$1 == "fact" && $2 == "ssh_target" {print $3}' \
  "$PREFLIGHT_REPORT")"
[ "$REPORT_TARGET" = "$SSH_TARGET" ] || die "preflight SSH target drifted"
case "$REMOTE_ROOT" in
  /*) ;;
  *) die "preflight returned a non-absolute remote root" ;;
esac

INVENTORY="$TEMPORARY/inventory.jsonl"
python3 "$ROOT/scripts/helios/corpus_snapshot.py" inventory \
  --root "$SOURCE_ROOT" \
  --out "$INVENTORY" >/dev/null
INVENTORY_SHA256="$(shasum -a 256 "$INVENTORY" | awk '{print $1}')"
HELPER="$ROOT/scripts/helios/corpus_snapshot.py"
HELPER_SHA256="$(shasum -a 256 "$HELPER" | awk '{print $1}')"
MANIFEST_SOURCE_SHA256="$(shasum -a 256 "$MANIFEST_SOURCE" | awk '{print $1}')"
TOKEN="$(date -u +%Y%m%dT%H%M%SZ)-$$"

REMOTE_CORPUS="$REMOTE_ROOT/corpora/$INVENTORY_SHA256"
REMOTE_INVENTORY="$REMOTE_ROOT/corpus-receipts/$INVENTORY_SHA256.jsonl"
REMOTE_HELPER="$REMOTE_ROOT/helpers/corpus-snapshot-$HELPER_SHA256.py"
REMOTE_MANIFEST_SOURCE="$REMOTE_ROOT/manifest-sources/$MANIFEST_SOURCE_SHA256.jsonl"
REMOTE_MANIFEST_ROOT="$REMOTE_ROOT/rebased-manifests/$INVENTORY_SHA256/$MANIFEST_SOURCE_SHA256"
REMOTE_MANIFEST="$REMOTE_MANIFEST_ROOT/$MANIFEST_RELATIVE"
REMOTE_INCOMING="$REMOTE_ROOT/incoming/corpus-$INVENTORY_SHA256-$TOKEN"
REMOTE_INCOMING_INVENTORY="$REMOTE_ROOT/incoming/corpus-$INVENTORY_SHA256-$TOKEN.jsonl"
REMOTE_INCOMING_HELPER="$REMOTE_ROOT/incoming/corpus-helper-$HELPER_SHA256-$TOKEN.py"
REMOTE_INCOMING_MANIFEST="$REMOTE_ROOT/incoming/manifest-$MANIFEST_SOURCE_SHA256-$TOKEN.jsonl"

ssh -o BatchMode=yes -o ConnectTimeout=15 "$SSH_TARGET" \
  "REMOTE_ROOT='$REMOTE_ROOT' REMOTE_HELPER='$REMOTE_HELPER' REMOTE_INCOMING_HELPER='$REMOTE_INCOMING_HELPER' HELPER_SHA256='$HELPER_SHA256' bash -l -s" <<'REMOTE'
set -euo pipefail
mkdir -p "$REMOTE_ROOT"/{corpora,corpus-receipts,helpers,incoming,manifest-sources,rebased-manifests}
if [ -e "$REMOTE_HELPER" ]; then
  test -f "$REMOTE_HELPER" && test ! -L "$REMOTE_HELPER"
  test "$(sha256sum "$REMOTE_HELPER" | awk '{print $1}')" = "$HELPER_SHA256"
else
  test ! -e "$REMOTE_INCOMING_HELPER"
  : > "$REMOTE_INCOMING_HELPER"
fi
REMOTE

if ! ssh -o BatchMode=yes -o ConnectTimeout=15 "$SSH_TARGET" \
  "test -s '$REMOTE_HELPER'"; then
  rsync -az -e "ssh -o BatchMode=yes -o ConnectTimeout=15" \
    "$HELPER" "$SSH_TARGET:$REMOTE_INCOMING_HELPER"
  ssh -o BatchMode=yes -o ConnectTimeout=15 "$SSH_TARGET" \
    "REMOTE_HELPER='$REMOTE_HELPER' REMOTE_INCOMING_HELPER='$REMOTE_INCOMING_HELPER' HELPER_SHA256='$HELPER_SHA256' bash -l -s" <<'REMOTE'
set -euo pipefail
test "$(sha256sum "$REMOTE_INCOMING_HELPER" | awk '{print $1}')" = "$HELPER_SHA256"
chmod 0444 "$REMOTE_INCOMING_HELPER"
test ! -e "$REMOTE_HELPER"
mv "$REMOTE_INCOMING_HELPER" "$REMOTE_HELPER"
REMOTE
fi

if ! ssh -o BatchMode=yes -o ConnectTimeout=15 "$SSH_TARGET" \
  "test -s '$REMOTE_MANIFEST_SOURCE'"; then
  ssh -o BatchMode=yes -o ConnectTimeout=15 "$SSH_TARGET" \
    "test ! -e '$REMOTE_INCOMING_MANIFEST'"
  rsync -az -e "ssh -o BatchMode=yes -o ConnectTimeout=15" \
    "$MANIFEST_SOURCE" "$SSH_TARGET:$REMOTE_INCOMING_MANIFEST"
  ssh -o BatchMode=yes -o ConnectTimeout=15 "$SSH_TARGET" \
    "REMOTE_MANIFEST_SOURCE='$REMOTE_MANIFEST_SOURCE' REMOTE_INCOMING_MANIFEST='$REMOTE_INCOMING_MANIFEST' MANIFEST_SOURCE_SHA256='$MANIFEST_SOURCE_SHA256' bash -l -s" <<'REMOTE'
set -euo pipefail
test "$(sha256sum "$REMOTE_INCOMING_MANIFEST" | awk '{print $1}')" = "$MANIFEST_SOURCE_SHA256"
chmod 0444 "$REMOTE_INCOMING_MANIFEST"
test ! -e "$REMOTE_MANIFEST_SOURCE"
mv "$REMOTE_INCOMING_MANIFEST" "$REMOTE_MANIFEST_SOURCE"
REMOTE
else
  ssh -o BatchMode=yes -o ConnectTimeout=15 "$SSH_TARGET" \
    "test \"\$(sha256sum '$REMOTE_MANIFEST_SOURCE' | awk '{print \$1}')\" = '$MANIFEST_SOURCE_SHA256'"
fi

if ssh -o BatchMode=yes -o ConnectTimeout=15 "$SSH_TARGET" \
  "test -d '$REMOTE_CORPUS'"; then
  ssh -o BatchMode=yes -o ConnectTimeout=15 "$SSH_TARGET" \
    "REMOTE_CORPUS='$REMOTE_CORPUS' REMOTE_INVENTORY='$REMOTE_INVENTORY' REMOTE_HELPER='$REMOTE_HELPER' INVENTORY_SHA256='$INVENTORY_SHA256' bash -l -s" <<'REMOTE'
set -euo pipefail
test -f "$REMOTE_INVENTORY" && test ! -L "$REMOTE_INVENTORY"
test "$(sha256sum "$REMOTE_INVENTORY" | awk '{print $1}')" = "$INVENTORY_SHA256"
python3 "$REMOTE_HELPER" verify --root "$REMOTE_CORPUS" --inventory "$REMOTE_INVENTORY" >/dev/null
REMOTE
else
  ssh -o BatchMode=yes -o ConnectTimeout=15 "$SSH_TARGET" \
    "REMOTE_INCOMING='$REMOTE_INCOMING' REMOTE_INCOMING_INVENTORY='$REMOTE_INCOMING_INVENTORY' bash -l -s" <<'REMOTE'
set -euo pipefail
test ! -e "$REMOTE_INCOMING"
test ! -e "$REMOTE_INCOMING_INVENTORY"
mkdir "$REMOTE_INCOMING"
REMOTE
  rsync -az --delete --exclude=.DS_Store \
    -e "ssh -o BatchMode=yes -o ConnectTimeout=15" \
    "$SOURCE_ROOT/" "$SSH_TARGET:$REMOTE_INCOMING/"
  rsync -az -e "ssh -o BatchMode=yes -o ConnectTimeout=15" \
    "$INVENTORY" "$SSH_TARGET:$REMOTE_INCOMING_INVENTORY"
  ssh -o BatchMode=yes -o ConnectTimeout=15 "$SSH_TARGET" \
    "REMOTE_INCOMING='$REMOTE_INCOMING' REMOTE_INCOMING_INVENTORY='$REMOTE_INCOMING_INVENTORY' REMOTE_CORPUS='$REMOTE_CORPUS' REMOTE_INVENTORY='$REMOTE_INVENTORY' REMOTE_HELPER='$REMOTE_HELPER' INVENTORY_SHA256='$INVENTORY_SHA256' bash -l -s" <<'REMOTE'
set -euo pipefail
test "$(sha256sum "$REMOTE_INCOMING_INVENTORY" | awk '{print $1}')" = "$INVENTORY_SHA256"
python3 "$REMOTE_HELPER" verify \
  --root "$REMOTE_INCOMING" \
  --inventory "$REMOTE_INCOMING_INVENTORY" >/dev/null
chmod -R a-w "$REMOTE_INCOMING"
chmod 0444 "$REMOTE_INCOMING_INVENTORY"
test ! -e "$REMOTE_CORPUS"
test ! -e "$REMOTE_INVENTORY"
mv "$REMOTE_INCOMING" "$REMOTE_CORPUS"
mv "$REMOTE_INCOMING_INVENTORY" "$REMOTE_INVENTORY"
REMOTE
fi

remote_manifest_sha256() {
  ssh -o BatchMode=yes -o ConnectTimeout=15 "$SSH_TARGET" \
    "REMOTE_CORPUS='$REMOTE_CORPUS' REMOTE_MANIFEST_SOURCE='$REMOTE_MANIFEST_SOURCE' REMOTE_MANIFEST='$REMOTE_MANIFEST' REMOTE_HELPER='$REMOTE_HELPER' INSTANCE_ROOT_RELATIVE='$INSTANCE_ROOT_RELATIVE' bash -l -s" <<'REMOTE'
set -euo pipefail
instance_root="$REMOTE_CORPUS/$INSTANCE_ROOT_RELATIVE"
test -f "$REMOTE_MANIFEST_SOURCE" && test -d "$instance_root"
if [ ! -e "$REMOTE_MANIFEST" ]; then
  mkdir -p "$(dirname "$REMOTE_MANIFEST")"
  python3 "$REMOTE_HELPER" rebase-manifest \
    --manifest "$REMOTE_MANIFEST_SOURCE" \
    --instance-root "$instance_root" \
    --out "$REMOTE_MANIFEST" >/dev/null
fi
test -f "$REMOTE_MANIFEST" && test ! -L "$REMOTE_MANIFEST"
python3 "$REMOTE_HELPER" verify-rebased-manifest \
  --manifest "$REMOTE_MANIFEST_SOURCE" \
  --instance-root "$instance_root" \
  --rebased "$REMOTE_MANIFEST" >/dev/null
chmod 0444 "$REMOTE_MANIFEST"
sha256sum "$REMOTE_MANIFEST" | awk '{print $1}'
REMOTE
}
REMOTE_MANIFEST_SHA256="$(remote_manifest_sha256)"
[[ "$REMOTE_MANIFEST_SHA256" =~ ^[0-9a-f]{64}$ ]] || \
  die "remote manifest hash is invalid"

printf 'key\tvalue\n'
printf 'corpus_inventory_sha256\t%s\n' "$INVENTORY_SHA256"
printf 'corpus_helper_sha256\t%s\n' "$HELPER_SHA256"
printf 'manifest_source_sha256\t%s\n' "$MANIFEST_SOURCE_SHA256"
printf 'remote_corpus_root\t%s\n' "$REMOTE_CORPUS"
printf 'remote_inventory\t%s\n' "$REMOTE_INVENTORY"
printf 'remote_manifest_source\t%s\n' "$REMOTE_MANIFEST_SOURCE"
printf 'remote_manifest\t%s\n' "$REMOTE_MANIFEST"
printf 'remote_manifest_sha256\t%s\n' "$REMOTE_MANIFEST_SHA256"
printf 'remote_instance_root\t%s/%s\n' "$REMOTE_CORPUS" "$INSTANCE_ROOT_RELATIVE"
