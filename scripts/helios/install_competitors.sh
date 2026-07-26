#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SSH_TARGET="${EUF_VIPER_HELIOS_SSH_TARGET:-helios}"
BUNDLE=""
RELEASE_LOCK="${EUF_VIPER_HELIOS_RELEASE_LOCK:-$ROOT/campaigns/solver-releases-2026-07.json}"

die() {
  printf '%s\n' "$*" >&2
  exit 2
}

usage() {
  cat <<'USAGE'
usage: install_competitors.sh --bundle PATH

Verifies a bundle produced by prepare_competitor_bundle.py, stages it under a
content-addressed Helios scratch path, executes every pinned solver remotely,
and atomically activates the bundle. Existing active bundles are never replaced.
USAGE
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --bundle)
      [ "$#" -ge 2 ] || die "--bundle requires a path"
      BUNDLE="$2"
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

[ -n "$BUNDLE" ] || { usage >&2; die "--bundle is required"; }
BUNDLE="$(cd "$BUNDLE" && pwd)"
[ -f "$BUNDLE/receipt.json" ] || die "bundle receipt is missing"
[ -f "$RELEASE_LOCK" ] || die "release lock is missing"
for program in python3 rsync shasum ssh; do
  command -v "$program" >/dev/null || die "$program is required"
done
[[ "$SSH_TARGET" =~ ^[A-Za-z0-9_.@+-]+$ ]] || die "unsafe SSH target"

python3 "$ROOT/scripts/helios/verify_competitor_bundle.py" \
  --bundle-root "$BUNDLE" \
  --receipt "$BUNDLE/receipt.json" \
  --release-lock "$RELEASE_LOCK" >/dev/null

PREFLIGHT="$(mktemp "${TMPDIR:-/tmp}/euf-viper-preflight.XXXXXX")"
cleanup() {
  rm -f -- "$PREFLIGHT"
}
trap cleanup EXIT HUP INT TERM
"$ROOT/scripts/helios/preflight.sh" > "$PREFLIGHT"
REMOTE_ROOT="$(awk -F '\t' '$1 == "fact" && $2 == "remote_root" {print $3}' "$PREFLIGHT")"
case "$REMOTE_ROOT" in /*) ;; *) die "preflight returned an invalid root" ;; esac

RECEIPT_SHA256="$(shasum -a 256 "$BUNDLE/receipt.json" | awk '{print $1}')"
PREPARER_SHA256="$(shasum -a 256 \
  "$ROOT/scripts/helios/prepare_competitor_bundle.py" | awk '{print $1}')"
VERIFIER_SHA256="$(shasum -a 256 \
  "$ROOT/scripts/helios/verify_competitor_bundle.py" | awk '{print $1}')"
RELEASE_LOCK_SHA256="$(shasum -a 256 "$RELEASE_LOCK" | awk '{print $1}')"
CONTROL_ID="$(printf '%s\n%s\n%s\n' \
  "$PREPARER_SHA256" "$VERIFIER_SHA256" "$RELEASE_LOCK_SHA256" | \
  shasum -a 256 | awk '{print $1}')"
TOKEN="$(date -u +%Y%m%dT%H%M%SZ)-$$"
REMOTE_BUNDLE="$REMOTE_ROOT/tools/solver-bundles/$RECEIPT_SHA256"
REMOTE_INCOMING="$REMOTE_ROOT/incoming/solver-bundle-$RECEIPT_SHA256-$TOKEN"
REMOTE_CONTROL="$REMOTE_ROOT/helpers/solver-bundle-$CONTROL_ID"
REMOTE_CONTROL_INCOMING="$REMOTE_ROOT/incoming/solver-control-$CONTROL_ID-$TOKEN"
REMOTE_ACTIVE="$REMOTE_ROOT/tools/solvers"

if ssh -o BatchMode=yes -o ConnectTimeout=15 "$SSH_TARGET" \
  "REMOTE_BUNDLE='$REMOTE_BUNDLE' REMOTE_CONTROL='$REMOTE_CONTROL' REMOTE_ACTIVE='$REMOTE_ACTIVE' RECEIPT_SHA256='$RECEIPT_SHA256' PREPARER_SHA256='$PREPARER_SHA256' VERIFIER_SHA256='$VERIFIER_SHA256' RELEASE_LOCK_SHA256='$RELEASE_LOCK_SHA256' bash -l -s" <<'REMOTE'
set -euo pipefail
test -d "$REMOTE_BUNDLE"
test -d "$REMOTE_CONTROL"
test -L "$REMOTE_ACTIVE"
test "$(readlink -f -- "$REMOTE_ACTIVE")" = "$REMOTE_BUNDLE"
test "$(sha256sum "$REMOTE_BUNDLE/receipt.json" | awk '{print $1}')" = "$RECEIPT_SHA256"
test "$(sha256sum "$REMOTE_CONTROL/prepare_competitor_bundle.py" | awk '{print $1}')" = "$PREPARER_SHA256"
test "$(sha256sum "$REMOTE_CONTROL/verify_competitor_bundle.py" | awk '{print $1}')" = "$VERIFIER_SHA256"
test "$(sha256sum "$REMOTE_CONTROL/solver-releases-2026-07.json" | awk '{print $1}')" = "$RELEASE_LOCK_SHA256"
REMOTE
then
  ssh -o BatchMode=yes -o ConnectTimeout=15 "$SSH_TARGET" \
    "python3 '$REMOTE_CONTROL/verify_competitor_bundle.py' --bundle-root '$REMOTE_BUNDLE' --receipt '$REMOTE_BUNDLE/receipt.json' --release-lock '$REMOTE_CONTROL/solver-releases-2026-07.json' --execute --format tsv"
  exit 0
fi

ssh -o BatchMode=yes -o ConnectTimeout=15 "$SSH_TARGET" \
  "REMOTE_ROOT='$REMOTE_ROOT' REMOTE_INCOMING='$REMOTE_INCOMING' REMOTE_CONTROL_INCOMING='$REMOTE_CONTROL_INCOMING' bash -l -s" <<'REMOTE'
set -euo pipefail
mkdir -p "$REMOTE_ROOT"/{helpers,incoming,tools/solver-bundles}
test ! -e "$REMOTE_INCOMING"
test ! -e "$REMOTE_CONTROL_INCOMING"
mkdir "$REMOTE_INCOMING" "$REMOTE_CONTROL_INCOMING"
REMOTE

rsync -az --delete -e "ssh -o BatchMode=yes -o ConnectTimeout=15" \
  "$BUNDLE/" "$SSH_TARGET:$REMOTE_INCOMING/"
rsync -az -e "ssh -o BatchMode=yes -o ConnectTimeout=15" \
  "$ROOT/scripts/helios/prepare_competitor_bundle.py" \
  "$ROOT/scripts/helios/verify_competitor_bundle.py" \
  "$RELEASE_LOCK" \
  "$SSH_TARGET:$REMOTE_CONTROL_INCOMING/"

ssh -o BatchMode=yes -o ConnectTimeout=15 "$SSH_TARGET" \
  "REMOTE_BUNDLE='$REMOTE_BUNDLE' REMOTE_INCOMING='$REMOTE_INCOMING' REMOTE_CONTROL='$REMOTE_CONTROL' REMOTE_CONTROL_INCOMING='$REMOTE_CONTROL_INCOMING' REMOTE_ACTIVE='$REMOTE_ACTIVE' RECEIPT_SHA256='$RECEIPT_SHA256' PREPARER_SHA256='$PREPARER_SHA256' VERIFIER_SHA256='$VERIFIER_SHA256' RELEASE_LOCK_SHA256='$RELEASE_LOCK_SHA256' bash -l -s" <<'REMOTE'
set -euo pipefail
preparer="$REMOTE_CONTROL_INCOMING/prepare_competitor_bundle.py"
verifier="$REMOTE_CONTROL_INCOMING/verify_competitor_bundle.py"
release_lock="$REMOTE_CONTROL_INCOMING/solver-releases-2026-07.json"
test "$(sha256sum "$preparer" | awk '{print $1}')" = "$PREPARER_SHA256"
test "$(sha256sum "$verifier" | awk '{print $1}')" = "$VERIFIER_SHA256"
test "$(sha256sum "$release_lock" | awk '{print $1}')" = "$RELEASE_LOCK_SHA256"
test "$(sha256sum "$REMOTE_INCOMING/receipt.json" | awk '{print $1}')" = "$RECEIPT_SHA256"
python3 "$verifier" \
  --bundle-root "$REMOTE_INCOMING" \
  --receipt "$REMOTE_INCOMING/receipt.json" \
  --release-lock "$release_lock" \
  --execute >/dev/null
chmod u+w "$REMOTE_CONTROL_INCOMING" "$REMOTE_INCOMING"
test ! -e "$REMOTE_CONTROL"
test ! -e "$REMOTE_BUNDLE"
mv "$REMOTE_CONTROL_INCOMING" "$REMOTE_CONTROL"
mv "$REMOTE_INCOMING" "$REMOTE_BUNDLE"
chmod -R a-w "$REMOTE_CONTROL" "$REMOTE_BUNDLE"
if test -e "$REMOTE_ACTIVE" || test -L "$REMOTE_ACTIVE"; then
  test "$(readlink -f -- "$REMOTE_ACTIVE")" = "$REMOTE_BUNDLE"
else
  ln -s "solver-bundles/$RECEIPT_SHA256" "$REMOTE_ACTIVE"
fi
python3 "$REMOTE_CONTROL/verify_competitor_bundle.py" \
  --bundle-root "$REMOTE_BUNDLE" \
  --receipt "$REMOTE_BUNDLE/receipt.json" \
  --release-lock "$REMOTE_CONTROL/solver-releases-2026-07.json" \
  --execute \
  --format tsv
REMOTE
