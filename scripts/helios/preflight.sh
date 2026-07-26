#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SSH_TARGET="${EUF_VIPER_HELIOS_SSH_TARGET:-helios}"
EXPECTED_USER="${EUF_VIPER_HELIOS_USER:-plgnasqret}"
GRANT="${EUF_VIPER_HELIOS_GRANT:-plgccaiautore2026}"
ACCOUNT="${EUF_VIPER_HELIOS_ACCOUNT:-plgccaiautore2026-cpu}"
PARTITION="${EUF_VIPER_HELIOS_PARTITION:-plgrid}"
EXPECTED_SCRATCH="${EUF_VIPER_HELIOS_SCRATCH:-/net/scratch/hscra/plgrid/plgnasqret}"
REMOTE_ROOT_SPEC="${EUF_VIPER_HELIOS_REMOTE_ROOT:-\$SCRATCH/codex-control/projects/euf-viper}"

die() {
  printf '%s\n' "$*" >&2
  exit 2
}

usage() {
  cat <<'USAGE'
usage: preflight.sh

Checks the Helios login identity, active CPU grant, scratch root, scheduler,
the exact GCCcore/Rust module stack, x86_64 Rust host, and executable hashes.
The machine-readable TSV report is written to stdout.
USAGE
}

case "${1:-}" in
  '') ;;
  -h|--help) usage; exit 0 ;;
  *) usage >&2; die "unknown argument: $1" ;;
esac

for value in "$SSH_TARGET" "$EXPECTED_USER" "$GRANT" "$ACCOUNT" "$PARTITION"; do
  [[ "$value" =~ ^[A-Za-z0-9_.@+-]+$ ]] || die "unsafe Helios setting: $value"
done
case "$ACCOUNT" in
  *-cpu) ;;
  *) die "Helios account must be a CPU account" ;;
esac
case "$REMOTE_ROOT_SPEC" in
  '$SCRATCH'|'$SCRATCH'/*|/*) ;;
  *) die "remote root must be an absolute path or start with literal \$SCRATCH" ;;
esac
[[ "$REMOTE_ROOT_SPEC" =~ ^[A-Za-z0-9_./$+-]+$ ]] || die "unsafe remote root"
case "/$REMOTE_ROOT_SPEC/" in
  */../*) die "remote root cannot contain .." ;;
esac
command -v ssh >/dev/null || die "ssh is required"
command -v shasum >/dev/null || die "shasum is required"

remote_facts() {
  ssh -o BatchMode=yes -o ConnectTimeout=15 "$SSH_TARGET" \
    "EXPECTED_USER='$EXPECTED_USER' GRANT='$GRANT' ACCOUNT='$ACCOUNT' PARTITION='$PARTITION' EXPECTED_SCRATCH='$EXPECTED_SCRATCH' REMOTE_ROOT_SPEC='$REMOTE_ROOT_SPEC' bash -l -s" <<'REMOTE'
set -euo pipefail

die() {
  printf '%s\n' "$*" >&2
  exit 2
}

[ "$(id -un)" = "$EXPECTED_USER" ] || die "unexpected Helios user: $(id -un)"
[ "$(uname -m)" = x86_64 ] || die "Helios login host is not x86_64"
for program in hpc-grants python3 readlink sbatch scancel sha256sum sinfo squeue srun; do
  command -v "$program" >/dev/null || die "missing Helios command: $program"
done
[ -n "${SCRATCH:-}" ] || die "SCRATCH is unset"
scratch="$(readlink -f -- "$SCRATCH")"
[ "$scratch" = "$EXPECTED_SCRATCH" ] || \
  die "unexpected SCRATCH: expected $EXPECTED_SCRATCH, got $scratch"
[ -d "$scratch" ] && [ -r "$scratch" ] && [ -w "$scratch" ] || \
  die "SCRATCH is not readable and writable"

case "$REMOTE_ROOT_SPEC" in
  '$SCRATCH') root="$scratch" ;;
  '$SCRATCH'/*) root="$scratch/${REMOTE_ROOT_SPEC#\$SCRATCH/}" ;;
  /*) root="$REMOTE_ROOT_SPEC" ;;
  *) die "invalid remote root" ;;
esac
case "$root" in
  "$scratch"|"$scratch"/*) ;;
  *) die "remote root escapes SCRATCH" ;;
esac
mkdir -p "$root"
root="$(readlink -f -- "$root")"
test -d "$root" && test ! -L "$root" && test -O "$root" || \
  die "remote root is not an owned directory: $root"
chmod u+rwx "$root"
for namespace in \
  campaigns corpora corpus-receipts helpers incoming logs manifest-sources \
  orchestration-checkouts rebased-manifests runs solver-checkouts tools
do
  path="$root/$namespace"
  if [ -e "$path" ] || [ -L "$path" ]; then
    test -d "$path" && test ! -L "$path" && test -O "$path" || \
      die "campaign namespace is not an owned directory: $path"
  else
    mkdir "$path"
  fi
  # Namespace containers stay mutable; content-addressed children are sealed.
  chmod u+rwx "$path"
  test -w "$path" || die "campaign namespace is not writable: $path"
done

grants="$(hpc-grants)"
printf '%s\n' "$grants" | grep -F "$GRANT" >/dev/null || \
  die "grant is not active: $GRANT"
squeue -h -A "$ACCOUNT" >/dev/null
partition_probe="$(sinfo -h -p "$PARTITION" -o '%P' | awk 'NF && !seen {print; seen=1}')"
[ -n "$partition_probe" ] || die "partition is unavailable: $PARTITION"

printf 'fact\tuser\t%s\t-\n' "$EXPECTED_USER"
printf 'fact\tgrant\t%s\t-\n' "$GRANT"
printf 'fact\taccount\t%s\t-\n' "$ACCOUNT"
printf 'fact\tpartition\t%s\t-\n' "$PARTITION"
printf 'fact\tscratch\t%s\t-\n' "$scratch"
printf 'fact\tremote_root\t%s\t-\n' "$root"
printf 'fact\tremote_root_writable\ttrue\t-\n'
REMOTE
}

REMOTE_FACTS="$(remote_facts)"

TOOLCHAIN="$({
  ssh -o BatchMode=yes -o ConnectTimeout=15 "$SSH_TARGET" 'bash -l -s' \
    < "$ROOT/scripts/helios/toolchain_receipt.sh"
})"
[ "$(printf '%s\n' "$TOOLCHAIN" | sed -n '1p')" = \
  $'kind\tname\tpath\tsha256' ] || die "invalid remote toolchain receipt"
TOOLCHAIN_SHA256="$(printf '%s\n' "$TOOLCHAIN" | shasum -a 256 | awk '{print $1}')"

printf 'kind\tname\tvalue\tsha256\n'
printf 'fact\tssh_target\t%s\t-\n' "$SSH_TARGET"
printf '%s\n' "$REMOTE_FACTS"
printf '%s\n' "$TOOLCHAIN" | sed '1d'
printf 'receipt\ttoolchain\t-\t%s\n' "$TOOLCHAIN_SHA256"
