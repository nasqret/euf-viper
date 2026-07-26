#!/usr/bin/env bash
set -euo pipefail

RUST_MODULE_GCC="GCCcore/14.3.0"
RUST_MODULE="Rust/1.88.0"

die() {
  printf '%s\n' "$*" >&2
  exit 2
}

hash_file() {
  sha256sum "$1" | awk '{print $1}'
}

module_location() {
  local output location
  output="$(module --redirect --location show "$1" 2>/dev/null)" || \
    die "cannot resolve modulefile for $1"
  location="$(printf '%s\n' "$output" | awk 'NF {line=$0} END {print line}')"
  [ -n "$location" ] && [ -f "$location" ] || \
    die "modulefile for $1 is not a regular file: $location"
  readlink -f -- "$location"
}

[ "$#" -eq 0 ] || die "usage: toolchain_receipt.sh"
command -v module >/dev/null 2>&1 || die "Lmod module command is unavailable"

module --force purge
module load GCCcore/14.3.0 Rust/1.88.0

[ "$(uname -m)" = x86_64 ] || die "Rust toolchain host must be x86_64"
RUSTC_VERBOSE="$(rustc -vV)"
printf '%s\n' "$RUSTC_VERBOSE" | grep -Fx 'release: 1.88.0' >/dev/null || \
  die "Rust module did not provide rustc 1.88.0"
printf '%s\n' "$RUSTC_VERBOSE" | grep -Fx 'host: x86_64-unknown-linux-gnu' >/dev/null || \
  die "Rust module did not provide the x86_64 Linux host"
printf '%s\n' "$RUSTC_VERBOSE" | grep -Fx 'LLVM version: 20.1.5' >/dev/null || \
  die "Rust module did not provide LLVM 20.1.5"

printf 'kind\tname\tpath\tsha256\n'
LOADED_MODULES="$(module --terse list 2>&1 | \
  awk '/^[A-Za-z0-9_.+-]+\/[A-Za-z0-9_.+-]+$/ {print}' | LC_ALL=C sort -u)"
for required in "$RUST_MODULE_GCC" "$RUST_MODULE"; do
  printf '%s\n' "$LOADED_MODULES" | grep -Fx "$required" >/dev/null || \
    die "required module is not loaded: $required"
done
while IFS= read -r specification; do
  [ -n "$specification" ] || continue
  location="$(module_location "$specification")"
  printf 'module\t%s\t%s\t%s\n' \
    "$specification" "$location" "$(hash_file "$location")"
done <<<"$LOADED_MODULES"

for binding in \
  bash:bash \
  cargo:cargo \
  git:git \
  python3:python3 \
  rsync:rsync \
  rustc:rustc \
  sbatch:sbatch \
  sha256sum:sha256sum \
  srun:srun; do
  label="${binding%%:*}"
  requested="${binding#*:}"
  if [ "${requested#/}" != "$requested" ]; then
    path="$requested"
  else
    path="$(command -v "$requested")" || die "missing required tool: $requested"
  fi
  path="$(readlink -f -- "$path")"
  [ -f "$path" ] && [ -x "$path" ] || die "tool is not executable: $path"
  printf 'tool\t%s\t%s\t%s\n' "$label" "$path" "$(hash_file "$path")"
done
