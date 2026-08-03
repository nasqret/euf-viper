#!/usr/bin/env bash
#SBATCH --job-name=euf-t11-prebuilt
#SBATCH --partition=cpu_idle
#SBATCH --cpus-per-task=2
#SBATCH --mem=8G
#SBATCH --time=02:00:00

set -euo pipefail
umask 077

die() {
  echo "T11 prebuilt preparation rejected: $*" >&2
  exit 2
}

canonical_sha256() {
  [ "${#1}" -eq 64 ] || return 1
  case "$1" in *[!0-9a-f]*) return 1 ;; *) return 0 ;; esac
}

readonly SOURCE_REPOSITORY="${EUF_VIPER_T11_SOURCE_REPOSITORY:?set clean source repository}"
readonly EXPECTED_COMMIT="${EUF_VIPER_T11_EXPECTED_COMMIT:?set exact source commit}"
readonly OUTPUT_DIRECTORY="${EUF_VIPER_T11_PREBUILT_OUTPUT:?set fresh prebuilt output directory}"
readonly SCRATCH_BASE="${EUF_VIPER_T11_SCRATCH_BASE:?set scratch base}"
readonly CARGO_HOME="${EUF_VIPER_T11_CARGO_HOME:?set offline Cargo home}"
readonly PYTHON="${EUF_VIPER_T11_PYTHON:?set pinned Python path}"
readonly PYTHON_SHA256="${EUF_VIPER_T11_PYTHON_SHA256:?set pinned Python SHA-256}"
readonly CARGO="${EUF_VIPER_T11_CARGO:?set pinned Cargo path}"
readonly CARGO_SHA256="${EUF_VIPER_T11_CARGO_SHA256:?set pinned Cargo SHA-256}"
readonly RUSTC="${EUF_VIPER_T11_RUSTC:?set pinned rustc path}"
readonly RUSTC_SHA256="${EUF_VIPER_T11_RUSTC_SHA256:?set pinned rustc SHA-256}"
readonly PREPARER="${EUF_VIPER_T11_PREPARER:?set preparation tool path}"
readonly PREPARER_SHA256="${EUF_VIPER_T11_PREPARER_SHA256:?set preparation tool SHA-256}"
readonly BUNDLE_TOOL="${EUF_VIPER_T11_BUNDLE_TOOL:?set prebuilt bundle tool path}"
readonly BUNDLE_TOOL_SHA256="${EUF_VIPER_T11_BUNDLE_TOOL_SHA256:?set bundle tool SHA-256}"
readonly PREPARATION_STDOUT="${EUF_VIPER_T11_PREPARATION_STDOUT:?set fresh stdout artifact path}"
readonly PREPARATION_STDERR="${EUF_VIPER_T11_PREPARATION_STDERR:?set fresh stderr artifact path}"

case "$EXPECTED_COMMIT" in *[!0-9a-f]*|'') die "expected commit is malformed" ;; esac
[ "${#EXPECTED_COMMIT}" -eq 40 ] || die "expected commit must contain 40 lowercase hex digits"
for digest in \
  "$PYTHON_SHA256" "$CARGO_SHA256" "$RUSTC_SHA256" \
  "$PREPARER_SHA256" "$BUNDLE_TOOL_SHA256"; do
  canonical_sha256 "$digest" || die "one pinned SHA-256 is malformed"
done
for path in \
  "$SOURCE_REPOSITORY" "$OUTPUT_DIRECTORY" "$SCRATCH_BASE" "$CARGO_HOME" \
  "$PYTHON" "$CARGO" "$RUSTC" "$PREPARER" "$BUNDLE_TOOL" \
  "$PREPARATION_STDOUT" "$PREPARATION_STDERR"; do
  case "$path" in /*) ;; *) die "all paths must be absolute: $path" ;; esac
done

sha256_file() {
  /usr/bin/sha256sum --binary "$1" | /usr/bin/cut -d ' ' -f 1
}

require_tool() {
  local path="$1"
  local expected="$2"
  local label="$3"
  [ -f "$path" ] && [ ! -L "$path" ] || die "$label is missing, nonregular, or a symlink"
  [ "$(sha256_file "$path")" = "$expected" ] || die "$label SHA-256 differs"
}

require_tool "$PYTHON" "$PYTHON_SHA256" python
require_tool "$CARGO" "$CARGO_SHA256" cargo
require_tool "$RUSTC" "$RUSTC_SHA256" rustc
require_tool "$PREPARER" "$PREPARER_SHA256" preparer
require_tool "$BUNDLE_TOOL" "$BUNDLE_TOOL_SHA256" bundle-tool
[ -x "$PYTHON" ] && [ -x "$CARGO" ] && [ -x "$RUSTC" ] && [ -x "$PREPARER" ] ||
  die "one pinned tool is not executable"
[ -d "$SOURCE_REPOSITORY" ] && [ ! -L "$SOURCE_REPOSITORY" ] || die "source repository is invalid"
[ -d "$SCRATCH_BASE" ] && [ ! -L "$SCRATCH_BASE" ] || die "scratch base is invalid"
[ -d "$CARGO_HOME" ] && [ ! -L "$CARGO_HOME" ] || die "Cargo home is invalid"
[ ! -e "$OUTPUT_DIRECTORY" ] || die "prebuilt output path already exists"
[ ! -e "$PREPARATION_STDOUT" ] || die "preparation stdout path already exists"
[ ! -e "$PREPARATION_STDERR" ] || die "preparation stderr path already exists"

[ "$(/usr/bin/git -C "$SOURCE_REPOSITORY" rev-parse --verify HEAD^{commit})" = "$EXPECTED_COMMIT" ] ||
  die "source commit differs"
[ -z "$(/usr/bin/git -C "$SOURCE_REPOSITORY" status --porcelain=v1 --untracked-files=all)" ] ||
  die "source repository is dirty"

set +e
/usr/bin/env -i \
  HOME=/ LANG=C LC_ALL=C PATH=/usr/bin:/bin TZ=UTC \
  "$PYTHON" -I -S -B "$PREPARER" \
    --source-repository "$SOURCE_REPOSITORY" \
    --expected-commit "$EXPECTED_COMMIT" \
    --output-directory "$OUTPUT_DIRECTORY" \
    --scratch-base "$SCRATCH_BASE" \
    --cargo-home "$CARGO_HOME" \
    --cargo "$CARGO" \
    --rustc "$RUSTC" \
    --controller-python "$PYTHON" \
    --bundle-tool "$BUNDLE_TOOL" \
    >"$PREPARATION_STDOUT" 2>"$PREPARATION_STDERR"
status=$?
set -e
chmod 400 "$PREPARATION_STDOUT" "$PREPARATION_STDERR"
[ "$status" -eq 0 ] || die "preparation tool failed with exit $status"
[ -z "$(/usr/bin/git -C "$SOURCE_REPOSITORY" status --porcelain=v1 --untracked-files=all)" ] ||
  die "source repository became dirty"

printf 't11_prebuilt_output=%s\n' "$OUTPUT_DIRECTORY"
printf 't11_prebuilt_preparation=%s/preparation.json\n' "$OUTPUT_DIRECTORY"
printf 't11_prebuilt_stdout_sha256=%s\n' "$(sha256_file "$PREPARATION_STDOUT")"
