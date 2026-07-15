#!/usr/bin/env bash

t1_die() {
  printf 'T1 timing preflight error: %s\n' "$*" >&2
  return 2
}

t1_git() {
  env -i HOME="$HOME" PATH=/usr/bin:/bin LANG=C LC_ALL=C \
    GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null git "$@"
}

t1_require_sha256() {
  local value="$1"
  local label="$2"
  if [ "${#value}" -ne 64 ]; then
    t1_die "$label must be a lowercase SHA-256"
    return
  fi
  case "$value" in
    *[!0-9a-f]*) t1_die "$label must be a lowercase SHA-256" ;;
  esac
}

t1_verify_pinned_tool() {
  local label="$1"
  local path_name="$2"
  local sha_name="$3"
  local version_name="$4"
  local configured="${!path_name:-}"
  local expected_sha256="${!sha_name:-}"
  local expected_version="${!version_name:-}"
  local canonical actual_sha256 actual_output actual_version

  [ -n "$configured" ] || { t1_die "$path_name must be set"; return; }
  case "$configured" in
    /*) ;;
    *) t1_die "$path_name must be absolute"; return ;;
  esac
  canonical="$(readlink -f -- "$configured")" || {
    t1_die "cannot canonicalize $label at $configured"
    return
  }
  [ "$canonical" = "$configured" ] || {
    t1_die "$path_name must be its canonical realpath: $canonical"
    return
  }
  [ -f "$configured" ] && [ -x "$configured" ] && [ ! -L "$configured" ] || {
    t1_die "$label is not a regular executable: $configured"
    return
  }
  t1_require_sha256 "$expected_sha256" "$sha_name" || return
  [ -n "$expected_version" ] || { t1_die "$version_name must be set"; return; }
  actual_sha256="$(sha256sum "$configured" | awk '{print $1}')"
  [ "$actual_sha256" = "$expected_sha256" ] || {
    t1_die "$label hash mismatch: expected $expected_sha256, got $actual_sha256"
    return
  }
  actual_output="$("$configured" --version 2>&1)" || {
    t1_die "$label --version failed"
    return
  }
  actual_version="${actual_output%%$'\n'*}"
  [ "$actual_version" = "$expected_version" ] || {
    t1_die "$label version mismatch: expected $expected_version, got $actual_version"
    return
  }
}

t1_verify_bound_file() {
  local path="$1"
  local expected_sha256="$2"
  local label="$3"
  local actual_sha256
  t1_require_sha256 "$expected_sha256" "$label SHA-256" || return
  [ -f "$path" ] && [ ! -L "$path" ] || { t1_die "$label is not a regular file: $path"; return; }
  actual_sha256="$(sha256sum "$path" | awk '{print $1}')"
  [ "$actual_sha256" = "$expected_sha256" ] || {
    t1_die "$label hash mismatch: expected $expected_sha256, got $actual_sha256"
    return
  }
}

t1_reject_forbidden_euf_viper_environment() {
  local name
  local forbidden=(
    EUF_VIPER_WMI_HOST
    EUF_VIPER_EXPECTED_REVISION
    EUF_VIPER_T1_PUBLISHED_REF
    EUF_VIPER_T1_REMOTE_PARENT
    EUF_VIPER_T1_CAMPAIGN_TAG
    EUF_VIPER_T1_DEPENDENCY
    EUF_VIPER_T1_PARTITION
    EUF_VIPER_T1_NODELIST
    EUF_VIPER_T1_TIMING_CONTRACT
    EUF_VIPER_T1_TIMING_MANIFEST
    EUF_VIPER_T1_TIMING_ROOT
    EUF_VIPER_T1_TIMING_ACCEPTED_PARITY_RECEIPT
    EUF_VIPER_T1_TIMING_BUILD_RECEIPT
    EUF_VIPER_T1_EXPECTED_CONTRACT_SHA256
    EUF_VIPER_T1_EXPECTED_MANIFEST_SHA256
    EUF_VIPER_T1_EXPECTED_CHECKOUT_RECEIPT_SHA256
    EUF_VIPER_T1_EXPECTED_PARITY_RECEIPT_SHA256
    EUF_VIPER_T1_SOURCE_ROOT
    EUF_VIPER_SHARED_CORPUS
  )
  for name in "${forbidden[@]}"; do
    if [ -n "${!name+x}" ]; then
      t1_die "ambient override is forbidden: $name"
      return
    fi
  done
}

t1_reject_ambient_influence() {
  local name
  t1_reject_forbidden_euf_viper_environment || return
  for name in $(compgen -e); do
    case "$name" in
      PYTHON*|CARGO_*|RUSTFLAGS|RUSTDOCFLAGS|RUSTC|RUSTC_*|RUSTUP_*|\
      CC|CXX|CPP|AR|LD|CFLAGS|CXXFLAGS|CPPFLAGS|LDFLAGS|MAKEFLAGS|NUM_JOBS|\
      BINDGEN_*|LIBCLANG_PATH|PKG_CONFIG*|LD_*|DYLD_*|MALLOC_*|GLIBC_TUNABLES|\
      ASAN_*|TSAN_*|UBSAN_*|LSAN_*|GIT_*|BASH_ENV|ENV|CDPATH)
        unset "$name"
        ;;
    esac
  done
  export PATH=/usr/bin:/bin
}

t1_verify_checkout() {
  local expected_revision="$1"
  local published_ref="$2"
  local actual_revision published_revision expected_tree index_tree nonnormal
  local path entry expected_mode expected_blob actual_blob state
  local critical_paths=(
    Cargo.lock
    Cargo.toml
    campaigns/t1-typed-parser-timing-v1.json
    results/wmi/typed-parser-parity-146510/audit.json
    results/wmi/typed-parser-parity-146510/prepare.json
    results/wmi/typed-parser-parity-146510/preflight.json
    results/wmi/typed-parser-parity-146510/receipt.json
    results/wmi/typed-parser-parity-146510/submission.json
    results/wmi/typed-parser-parity-146510/typed-parser-parity-20260713T221314Z-66099-independent.json
    scripts/bench/typed_parser_timing.py
    scripts/wmi/t1_timing_build_guard.py
    scripts/wmi/t1_timing_checkout_receipt.py
    scripts/wmi/t1_timing_common.sh
    scripts/wmi/t1_timing_remote_submit.py
    scripts/wmi/euf_viper_t1_timing_prepare.sbatch
    scripts/wmi/euf_viper_t1_timing_array.sbatch
    scripts/wmi/euf_viper_t1_timing_audit.sbatch
    scripts/wmi/submit_t1_timing.sh
    src/main.rs
    src/smt2_stream.rs
  )

  [ "${#expected_revision}" -eq 40 ] || { t1_die "expected revision must have 40 hex digits"; return; }
  case "$expected_revision" in
    *[!0-9a-f]*) t1_die "expected revision is malformed"; return ;;
  esac
  case "$published_ref" in
    ''|*[!A-Za-z0-9._/-]*|*..*|-*) t1_die "published ref is unsafe"; return ;;
  esac
  actual_revision="$(t1_git rev-parse --verify HEAD^{commit})"
  [ "$actual_revision" = "$expected_revision" ] || {
    t1_die "revision mismatch: expected $expected_revision, got $actual_revision"
    return
  }
  published_revision="$(t1_git rev-parse --verify "$published_ref^{commit}")" || {
    t1_die "published ref is unavailable: $published_ref"
    return
  }
  [ "$published_revision" = "$expected_revision" ] || {
    t1_die "published ref $published_ref resolves to $published_revision"
    return
  }
  nonnormal="$(t1_git ls-files -v | awk '$1 != "H" {print; exit}')"
  [ -z "$nonnormal" ] || { t1_die "tracked index has nonnormal flags: $nonnormal"; return; }
  t1_git diff --quiet -- || { t1_die "tracked worktree differs from HEAD"; return; }
  t1_git diff --cached --quiet -- || { t1_die "index differs from HEAD"; return; }
  [ -z "$(t1_git status --porcelain=v1 --untracked-files=all)" ] || {
    t1_die "checkout contains untracked influence"
    return
  }
  [ -z "$(t1_git ls-files --others --ignored --exclude-standard)" ] || {
    t1_die "checkout contains ignored influence"
    return
  }
  for path in "$PWD/.cargo/config" "$PWD/.cargo/config.toml" "$HOME/.cargo/config" "$HOME/.cargo/config.toml" "/.cargo/config" "/.cargo/config.toml"; do
    [ ! -e "$path" ] || { t1_die "cargo configuration can influence build: $path"; return; }
  done
  expected_tree="$(t1_git rev-parse --verify "$expected_revision^{tree}")"
  index_tree="$(t1_git write-tree)"
  [ "$index_tree" = "$expected_tree" ] || { t1_die "index tree differs from published revision"; return; }

  for path in "${critical_paths[@]}"; do
    [ -f "$path" ] && [ ! -L "$path" ] || {
      t1_die "critical runtime path is missing or not regular: $path"
      return
    }
    state="$(t1_git ls-files -v -- "$path")"
    [ "$state" = "H $path" ] || { t1_die "critical path has hidden index state: $state"; return; }
    entry="$(t1_git ls-tree "$expected_revision" -- "$path")"
    expected_mode="${entry%% *}"
    expected_blob="$(printf '%s\n' "$entry" | awk '{print $3}')"
    actual_blob="$(t1_git hash-object --no-filters -- "$path")"
    [ "$actual_blob" = "$expected_blob" ] || { t1_die "critical path blob mismatch: $path"; return; }
    case "$expected_mode" in
      100755) [ -x "$path" ] || { t1_die "critical executable mode mismatch: $path"; return; } ;;
      100644) [ ! -x "$path" ] || { t1_die "critical nonexecutable mode mismatch: $path"; return; } ;;
      *) t1_die "unsupported critical tree mode $expected_mode for $path"; return ;;
    esac
  done
}
