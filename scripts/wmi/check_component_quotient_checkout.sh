#!/usr/bin/env bash
set -euo pipefail

EXPECTED_REVISION="${1:?usage: check_component_quotient_checkout.sh REVISION}"
if [[ ! "$EXPECTED_REVISION" =~ ^[0-9a-f]{40}$ ]]; then
  echo "expected revision must be a full lowercase Git SHA-1" >&2
  exit 2
fi

reject_hostile_environment() {
  local entry name
  while IFS= read -r entry; do
    name="${entry%%=*}"
    case "$name" in
      BASH_ENV|CDPATH|ENV|GIT_*|PYTHON*|CARGO_*|RUST*|LD_*|DYLD_*|BASH_FUNC_*)
        echo "hostile ambient environment is forbidden: $name" >&2
        exit 2
        ;;
    esac
  done < <(env)
}

reject_hostile_environment

ROOT="$(pwd -P)"
GIT_DIR_ABS="$(
  env -i \
    PATH=/usr/bin:/bin HOME=/nonexistent LANG=C LC_ALL=C \
    GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null \
    git -C "$ROOT" rev-parse --absolute-git-dir
)"

safe_git() {
  env -i \
    PATH=/usr/bin:/bin HOME=/nonexistent LANG=C LC_ALL=C \
    GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null \
    GIT_PAGER=cat \
    git --git-dir="$GIT_DIR_ABS" --work-tree="$ROOT" "$@"
}

ACTUAL_REVISION="$(safe_git rev-parse HEAD)"
if [ "$ACTUAL_REVISION" != "$EXPECTED_REVISION" ]; then
  echo "revision mismatch: expected $EXPECTED_REVISION, got $ACTUAL_REVISION" >&2
  exit 2
fi

FLAGGED_INDEX_ENTRIES=()
while IFS= read -r -d '' entry; do
  flag="${entry:0:1}"
  if [ "$flag" = S ] || [[ "$flag" =~ [a-z] ]]; then
    FLAGGED_INDEX_ENTRIES+=("$entry")
  fi
done < <(safe_git ls-files -v -z)
if [ "${#FLAGGED_INDEX_ENTRIES[@]}" -ne 0 ]; then
  echo "skip-worktree and assume-unchanged index flags are forbidden" >&2
  printf '%s\n' "${FLAGGED_INDEX_ENTRIES[@]}" >&2
  exit 2
fi

STATUS="$(safe_git status --porcelain=v1 --untracked-files=all)"
if [ -n "$STATUS" ]; then
  echo "repository state is dirty, including untracked files" >&2
  printf '%s\n' "$STATUS" >&2
  exit 2
fi

IGNORED_RUNTIME_INFLUENCE=()
while IFS= read -r -d '' path; do
  case "$path" in
    scripts/*|\
    *.py|*.pyi|*.pyc|*.pyo|*.pth|*.so|*.dylib|\
    __pycache__/*|*/__pycache__/*|\
    pyproject.toml|*/pyproject.toml|setup.cfg|*/setup.cfg|\
    tox.ini|*/tox.ini|pytest.ini|*/pytest.ini|\
    .python-version|*/.python-version|.env|*/.env|.env.*|*/.env.*|\
    requirements*.txt|*/requirements*.txt|\
    Cargo.toml|*/Cargo.toml|Cargo.lock|*/Cargo.lock|build.rs|*/build.rs|\
    .cargo/config|.cargo/config.toml|*/.cargo/config|*/.cargo/config.toml|\
    target/*|*/target/*|build/*|*/build/*|dist/*|*/dist/*|\
    .venv/*|*/.venv/*|venv/*|*/venv/*|.tox/*|*/.tox/*)
      IGNORED_RUNTIME_INFLUENCE+=("$path")
      ;;
  esac
done < <(safe_git ls-files --others --ignored --exclude-standard -z)
if [ "${#IGNORED_RUNTIME_INFLUENCE[@]}" -ne 0 ]; then
  echo "ignored Python, configuration, or build influence is forbidden" >&2
  printf '%s\n' "${IGNORED_RUNTIME_INFLUENCE[@]}" >&2
  exit 2
fi

PROJECT_RUNTIME_FILES=(
  .github/workflows/campaign-contract.yml
  campaigns/component-quotient-ram-census-v1.json
  benchmarks/smtcomp-2025/qf_uf_manifest.jsonl
  scripts/bench/build_family_manifest.py
  scripts/bench/census_component_quotient_ram.py
  scripts/bench/component_quotient_contract.py
  scripts/bench/finalize_component_quotient_ram_metadata.py
  scripts/bench/independent_component_quotient_verifier.py
  scripts/bench/t5_independent_smtlib.py
  scripts/bench/t5_held_scheduler.py
  scripts/bench/t5_linux_publication.py
  scripts/bench/t5_runtime_environment.py
  scripts/bench/t5_submission_receipt.py
  scripts/bench/verify_component_quotient_publication.py
  scripts/bench/verify_component_quotient_ram_bundle.py
  scripts/cert/independent_qfuf.py
  scripts/wmi/check_component_quotient_checkout.sh
  scripts/wmi/euf_viper_component_quotient_census.sbatch
  scripts/wmi/submit_component_quotient_census.sh
)

for path in "${PROJECT_RUNTIME_FILES[@]}"; do
  tree_entry="$(safe_git ls-tree "$EXPECTED_REVISION" -- "$path")"
  if [ -z "$tree_entry" ]; then
    echo "runtime project file is absent from expected tree: $path" >&2
    exit 2
  fi
  metadata="${tree_entry%%$'\t'*}"
  tree_path="${tree_entry#*$'\t'}"
  read -r mode object_type expected_blob <<< "$metadata"
  if [ "$tree_path" != "$path" ] || [ "$object_type" != blob ]; then
    echo "runtime project path has unexpected tree identity: $path" >&2
    exit 2
  fi
  if [ "$mode" = 100755 ]; then
    [ -x "$path" ] || {
      echo "runtime project file lost executable mode: $path" >&2
      exit 2
    }
  elif [ "$mode" = 100644 ]; then
    [ ! -x "$path" ] || {
      echo "runtime project file gained executable mode: $path" >&2
      exit 2
    }
  else
    echo "runtime project file has unsupported tree mode $mode: $path" >&2
    exit 2
  fi
  if ! cmp -s -- "$path" <(safe_git cat-file blob "$EXPECTED_REVISION:$path"); then
    echo "runtime project bytes differ from expected revision blob: $path" >&2
    exit 2
  fi
  actual_blob="$(safe_git hash-object --no-filters -- "$path")"
  if [ "$actual_blob" != "$expected_blob" ]; then
    echo "runtime project object differs from expected revision blob: $path" >&2
    exit 2
  fi
done

if command -v sha256sum >/dev/null 2>&1; then
  LOCK_SHA256="$(sha256sum -- campaigns/component-quotient-ram-census-v1.json)"
else
  LOCK_SHA256="$(shasum -a 256 -- campaigns/component-quotient-ram-census-v1.json)"
fi
LOCK_SHA256="${LOCK_SHA256%% *}"
if [ "$LOCK_SHA256" != 7958892d3bf45abbf7d40f31b75c5cdf07a6aec13c66442278685b0ad4eddc24 ]; then
  echo "T5 campaign lock differs from the preregistered contract" >&2
  exit 2
fi

if command -v sha256sum >/dev/null 2>&1; then
  MANIFEST_SHA256="$(sha256sum -- benchmarks/smtcomp-2025/qf_uf_manifest.jsonl)"
else
  MANIFEST_SHA256="$(shasum -a 256 -- benchmarks/smtcomp-2025/qf_uf_manifest.jsonl)"
fi
MANIFEST_SHA256="${MANIFEST_SHA256%% *}"
OFFICIAL_ROWS="$(wc -l < benchmarks/smtcomp-2025/qf_uf_manifest.jsonl)"
OFFICIAL_ROWS="${OFFICIAL_ROWS//[[:space:]]/}"
if [ "$MANIFEST_SHA256" != ed00b0e2105ec9579b02448d161e7f04ceceaf816919535b48734c6525a2aaa6 ] || \
   [ "$OFFICIAL_ROWS" != 3521 ]; then
  echo "tracked official manifest no longer has its bound 3,521-row identity" >&2
  exit 2
fi
