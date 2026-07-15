#!/bin/bash
#SBATCH --job-name=euf-p0-prepare
#SBATCH --partition=cpu_idle
#SBATCH --cpus-per-task=1
#SBATCH --mem=16G
#SBATCH --time=02:00:00
#SBATCH --output=/dev/null
#SBATCH --error=/dev/null

set -euo pipefail
umask 077

ATTEMPT_ID="${EUF_VIPER_ATTEMPT_ID:?set EUF_VIPER_ATTEMPT_ID}"
ATTEMPT_ROOT="${EUF_VIPER_ATTEMPT_ROOT:?set EUF_VIPER_ATTEMPT_ROOT}"
CHECKOUT="${EUF_VIPER_CHECKOUT:?set EUF_VIPER_CHECKOUT}"
EXPECTED_REVISION="${EUF_VIPER_EXPECTED_REVISION:?set EUF_VIPER_EXPECTED_REVISION}"
PYTHON_BIN="${EUF_VIPER_PYTHON:?set EUF_VIPER_PYTHON}"
PYTHON_SHA256="${EUF_VIPER_PYTHON_SHA256:?set EUF_VIPER_PYTHON_SHA256}"
SHA256SUM_BIN="${EUF_VIPER_SHA256SUM:?set EUF_VIPER_SHA256SUM}"
PROVENANCE_HELPER_SHA256="${EUF_VIPER_PROVENANCE_HELPER_SHA256:?set EUF_VIPER_PROVENANCE_HELPER_SHA256}"
SUBMISSION_MANIFEST="${EUF_VIPER_SUBMISSION_MANIFEST:?set EUF_VIPER_SUBMISSION_MANIFEST}"
SUBMISSION_MANIFEST_SHA256="${EUF_VIPER_SUBMISSION_MANIFEST_SHA256:?set EUF_VIPER_SUBMISSION_MANIFEST_SHA256}"
SHARDS="${EUF_VIPER_LOCKED_SHARDS:?set EUF_VIPER_LOCKED_SHARDS}"
SHARED_CORPUS="${EUF_VIPER_SHARED_CORPUS:?set EUF_VIPER_SHARED_CORPUS}"
PROVENANCE_HELPER="$CHECKOUT/scripts/wmi/hermetic_provenance.py"
SEALED_BUILD_HELPER="$CHECKOUT/scripts/wmi/sealed_linux_build.py"
EXECUTION_CLOSURE_HELPER="$CHECKOUT/scripts/wmi/execution_closure.py"
BUILD_ATTESTOR="$CHECKOUT/scripts/wmi/attest_sealed_build.py"

hash_file() {
  local OUTPUT
  OUTPUT="$("$SHA256SUM_BIN" "$1")"
  printf '%s' "${OUTPUT%% *}"
}

BOUND_PYTHON_CODE='import fcntl, hashlib, os, stat, sys
path, expected, python_expected, *arguments = sys.argv[1:]
python_descriptor = os.dup(9)
try:
    python_before = os.fstat(python_descriptor)
    python_chunks = []
    while True:
        block = os.read(python_descriptor, 1024 * 1024)
        if not block:
            break
        python_chunks.append(block)
    python_after = os.fstat(python_descriptor)
finally:
    os.close(python_descriptor)
python_identity = lambda item: (item.st_dev, item.st_ino, item.st_mode, item.st_size, item.st_mtime_ns, item.st_ctime_ns)
if python_identity(python_before) != python_identity(python_after) or hashlib.sha256(b"".join(python_chunks)).hexdigest() != python_expected:
    raise SystemExit("bound Python executable descriptor mismatch")
descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
try:
    before = os.fstat(descriptor)
    chunks = []
    while True:
        block = os.read(descriptor, 1024 * 1024)
        if not block:
            break
        chunks.append(block)
    after = os.fstat(descriptor)
finally:
    os.close(descriptor)
raw = b"".join(chunks)
identity = lambda item: (item.st_dev, item.st_ino, item.st_mode, item.st_size, item.st_mtime_ns, item.st_ctime_ns)
if not stat.S_ISREG(after.st_mode) or identity(before) != identity(after) or len(raw) != after.st_size:
    raise SystemExit("bound Python helper changed while read")
if hashlib.sha256(raw).hexdigest() != expected:
    raise SystemExit("bound Python helper SHA-256 mismatch")
sealed = os.memfd_create("euf-viper-bound-helper", os.MFD_ALLOW_SEALING)
offset = 0
while offset < len(raw):
    written = os.write(sealed, raw[offset:])
    if written <= 0:
        raise SystemExit("short bound Python helper write")
    offset += written
os.fchmod(sealed, 0o400)
fcntl.fcntl(sealed, fcntl.F_ADD_SEALS, fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE)
os.lseek(sealed, 0, os.SEEK_SET)
sealed_chunks = []
while True:
    block = os.read(sealed, 1024 * 1024)
    if not block:
        break
    sealed_chunks.append(block)
if hashlib.sha256(b"".join(sealed_chunks)).hexdigest() != expected:
    raise SystemExit("sealed Python helper SHA-256 mismatch")
helper = f"/proc/self/fd/{sealed}"
sys.argv = [helper, *arguments]
scope = {"__name__": "__main__", "__file__": helper, "__package__": None, "__cached__": None}
exec(compile(raw, helper, "exec"), scope, scope)'

python_bound_bootstrap() {
  local SCRIPT="$1" EXPECTED="$2"
  shift 2
  (
    exec 9<"$PYTHON_BIN"
    if [ "$(hash_file /proc/self/fd/9)" != "$PYTHON_SHA256" ]; then
      echo "bound Python descriptor SHA-256 mismatch" >&2
      exit 2
    fi
    /proc/self/fd/9 -B -I -S -c "$BOUND_PYTHON_CODE" \
      "$SCRIPT" "$EXPECTED" "$PYTHON_SHA256" "$@"
  )
}

if [ "$(hash_file "$PYTHON_BIN")" != "$PYTHON_SHA256" ]; then
  echo "receipt-bound Python SHA-256 mismatch" >&2
  exit 2
fi
if [ "$(hash_file "$PROVENANCE_HELPER")" != "$PROVENANCE_HELPER_SHA256" ]; then
  echo "receipt-bound provenance helper SHA-256 mismatch" >&2
  exit 2
fi
if [ "$(hash_file "$SUBMISSION_MANIFEST")" != "$SUBMISSION_MANIFEST_SHA256" ]; then
  echo "receipt-bound submission manifest SHA-256 mismatch" >&2
  exit 2
fi

VERIFIED_PROVENANCE="$(python_bound_bootstrap "$PROVENANCE_HELPER" \
  "$PROVENANCE_HELPER_SHA256" verify \
  --manifest "$SUBMISSION_MANIFEST" \
  --expected-sha256 "$SUBMISSION_MANIFEST_SHA256" \
  --stage prepare)"

EXECUTION_FIELDS="$("$PYTHON_BIN" -B -I -S -c '
import json, sys
value = json.loads(sys.argv[1])
environment = value["execution_environment"]
tools = value["runtime_tools"]
fields = [
    environment["HOME"], environment["PATH"], environment["RUSTUP_HOME"],
    environment["CARGO_HOME"], environment["CARGO_TARGET_DIR"], environment["TMPDIR"],
    environment["XDG_CACHE_HOME"], environment["XDG_CONFIG_HOME"],
    tools["bash"]["realpath"], tools["cargo"]["realpath"], tools["git"]["realpath"],
    tools["chmod"]["realpath"], tools["env"]["realpath"], tools["mkdir"]["realpath"],
    tools["ldd"]["realpath"], tools["unshare"]["realpath"],
    tools["cc"]["realpath"], tools["cxx"]["realpath"], tools["ar"]["realpath"],
    tools["ranlib"]["realpath"], tools["rustc"]["realpath"], tools["find"]["realpath"],
    tools["strace"]["realpath"],
    value["sealed_build_helper_sha256"], value["execution_closure_helper_sha256"],
    value["attestor_helper_sha256"],
]
if any("\t" in item or "\n" in item for item in fields):
    raise SystemExit("unsafe execution-environment field")
print("\t".join(fields))
' "$VERIFIED_PROVENANCE")"
IFS=$'\t' read -r PRIVATE_HOME RUNTIME_PATH RUSTUP_HOME CARGO_HOME CARGO_TARGET_DIR \
  PRIVATE_TMP XDG_CACHE_HOME XDG_CONFIG_HOME BASH_BIN CARGO_BIN GIT_BIN \
  CHMOD_BIN ENV_BIN MKDIR_BIN LDD_BIN UNSHARE_BIN CC_BIN CXX_BIN AR_BIN \
  RANLIB_BIN RUSTC_BIN FIND_BIN STRACE_BIN SEALED_BUILD_HELPER_SHA256 \
  EXECUTION_CLOSURE_HELPER_SHA256 BUILD_ATTESTOR_SHA256 \
  <<<"$EXECUTION_FIELDS"

if [ "$(hash_file "$SEALED_BUILD_HELPER")" != "$SEALED_BUILD_HELPER_SHA256" ] || \
   [ "$(hash_file "$EXECUTION_CLOSURE_HELPER")" != "$EXECUTION_CLOSURE_HELPER_SHA256" ] || \
   [ "$(hash_file "$BUILD_ATTESTOR")" != "$BUILD_ATTESTOR_SHA256" ]; then
  echo "receipt-bound build helper SHA-256 mismatch" >&2
  exit 2
fi

"$MKDIR_BIN" -p "$PRIVATE_HOME" "$PRIVATE_TMP" "$XDG_CACHE_HOME" "$XDG_CONFIG_HOME" \
  "$CARGO_HOME" "$CARGO_TARGET_DIR" "$ATTEMPT_ROOT/results" "$ATTEMPT_ROOT/solvers" \
  "$ATTEMPT_ROOT/corpus"
"$CHMOD_BIN" 0700 "$PRIVATE_HOME" "$PRIVATE_TMP" "$XDG_CACHE_HOME" "$XDG_CONFIG_HOME" \
  "$ATTEMPT_ROOT/results" "$ATTEMPT_ROOT/solvers" "$ATTEMPT_ROOT/corpus"

clean_env() {
  "$ENV_BIN" -i \
    HOME="$PRIVATE_HOME" \
    LANG=C \
    LC_ALL=C \
    PATH="$RUNTIME_PATH" \
    CARGO_HOME="$CARGO_HOME" \
    RUSTUP_HOME="$RUSTUP_HOME" \
    CARGO_TARGET_DIR="$CARGO_TARGET_DIR" \
    TMPDIR="$PRIVATE_TMP" \
    TZ=UTC \
    XDG_CACHE_HOME="$XDG_CACHE_HOME" \
    XDG_CONFIG_HOME="$XDG_CONFIG_HOME" \
    "$@"
}
python_clean() {
  clean_env "$PYTHON_BIN" -B -I -S "$@"
}
python_bound() {
  local SCRIPT="$1" EXPECTED="$2"
  shift 2
  (
    exec 9<"$PYTHON_BIN"
    if [ "$(hash_file /proc/self/fd/9)" != "$PYTHON_SHA256" ]; then
      echo "bound Python descriptor SHA-256 mismatch" >&2
      exit 2
    fi
    clean_env /proc/self/fd/9 -B -I -S -c "$BOUND_PYTHON_CODE" \
      "$SCRIPT" "$EXPECTED" "$PYTHON_SHA256" "$@"
  )
}

cd "$CHECKOUT"
RUN_ROOT="$ATTEMPT_ROOT/results/p0-${SLURM_JOB_ID}"
OFFICIAL_CACHE="$RUN_ROOT/source/results-sq-2025.json.gz"
"$MKDIR_BIN" -p "$RUN_ROOT/source" "$RUN_ROOT/taxonomy" "$RUN_ROOT/locks"

python_clean scripts/bench/validate_campaign_spec.py \
  campaigns/best-overall-qf-uf-2026-07.json \
  --out "$RUN_ROOT/validated-campaign.json"

SEALED_ARTIFACT_DIR="$ATTEMPT_ROOT/build/sealed-release"
"$MKDIR_BIN" -p "$ATTEMPT_ROOT/build" "$ATTEMPT_ROOT/build/sealed-staging"
python_bound "$SEALED_BUILD_HELPER" "$SEALED_BUILD_HELPER_SHA256" build \
  --repository "$CHECKOUT" \
  --revision "$EXPECTED_REVISION" \
  --artifact-dir "$SEALED_ARTIFACT_DIR" \
  --staging-root "$ATTEMPT_ROOT/build/sealed-staging" \
  --cargo-home "$CARGO_HOME" \
  --rustup-home "$RUSTUP_HOME" \
  --home "$PRIVATE_HOME" \
  --git "$GIT_BIN" \
  --cargo "$CARGO_BIN" \
  --rustc "$RUSTC_BIN" \
  --unshare "$UNSHARE_BIN" \
  --ldd "$LDD_BIN" \
  --cc "$CC_BIN" \
  --cxx "$CXX_BIN" \
  --ar "$AR_BIN" \
  --ranlib "$RANLIB_BIN" \
  --strace "$STRACE_BIN" \
  --attestor "$BUILD_ATTESTOR" \
  --attestor-sha256 "$BUILD_ATTESTOR_SHA256" \
  >"$RUN_ROOT/sealed-build-summary.json"
python_bound "$BUILD_ATTESTOR" "$BUILD_ATTESTOR_SHA256" verify \
  --artifact-dir "$SEALED_ARTIFACT_DIR" \
  >"$RUN_ROOT/sealed-build-attestation-verification.json"
VIPER_BINARY="$SEALED_ARTIFACT_DIR/euf-viper"
VIPER_FEATURE_REPORT="$SEALED_ARTIFACT_DIR/euf-viper-build-features"
SEALED_BUILD_MANIFEST="$SEALED_ARTIFACT_DIR/sealed-build-manifest.json"
SEALED_BUILD_ATTESTATION="$SEALED_ARTIFACT_DIR/sealed-build-attestation.json"
SEALED_BUILD_RECEIPT="$SEALED_ARTIFACT_DIR/sealed-build-receipt.json"
if [ ! -x "$VIPER_FEATURE_REPORT" ]; then
  echo "locked build omitted the production-evidence feature report" >&2
  exit 2
fi
VIPER_BUILD_FEATURES="$(clean_env "$VIPER_FEATURE_REPORT")"
EXPECTED_BUILD_FEATURES="certificates,default,finite-symmetry,production-evidence"
if [ "$VIPER_BUILD_FEATURES" != "$EXPECTED_BUILD_FEATURES" ]; then
  echo "locked binary feature report differs: expected $EXPECTED_BUILD_FEATURES, got $VIPER_BUILD_FEATURES" >&2
  exit 2
fi

SOLVER_ROOT="$ATTEMPT_ROOT/solvers"
clean_env "$BASH_BIN" scripts/bench/install_solvers.sh "$SOLVER_ROOT" \
  >"$RUN_ROOT/install-solvers.log" 2>&1

CORPUS_ROOT="$SHARED_CORPUS"
if [ ! -s "$CORPUS_ROOT/qf_uf_manifest.jsonl" ]; then
  CORPUS_ROOT="$ATTEMPT_ROOT/corpus/smtlib-2025"
  clean_env "$BASH_BIN" scripts/bench/fetch_smtlib_qf_uf.sh "$CORPUS_ROOT" \
    >"$RUN_ROOT/fetch-corpus.log" 2>&1
else
  printf 'shared_corpus=%s\n' "$("$PYTHON_BIN" -B -I -S -c \
    'from pathlib import Path; import sys; print(Path(sys.argv[1]).resolve(strict=True))' \
    "$CORPUS_ROOT")" >"$RUN_ROOT/fetch-corpus.log"
fi

FULL_MANIFEST="$CORPUS_ROOT/qf_uf_manifest.jsonl"
OFFICIAL_MANIFEST="$CHECKOUT/benchmarks/smtcomp-2025/qf_uf_manifest.jsonl"
RECONSTRUCTED_OFFICIAL="$RUN_ROOT/reconstructed-official.jsonl"
python_clean scripts/bench/ingest_smtcomp_2025_qf_uf.py \
  --full-manifest "$FULL_MANIFEST" \
  --official-results "$OFFICIAL_CACHE" \
  --download \
  --out "$RECONSTRUCTED_OFFICIAL" \
  --metadata "$RUN_ROOT/reconstructed-official-metadata.json"
clean_env "$("$PYTHON_BIN" -B -I -S -c \
  'import json,sys; print(json.loads(sys.argv[1])["runtime_tools"]["cmp"]["realpath"])' \
  "$VERIFIED_PROVENANCE")" "$OFFICIAL_MANIFEST" "$RECONSTRUCTED_OFFICIAL"

python_clean scripts/bench/build_family_manifest.py "$FULL_MANIFEST" \
  --taxonomy-out "$RUN_ROOT/taxonomy/full.jsonl" \
  --split-out "$RUN_ROOT/taxonomy/full-split.json"
python_clean scripts/bench/build_family_manifest.py "$OFFICIAL_MANIFEST" \
  --taxonomy-out "$RUN_ROOT/taxonomy/official.jsonl" \
  --split-out "$RUN_ROOT/taxonomy/official-split.json"

VIPER_VERSION="0.1.0+$EXPECTED_REVISION.certificates-production-evidence"
python_clean scripts/bench/record_solver_config.py \
  --campaign campaigns/best-overall-qf-uf-2026-07.json \
  --viper "$VIPER_BINARY" \
  --viper-feature-report "$VIPER_FEATURE_REPORT" \
  --viper-sealed-build-receipt "$SEALED_BUILD_RECEIPT" \
  --viper-version "$VIPER_VERSION" \
  --z3 "$SOLVER_ROOT/bin/z3" \
  --cvc5 "$SOLVER_ROOT/bin/cvc5" \
  --yices2 "$SOLVER_ROOT/bin/yices-smt2" \
  --opensmt "$SOLVER_ROOT/bin/opensmt" \
  --smoke-instance generated/synthetic/chain1000_sat.smt2 \
  --smoke-expected sat \
  --out "$RUN_ROOT/solver-config.json" \
  >"$RUN_ROOT/solver-config-summary.json"

Z3_LIBZ3="$($FIND_BIN "$SOLVER_ROOT" -type f \( -name 'libz3.so' -o -name 'libz3.so.*' \) -print -quit)"
if [ -z "$Z3_LIBZ3" ]; then
  echo "Z3 execution closure does not contain libz3" >&2
  exit 2
fi
EXECUTION_CLOSURE_MANIFEST="$RUN_ROOT/execution-closure.json"
python_bound "$EXECUTION_CLOSURE_HELPER" "$EXECUTION_CLOSURE_HELPER_SHA256" create \
  --ldd "$LDD_BIN" \
  --python-executable-name python \
  --executable "euf-viper=$VIPER_BINARY" \
  --executable "feature-report=$VIPER_FEATURE_REPORT" \
  --executable "python=$PYTHON_BIN" \
  --executable "git=$GIT_BIN" \
  --executable "unshare=$UNSHARE_BIN" \
  --executable "z3=$SOLVER_ROOT/bin/z3" \
  --executable "cvc5=$SOLVER_ROOT/bin/cvc5" \
  --executable "yices2=$SOLVER_ROOT/bin/yices-smt2" \
  --executable "opensmt=$SOLVER_ROOT/bin/opensmt" \
  --artifact "checker=$CHECKOUT/scripts/cert/check_production_evidence.py" \
  --artifact "independent-parser=$CHECKOUT/scripts/cert/independent_qfuf.py" \
  --artifact "libz3=$Z3_LIBZ3" \
  --artifact "sealed-build=$SEALED_BUILD_MANIFEST" \
  --artifact "sealed-build-attestation=$SEALED_BUILD_ATTESTATION" \
  --artifact "sealed-build-receipt=$SEALED_BUILD_RECEIPT" \
  --artifact "ld-cache=/etc/ld.so.cache" \
  --python-script "provenance-helper=$PROVENANCE_HELPER" \
  --python-script "execution-closure-helper=$EXECUTION_CLOSURE_HELPER" \
  --python-script "bind-campaign-cpu=$CHECKOUT/scripts/bench/bind_campaign_cpu.py" \
  --python-script "run-locked-campaign=$CHECKOUT/scripts/bench/run_locked_campaign.py" \
  --python-script "analyze-campaign=$CHECKOUT/scripts/bench/analyze_campaign.py" \
  --python-script "finalize-locked-audit=$CHECKOUT/scripts/wmi/finalize_locked_audit.py" \
  --python-script "production-checker=$CHECKOUT/scripts/cert/check_production_evidence.py" \
  --python-script "independent-parser=$CHECKOUT/scripts/cert/independent_qfuf.py" \
  --out "$EXECUTION_CLOSURE_MANIFEST" \
  >"$RUN_ROOT/execution-closure-summary.json"

CORPUS_INSTANCES="$CORPUS_ROOT/QF_UF"
python_clean scripts/bench/freeze_campaign.py \
  campaigns/best-overall-qf-uf-2026-07.json \
  --manifest "$FULL_MANIFEST" \
  --taxonomy "$RUN_ROOT/taxonomy/full.jsonl" \
  --solver-config "$RUN_ROOT/solver-config.json" \
  --repository "$CHECKOUT" \
  --corpus-root "$CORPUS_INSTANCES" \
  --cpu-id 0 \
  --memory-bytes 8589934592 \
  --order balanced_latin_square \
  --budget 2 \
  --output-directory "$RUN_ROOT/full-2s" \
  --out "$RUN_ROOT/locks/full-parent.json" \
  >"$RUN_ROOT/locks/full-parent-summary.json"

python_clean scripts/bench/freeze_campaign.py \
  campaigns/best-overall-qf-uf-2026-07.json \
  --manifest "$OFFICIAL_MANIFEST" \
  --taxonomy "$RUN_ROOT/taxonomy/official.jsonl" \
  --solver-config "$RUN_ROOT/solver-config.json" \
  --repository "$CHECKOUT" \
  --corpus-root "$CORPUS_INSTANCES" \
  --cpu-id 0 \
  --memory-bytes 8589934592 \
  --order balanced_latin_square \
  --budget 2 \
  --output-directory "$RUN_ROOT/official-2s" \
  --out "$RUN_ROOT/locks/official-parent.json" \
  >"$RUN_ROOT/locks/official-parent-summary.json"

python_clean scripts/bench/shard_campaign_lock.py \
  "$RUN_ROOT/locks/full-parent.json" \
  --count "$SHARDS" \
  --out-dir "$RUN_ROOT/locks/full" \
  >"$RUN_ROOT/locks/full-shards-summary.json"
python_clean scripts/bench/shard_campaign_lock.py \
  "$RUN_ROOT/locks/official-parent.json" \
  --count "$SHARDS" \
  --out-dir "$RUN_ROOT/locks/official" \
  >"$RUN_ROOT/locks/official-shards-summary.json"

FINAL_PROVENANCE="$(python_bound_bootstrap "$PROVENANCE_HELPER" \
  "$PROVENANCE_HELPER_SHA256" verify \
  --manifest "$SUBMISSION_MANIFEST" \
  --expected-sha256 "$SUBMISSION_MANIFEST_SHA256" \
  --stage prepare)"
if [ "$FINAL_PROVENANCE" != "$VERIFIED_PROVENANCE" ]; then
  echo "provenance changed during preparation" >&2
  exit 2
fi

python_clean - "$RUN_ROOT/prepare.json" "$VERIFIED_PROVENANCE" \
  "$RUN_ROOT" "$CORPUS_ROOT" "$FULL_MANIFEST" "$OFFICIAL_MANIFEST" \
  "$VIPER_BINARY" "$VIPER_BUILD_FEATURES" "$VIPER_FEATURE_REPORT" "$SLURM_JOB_ID" \
  "${SLURM_SUBMIT_DIR:-}" "$SHARDS" "$SEALED_BUILD_MANIFEST" \
  "$SEALED_BUILD_ATTESTATION" "$SEALED_BUILD_RECEIPT" \
  "$EXECUTION_CLOSURE_MANIFEST" <<'PY_PREPARE_RECEIPT'
import hashlib
import json
import os
import platform
import stat
import sys
from pathlib import Path

(
    raw_out, raw_provenance, raw_root, raw_corpus, raw_full_manifest,
    raw_official_manifest, raw_viper, build_features, raw_feature_report, job_id,
    submit_directory, shards, raw_sealed_build, raw_sealed_attestation,
    raw_sealed_receipt, raw_execution_closure,
) = sys.argv[1:]
out = Path(raw_out)
root = Path(raw_root).resolve(strict=True)
provenance = json.loads(raw_provenance)

def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def executable(path):
    value = Path(path)
    resolved = value.resolve(strict=True)
    metadata = resolved.stat()
    if not stat.S_ISREG(metadata.st_mode) or not os.access(resolved, os.X_OK):
        raise SystemExit(f"runtime is not an executable regular file: {path}")
    return {
        "path": str(value.absolute()),
        "realpath": str(resolved),
        "sha256": digest(resolved),
        "bytes": metadata.st_size,
    }

artifacts = {}
for name in (
    "solver-config.json",
    "taxonomy/full.jsonl",
    "taxonomy/full-split.json",
    "taxonomy/official.jsonl",
    "taxonomy/official-split.json",
    "locks/full-parent.json",
    "locks/official-parent.json",
):
    path = root / name
    artifacts[name] = {"path": str(path.resolve(strict=True)), "sha256": digest(path)}

solver_config = json.loads((root / "solver-config.json").read_text(encoding="utf-8"))
sealed_build_path = Path(raw_sealed_build).resolve(strict=True)
sealed_build = json.loads(sealed_build_path.read_text(encoding="utf-8"))
sealed_attestation_path = Path(raw_sealed_attestation).resolve(strict=True)
sealed_receipt_path = Path(raw_sealed_receipt).resolve(strict=True)
execution_closure_path = Path(raw_execution_closure).resolve(strict=True)
payload = {
    "schema": "euf-viper.locked-p0-preparation.v3",
    "status": "prepared",
    "attempt": provenance["attempt"],
    "artifacts": artifacts,
    "build_features": build_features.split(",") if build_features else [],
    "corpus": {
        "full_manifest": {
            "path": str(Path(raw_full_manifest).resolve(strict=True)),
            "sha256": digest(raw_full_manifest),
        },
        "official_manifest": {
            "path": str(Path(raw_official_manifest).resolve(strict=True)),
            "sha256": digest(raw_official_manifest),
        },
        "root": str(Path(raw_corpus).resolve(strict=True)),
    },
    "environment": provenance["environment"],
    "execution_environment": provenance["execution_environment"],
    "feature_report": executable(raw_feature_report),
    "hostname": platform.node(),
    "job": {
        "id": int(job_id),
        "submit_directory": submit_directory or None,
    },
    "paths": {
        "checkout": provenance["attempt"]["checkout"],
        "run_root": str(root),
        "submission_manifest": provenance["manifest"],
    },
    "revision": provenance["revision"],
    "runtime_tools": provenance["runtime_tools"],
    "sealed_build": {
        "path": str(sealed_build_path),
        "sha256": digest(sealed_build_path),
        "source_snapshot_manifest_sha256": sealed_build["source_snapshot_manifest_sha256"],
        "build_execution_closure_sha256": sealed_build["build_execution_closure_sha256"],
        "attestation_path": str(sealed_attestation_path),
        "attestation_sha256": digest(sealed_attestation_path),
        "receipt_path": str(sealed_receipt_path),
        "receipt_sha256": digest(sealed_receipt_path),
    },
    "execution_closure": {
        "path": str(execution_closure_path),
        "sha256": digest(execution_closure_path),
    },
    "shards": int(shards),
    "solver_executables": {
        record["id"]: executable(record["binary"])
        for record in solver_config["solvers"]
    },
    "source": {
        "blob_count": provenance["source_blob_count"],
        "blobs_sha256": provenance["source_blobs_sha256"],
        "tree": provenance["source_tree"],
        "snapshot_manifest_sha256": sealed_build["source_snapshot_manifest_sha256"],
        "build_execution_closure_sha256": sealed_build["build_execution_closure_sha256"],
    },
    "submission_manifest_sha256": provenance["manifest_sha256"],
    "viper": executable(raw_viper),
}
encoded = (
    json.dumps(
        payload,
        allow_nan=False,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    + "\n"
).encode("utf-8")
descriptor = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
try:
    with os.fdopen(descriptor, "wb", closefd=False) as handle:
        handle.write(encoded)
        handle.flush()
        os.fsync(handle.fileno())
finally:
    os.close(descriptor)
directory = os.open(out.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
try:
    os.fsync(directory)
finally:
    os.close(directory)
PY_PREPARE_RECEIPT

printf 'attempt_id=%s\n' "$ATTEMPT_ID"
printf 'run_root=%s\n' "$RUN_ROOT"
printf 'revision=%s\n' "$EXPECTED_REVISION"
printf 'shards=%s\n' "$SHARDS"
