#!/usr/bin/env python3
"""Validate and use the externally provisioned T6 WMI Rust toolchain."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
CONTRACT_PATH = ROOT / "campaigns" / "t6-wmi-rust-toolchain-1.96.0-v1.json"
EXPECTED_CONTRACT_SHA256 = (
    "db825fa64cf03e20d07842d063638ecdf7193a1eba4966be5d9e5f7e5c108baa"
)
SCHEMA = "euf-viper.t6-wmi-rust-toolchain.v1"
TOOLCHAIN = "1.96.0"
TOOL_NAMES = ("ar", "cargo", "cc", "cxx", "ranlib", "rust_linker", "rustc")
TOOL_FIELDS = frozenset({"path", "sha256", "version"})
TOP_FIELDS = frozenset(
    {
        "binaries",
        "build_environment_allowlist",
        "cargo_config_policy",
        "cargo_home_policy",
        "eligibility",
        "independent_verification",
        "ineligibility_reason",
        "provision_root",
        "provisioning_mode",
        "required_absent_environment",
        "schema",
        "target",
        "target_dir_policy",
        "toolchain",
        "workspace_cargo_config_policy",
    }
)
INDEPENDENT_FIELDS = frozenset({"evidence_sha256", "reviewer", "status"})
BUILD_ENVIRONMENT_ALLOWLIST = (
    "AR",
    "CARGO_BUILD_JOBS",
    "CARGO_HOME",
    "CARGO_INCREMENTAL",
    "CARGO_TARGET_DIR",
    "CC",
    "CXX",
    "EUF_VIPER_EXPECTED_REVISION",
    "EUF_VIPER_T6_CORPUS_ROOT",
    "EUF_VIPER_T6_MANIFEST",
    "EUF_VIPER_T6_OUTPUT",
    "HOME",
    "LANG",
    "LC_ALL",
    "OMP_NUM_THREADS",
    "OPENBLAS_NUM_THREADS",
    "PATH",
    "RANLIB",
    "RAYON_NUM_THREADS",
    "RUSTC",
    "RUST_MIN_STACK",
    "TMPDIR",
    "TZ",
)
REQUIRED_ABSENT_ENVIRONMENT = (
    "CARGO_ENCODED_RUSTFLAGS",
    "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER",
    "LD_LIBRARY_PATH",
    "RUSTC_WRAPPER",
    "RUSTC_WORKSPACE_WRAPPER",
    "RUSTDOCFLAGS",
    "RUSTFLAGS",
    "RUSTUP_HOME",
    "RUSTUP_TOOLCHAIN",
)
SHA256_RE = re.compile(r"[0-9a-f]{64}")
SAFE_PATH_RE = re.compile(r"/[A-Za-z0-9_./+:-]+")


class ToolchainError(ValueError):
    """Raised when the WMI toolchain contract is incomplete or drifts."""


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ToolchainError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def reject_nonfinite(value: str) -> None:
    raise ToolchainError(f"non-finite JSON number {value!r}")


def strict_json_bytes(data: bytes, context: str) -> Any:
    try:
        return json.loads(
            data.decode("utf-8"),
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=reject_nonfinite,
        )
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ToolchainError(f"invalid strict JSON in {context}: {error}") from error


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def require_sha256(value: Any, context: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise ToolchainError(f"{context} is not a lowercase SHA-256")
    return value


def validate_contract(contract: Any) -> dict[str, Any]:
    if not isinstance(contract, dict) or frozenset(contract) != TOP_FIELDS:
        raise ToolchainError("T6 WMI toolchain top-level field drift")
    if (
        contract["schema"] != SCHEMA
        or contract["toolchain"] != TOOLCHAIN
        or contract["provisioning_mode"] != "external_only_no_rustup_mutation"
        or contract["cargo_config_policy"] != "attempt_private_generated_exact"
        or contract["cargo_home_policy"] != "attempt_private_empty"
        or contract["target_dir_policy"] != "attempt_private"
        or contract["workspace_cargo_config_policy"] != "forbidden"
    ):
        raise ToolchainError("T6 WMI toolchain policy drift")
    if contract["build_environment_allowlist"] != list(BUILD_ENVIRONMENT_ALLOWLIST):
        raise ToolchainError("T6 build environment allowlist drift")
    if contract["required_absent_environment"] != list(REQUIRED_ABSENT_ENVIRONMENT):
        raise ToolchainError("T6 required-absent environment drift")

    binaries = contract["binaries"]
    if not isinstance(binaries, dict) or tuple(sorted(binaries)) != tuple(sorted(TOOL_NAMES)):
        raise ToolchainError("T6 WMI binary inventory drift")
    verification = contract["independent_verification"]
    if not isinstance(verification, dict) or frozenset(verification) != INDEPENDENT_FIELDS:
        raise ToolchainError("T6 independent-verification field drift")

    eligibility = contract["eligibility"]
    if eligibility == "ineligible":
        if (
            not isinstance(contract["ineligibility_reason"], str)
            or not contract["ineligibility_reason"]
            or contract["provision_root"] is not None
            or contract["target"] is not None
            or any(value is not None for value in binaries.values())
            or verification
            != {"evidence_sha256": None, "reviewer": None, "status": "pending"}
        ):
            raise ToolchainError("ineligible T6 WMI toolchain is not fail-closed")
        return contract
    if eligibility != "eligible":
        raise ToolchainError("unknown T6 WMI toolchain eligibility")
    if contract["ineligibility_reason"] is not None:
        raise ToolchainError("eligible T6 WMI toolchain retains an ineligibility reason")
    if verification.get("status") != "independently_verified":
        raise ToolchainError("T6 WMI toolchain lacks independent verification")
    require_sha256(verification.get("evidence_sha256"), "verification evidence SHA-256")
    if not isinstance(verification.get("reviewer"), str) or not verification["reviewer"].strip():
        raise ToolchainError("T6 WMI toolchain reviewer is missing")
    require_absolute_path(contract["provision_root"], "provision root")
    target = contract["target"]
    if not isinstance(target, str) or not re.fullmatch(r"[A-Za-z0-9_.-]+", target):
        raise ToolchainError("T6 WMI target triple is malformed")
    for name in TOOL_NAMES:
        record = binaries[name]
        if not isinstance(record, dict) or frozenset(record) != TOOL_FIELDS:
            raise ToolchainError(f"{name} binary contract is incomplete")
        require_absolute_path(record["path"], f"{name} path")
        require_sha256(record["sha256"], f"{name} SHA-256")
        if not isinstance(record["version"], str) or not record["version"]:
            raise ToolchainError(f"{name} version record is missing")
    provision_root = Path(contract["provision_root"])
    for name in ("cargo", "rustc"):
        try:
            Path(binaries[name]["path"]).relative_to(provision_root)
        except ValueError as error:
            raise ToolchainError(f"{name} is outside the external provision root") from error
    return contract


def load_pinned_contract() -> tuple[dict[str, Any], bytes]:
    data = CONTRACT_PATH.read_bytes()
    observed = sha256_bytes(data)
    if observed != EXPECTED_CONTRACT_SHA256:
        raise ToolchainError(
            "T6 WMI toolchain artifact hash mismatch: "
            f"expected {EXPECTED_CONTRACT_SHA256}, observed {observed}"
        )
    return validate_contract(strict_json_bytes(data, str(CONTRACT_PATH))), data


def require_eligible(contract: dict[str, Any]) -> None:
    if contract["eligibility"] != "eligible":
        raise ToolchainError(
            "T6 WMI remains ineligible: external Rust 1.96.0 provisioning and "
            "independent verification are incomplete"
        )


def require_absolute_path(value: Any, context: str) -> Path:
    if not isinstance(value, str) or SAFE_PATH_RE.fullmatch(value) is None:
        raise ToolchainError(f"{context} must be a canonical safe absolute path")
    path = Path(value)
    if not path.is_absolute() or os.path.normpath(value) != value:
        raise ToolchainError(f"{context} must be a canonical safe absolute path")
    return path


def stable_file_hash(path: Path, context: str) -> tuple[str, tuple[int, int]]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ToolchainError(f"cannot open {context} {path}: {error}") from error
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size <= 0:
            raise ToolchainError(f"{context} is not a nonempty regular file: {path}")
        digest = hashlib.sha256()
        while chunk := os.read(descriptor, 1024 * 1024):
            digest.update(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    before_state = (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    )
    after_state = (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    )
    if before_state != after_state:
        raise ToolchainError(f"{context} changed while hashing: {path}")
    return digest.hexdigest(), (after.st_dev, after.st_ino)


def version_arguments(name: str) -> list[str]:
    if name == "cargo":
        return ["-V"]
    if name == "rustc":
        return ["-vV"]
    return ["--version"]


def inspect_binary(name: str, record: dict[str, str]) -> dict[str, Any]:
    path = require_absolute_path(record["path"], f"{name} path")
    try:
        symbolic = path.is_symlink()
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise ToolchainError(f"cannot resolve {name} binary {path}: {error}") from error
    if symbolic or resolved != path:
        raise ToolchainError(f"{name} must name the direct binary, not a symlink or proxy path")
    if not os.access(path, os.X_OK):
        raise ToolchainError(f"{name} is not executable: {path}")
    before_hash, before_identity = stable_file_hash(path, f"{name} binary")
    if before_hash != record["sha256"]:
        raise ToolchainError(
            f"{name} SHA-256 mismatch: expected {record['sha256']}, observed {before_hash}"
        )
    clean_env = {"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"}
    completed = subprocess.run(
        [str(path), *version_arguments(name)],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env=clean_env,
        text=True,
    )
    observed_version = completed.stdout.rstrip("\n")
    if completed.returncode != 0 or observed_version != record["version"]:
        raise ToolchainError(
            f"{name} version mismatch: expected {record['version']!r}, "
            f"observed {observed_version!r} with exit {completed.returncode}"
        )
    after_hash, after_identity = stable_file_hash(path, f"{name} binary")
    if (after_hash, after_identity) != (before_hash, before_identity):
        raise ToolchainError(f"{name} changed while it was inspected")
    return {
        "path": str(path),
        "sha256": before_hash,
        "version": observed_version,
        "device": before_identity[0],
        "inode": before_identity[1],
    }


def cargo_config_candidates(repo_root: Path) -> list[Path]:
    candidates: list[Path] = []
    for directory in (repo_root, *repo_root.parents):
        candidates.extend((directory / ".cargo" / "config", directory / ".cargo" / "config.toml"))
    return candidates


def inspect_host(contract: dict[str, Any], repo_root: Path) -> dict[str, Any]:
    require_eligible(contract)
    repo_root = repo_root.resolve(strict=True)
    if not repo_root.is_dir():
        raise ToolchainError(f"repository root is not a directory: {repo_root}")
    present_configs = [str(path) for path in cargo_config_candidates(repo_root) if path.exists()]
    if present_configs:
        raise ToolchainError(
            "workspace or ancestor Cargo configuration is forbidden: " + ", ".join(present_configs)
        )
    inspected = {
        name: inspect_binary(name, contract["binaries"][name]) for name in TOOL_NAMES
    }
    cargo_identity = (inspected["cargo"]["device"], inspected["cargo"]["inode"])
    rustc_identity = (inspected["rustc"]["device"], inspected["rustc"]["inode"])
    if cargo_identity == rustc_identity or inspected["cargo"]["sha256"] == inspected["rustc"]["sha256"]:
        raise ToolchainError("cargo and rustc resolve to the same rustup-style proxy binary")
    if not inspected["cargo"]["version"].startswith("cargo 1.96.0 ("):
        raise ToolchainError("direct cargo is not exact version 1.96.0")
    if not inspected["rustc"]["version"].startswith("rustc 1.96.0 ("):
        raise ToolchainError("direct rustc is not exact version 1.96.0")
    host_lines = [
        line.removeprefix("host: ")
        for line in inspected["rustc"]["version"].splitlines()
        if line.startswith("host: ")
    ]
    if host_lines != [contract["target"]]:
        raise ToolchainError("rustc -vV host does not match the frozen target")
    return {
        "binaries": inspected,
        "cargo_config_search": {
            "candidates": [str(path) for path in cargo_config_candidates(repo_root)],
            "present": [],
        },
    }


def toml_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=True)


def create_attempt(
    contract: dict[str, Any],
    inspection: dict[str, Any],
    attempt_root: Path,
    runtime: dict[str, str],
) -> tuple[dict[str, str], dict[str, Any]]:
    if not attempt_root.is_absolute():
        raise ToolchainError("attempt root must be absolute")
    attempt_root.mkdir(mode=0o700, parents=False, exist_ok=False)
    home = attempt_root / "home"
    cargo_home = attempt_root / "cargo-home"
    target_dir = attempt_root / "target"
    temporary = attempt_root / "tmp"
    for path in (home, cargo_home, target_dir, temporary):
        path.mkdir(mode=0o700)

    binaries = inspection["binaries"]
    config_text = (
        "[build]\n"
        f"rustc = {toml_string(binaries['rustc']['path'])}\n\n"
        f"[target.{contract['target']}]\n"
        f"linker = {toml_string(binaries['rust_linker']['path'])}\n"
        f"ar = {toml_string(binaries['ar']['path'])}\n"
    )
    config_path = cargo_home / "config.toml"
    config_path.write_text(config_text, encoding="ascii", newline="\n")
    config_sha256 = sha256_bytes(config_text.encode("ascii"))

    path_entries = []
    for name in TOOL_NAMES:
        parent = str(Path(binaries[name]["path"]).parent)
        if parent not in path_entries:
            path_entries.append(parent)
    path_entries.extend(path for path in ("/usr/bin", "/bin") if path not in path_entries)
    build_environment = {
        "AR": binaries["ar"]["path"],
        "CARGO_BUILD_JOBS": "1",
        "CARGO_HOME": str(cargo_home),
        "CARGO_INCREMENTAL": "0",
        "CARGO_TARGET_DIR": str(target_dir),
        "CC": binaries["cc"]["path"],
        "CXX": binaries["cxx"]["path"],
        "EUF_VIPER_EXPECTED_REVISION": runtime["revision"],
        "EUF_VIPER_T6_CORPUS_ROOT": runtime["corpus_root"],
        "EUF_VIPER_T6_MANIFEST": runtime["manifest"],
        "EUF_VIPER_T6_OUTPUT": runtime["output"],
        "HOME": str(home),
        "LANG": "C",
        "LC_ALL": "C",
        "OMP_NUM_THREADS": "1",
        "OPENBLAS_NUM_THREADS": "1",
        "PATH": ":".join(path_entries),
        "RANLIB": binaries["ranlib"]["path"],
        "RAYON_NUM_THREADS": "1",
        "RUSTC": binaries["rustc"]["path"],
        "RUST_MIN_STACK": "134217728",
        "TMPDIR": str(temporary),
        "TZ": "UTC",
    }
    if tuple(sorted(build_environment)) != tuple(sorted(BUILD_ENVIRONMENT_ALLOWLIST)):
        raise ToolchainError("constructed Cargo environment does not match the strict allowlist")
    if any(name in build_environment for name in REQUIRED_ABSENT_ENVIRONMENT):
        raise ToolchainError("a required-absent build variable was constructed")
    record = {
        "attempt_root": str(attempt_root),
        "cargo_config": {
            "content": config_text,
            "path": str(config_path),
            "sha256": config_sha256,
        },
        "environment": build_environment,
        "required_absent_environment": list(REQUIRED_ABSENT_ENVIRONMENT),
        "wrappers": {
            "RUSTC_WRAPPER": None,
            "RUSTC_WORKSPACE_WRAPPER": None,
        },
        "linkers": {
            name: binaries[name]
            for name in ("ar", "cc", "cxx", "ranlib", "rust_linker")
        },
    }
    return build_environment, record


def atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = (
        json.dumps(payload, allow_nan=False, ensure_ascii=True, indent=2, sort_keys=True)
        + "\n"
    )
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(data, encoding="ascii", newline="\n")
    temporary.replace(path)


def attestation(
    contract: dict[str, Any], inspection: dict[str, Any], repo_root: Path
) -> dict[str, Any]:
    return {
        "schema": "euf-viper.t6-wmi-toolchain-attestation.v1",
        "state": "inspected",
        "contract_sha256": EXPECTED_CONTRACT_SHA256,
        "toolchain": TOOLCHAIN,
        "target": contract["target"],
        "independent_verification": contract["independent_verification"],
        "repository": str(repo_root.resolve()),
        **inspection,
    }


def run_census(args: argparse.Namespace, contract: dict[str, Any]) -> None:
    repo_root = args.repo_root.resolve(strict=True)
    inspection = inspect_host(contract, repo_root)
    runtime = {
        "revision": args.revision,
        "corpus_root": str(args.corpus_root),
        "manifest": str(args.manifest),
        "output": str(args.output),
    }
    environment, attempt_record = create_attempt(
        contract, inspection, args.attempt_root, runtime
    )
    cargo = inspection["binaries"]["cargo"]["path"]
    command = [
        cargo,
        "test",
        "--release",
        "--locked",
        "--all-features",
        "t6_bool_dag_census::tests::p0_qg12_census_from_env",
        "--",
        "--ignored",
        "--exact",
        "--nocapture",
    ]
    payload = attestation(contract, inspection, repo_root)
    payload.update(
        {
            "state": "running",
            "attempt": attempt_record,
            "command": command,
            "cargo_exit_code": None,
        }
    )
    atomic_write_json(args.attestation, payload)
    args.run_log.parent.mkdir(parents=True, exist_ok=True)
    with args.run_log.open("wb") as handle:
        completed = subprocess.run(
            command,
            cwd=repo_root,
            env=environment,
            stdout=handle,
            stderr=subprocess.STDOUT,
            check=False,
        )
    payload["cargo_exit_code"] = completed.returncode
    payload["state"] = "completed" if completed.returncode == 0 else "failed"
    atomic_write_json(args.attestation, payload)
    if completed.returncode != 0:
        raise ToolchainError(f"direct Cargo census test failed with exit {completed.returncode}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("contract-status")
    subparsers.add_parser("require-ready")
    inspect = subparsers.add_parser("inspect-host")
    inspect.add_argument("--repo-root", required=True, type=Path)
    inspect.add_argument("--output", required=True, type=Path)
    run = subparsers.add_parser("run-census")
    run.add_argument("--repo-root", required=True, type=Path)
    run.add_argument("--attempt-root", required=True, type=Path)
    run.add_argument("--manifest", required=True, type=Path)
    run.add_argument("--corpus-root", required=True, type=Path)
    run.add_argument("--output", required=True, type=Path)
    run.add_argument("--revision", required=True)
    run.add_argument("--run-log", required=True, type=Path)
    run.add_argument("--attestation", required=True, type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    contract, _ = load_pinned_contract()
    if args.command == "contract-status":
        print(
            json.dumps(
                {
                    "contract_sha256": EXPECTED_CONTRACT_SHA256,
                    "eligibility": contract["eligibility"],
                    "independent_verification": contract["independent_verification"]["status"],
                    "toolchain": TOOLCHAIN,
                },
                allow_nan=False,
                sort_keys=True,
            )
        )
        return 0
    if args.command == "require-ready":
        require_eligible(contract)
        return 0
    if args.command == "inspect-host":
        inspection = inspect_host(contract, args.repo_root)
        atomic_write_json(args.output, attestation(contract, inspection, args.repo_root))
        return 0
    if args.command == "run-census":
        run_census(args, contract)
        return 0
    raise AssertionError(args.command)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ToolchainError as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(2) from error
