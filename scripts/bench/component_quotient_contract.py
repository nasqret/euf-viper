#!/usr/bin/env python3
"""Fixed, reviewable constants for the T5 component-quotient census."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
from pathlib import Path
from typing import Final


ROOT: Final = Path(__file__).resolve().parents[2]
LOCK_RELATIVE_PATH: Final = "campaigns/component-quotient-ram-census-v1.json"
LOCK_SHA256: Final = (
    "7958892d3bf45abbf7d40f31b75c5cdf07a6aec13c66442278685b0ad4eddc24"
)
MANIFEST_RELATIVE_PATH: Final = "benchmarks/smtlib-2025/qf_uf_manifest.jsonl"
MANIFEST_SHA256: Final = (
    "32aba287e33c5665847f0a0a71311da6214feb5e69f458877ba02ef96976a2d4"
)
OFFICIAL_MANIFEST_RELATIVE_PATH: Final = (
    "benchmarks/smtcomp-2025/qf_uf_manifest.jsonl"
)
OFFICIAL_MANIFEST_SHA256: Final = (
    "ed00b0e2105ec9579b02448d161e7f04ceceaf816919535b48734c6525a2aaa6"
)
OFFICIAL_MANIFEST_SOURCES: Final = 3521
PORTABLE_SOURCE_SET_SHA256: Final = (
    "d8997c621fbd58034e55bef1e6636ea0f0a28bc63bb6391be39e9195c6f44653"
)
EXPECTED_SOURCES: Final = 7503
EXPECTED_FAMILY_POPULATIONS: Final = {
    "goel": 773,
    "qg": 6396,
}
SELECTOR_MINIMUM_APPLICATIONS: Final = 64
SELECTOR_MINIMUM_SYMBOL_APPLICATIONS: Final = 32
MINIMUM_FAMILY_FRACTION: Final = (1, 20)
MINIMUM_GENERATOR_LINEAGES: Final = 8
MINIMUM_REDUCTION: Final = (1, 4)
MINIMUM_INDIVIDUAL_FRACTION: Final = (1, 2)
RAM_MAXIMUM_RATIO: Final = (1, 1)
RAM_PERCENTILE: Final = 95
VARIABLE_MAXIMUM_RATIO: Final = (5, 4)
VARIABLE_PERCENTILE: Final = 95

MARKER_SCHEMA: Final = "euf-viper.component-quotient-publication-marker.v2"
SUBMISSION_SCHEMA: Final = "euf-viper.component-quotient-ram-wmi-submission.v6"
FINAL_RECEIPT_SCHEMA: Final = (
    "euf-viper.component-quotient-ram-final-consumer-receipt.v2"
)
INDEPENDENT_RECEIPT_SCHEMA: Final = (
    "euf-viper.component-quotient-independent-decision.v2"
)
BUNDLE_METADATA_SCHEMA: Final = (
    "euf-viper.component-quotient-ram-wmi-immutable-bundle.v4"
)

RUNTIME_PROJECT_FILES: Final = (
    ".github/workflows/campaign-contract.yml",
    LOCK_RELATIVE_PATH,
    OFFICIAL_MANIFEST_RELATIVE_PATH,
    "scripts/bench/build_family_manifest.py",
    "scripts/bench/census_component_quotient_ram.py",
    "scripts/bench/component_quotient_contract.py",
    "scripts/bench/finalize_component_quotient_ram_metadata.py",
    "scripts/bench/independent_component_quotient_verifier.py",
    "scripts/bench/t5_independent_smtlib.py",
    "scripts/bench/t5_linux_publication.py",
    "scripts/bench/t5_runtime_environment.py",
    "scripts/bench/verify_component_quotient_publication.py",
    "scripts/bench/verify_component_quotient_ram_bundle.py",
    "scripts/cert/independent_qfuf.py",
    "scripts/wmi/check_component_quotient_checkout.sh",
    "scripts/wmi/euf_viper_component_quotient_census.sbatch",
    "scripts/wmi/submit_component_quotient_census.sh",
)

PROHIBITED_ENVIRONMENT_NAMES: Final = frozenset(
    {
        "BASH_ENV",
        "CDPATH",
        "ENV",
        "GIT_DIR",
        "GIT_INDEX_FILE",
        "GIT_OBJECT_DIRECTORY",
        "GIT_WORK_TREE",
        "PYTHONHOME",
        "PYTHONINSPECT",
        "PYTHONPATH",
        "PYTHONSTARTUP",
        "PYTHONUSERBASE",
    }
)
PROHIBITED_ENVIRONMENT_PREFIXES: Final = (
    "BASH_FUNC_",
    "CARGO_",
    "DYLD_",
    "GIT_",
    "LD_",
    "PYTHON",
    "RUST",
)


class ContractError(ValueError):
    """Raised when bytes or controls differ from the fixed T5 contract."""


def canonical_json_bytes(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
        + "\n"
    ).encode("ascii")


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def require_exact_lock_bytes(payload: bytes) -> dict[str, object]:
    digest = sha256_bytes(payload)
    if digest != LOCK_SHA256:
        raise ContractError(
            f"T5 campaign lock SHA-256 drift: expected {LOCK_SHA256}, got {digest}"
        )
    try:
        value = json.loads(payload.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ContractError(f"T5 campaign lock is not strict ASCII JSON: {error}") from error
    if type(value) is not dict:
        raise ContractError("T5 campaign lock must be a JSON object")
    fixed_values: tuple[tuple[tuple[str, ...], object], ...] = (
        (("corpus", "expected_sources"), EXPECTED_SOURCES),
        (("corpus", "manifest"), MANIFEST_RELATIVE_PATH),
        (("corpus", "manifest_sha256"), MANIFEST_SHA256),
        (("corpus", "families", "goel", "expected_population"), 773),
        (("corpus", "families", "qg", "expected_population"), 6396),
        (("corpus", "portable_source_set_sha256"), PORTABLE_SOURCE_SET_SHA256),
        (("selector", "minimum_total_applications"), SELECTOR_MINIMUM_APPLICATIONS),
        (
            ("selector", "minimum_max_symbol_applications"),
            SELECTOR_MINIMUM_SYMBOL_APPLICATIONS,
        ),
        (("gates", "broadness", "minimum_family_fraction", "numerator"), 1),
        (("gates", "broadness", "minimum_family_fraction", "denominator"), 20),
        (("gates", "broadness", "minimum_generator_lineages"), 8),
        (("gates", "opportunity", "minimum_reduction", "numerator"), 1),
        (("gates", "opportunity", "minimum_reduction", "denominator"), 4),
        (
            ("gates", "opportunity", "minimum_individual_fraction", "numerator"),
            1,
        ),
        (
            ("gates", "opportunity", "minimum_individual_fraction", "denominator"),
            2,
        ),
        (("gates", "ram_control", "maximum_ratio", "numerator"), 1),
        (("gates", "ram_control", "maximum_ratio", "denominator"), 1),
        (("gates", "ram_control", "percentile"), 95),
        (("gates", "variable_control", "maximum_ratio", "numerator"), 5),
        (("gates", "variable_control", "maximum_ratio", "denominator"), 4),
        (("gates", "variable_control", "percentile"), 95),
    )
    for keys, expected in fixed_values:
        selected: object = value
        for key in keys:
            if type(selected) is not dict or key not in selected:
                raise ContractError(f"T5 campaign lock lacks fixed field {'.'.join(keys)}")
            selected = selected[key]
        if selected != expected or type(selected) is not type(expected):
            raise ContractError(f"T5 campaign lock fixed field drift: {'.'.join(keys)}")
    return value


def require_safe_token(value: str, context: str, *, minimum: int = 1) -> str:
    if not minimum <= len(value) <= 128 or any(
        character not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-"
        for character in value
    ):
        raise ContractError(f"{context} is malformed")
    return value


def require_lower_sha256(value: str, context: str) -> str:
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise ContractError(f"{context} must be a lowercase SHA-256")
    return value


def require_campaign_manifest_path(repository_root: Path, manifest_path: Path) -> Path:
    root = Path(os.path.abspath(repository_root))
    selected = Path(os.path.abspath(manifest_path))
    expected = root / MANIFEST_RELATIVE_PATH
    official = root / OFFICIAL_MANIFEST_RELATIVE_PATH
    if selected == official:
        raise ContractError(
            "T5 selected the tracked 3,521-row official manifest instead of the "
            "external 7,503-row campaign manifest"
        )
    if selected != expected:
        raise ContractError(
            f"T5 manifest path drift: expected {expected}, got {selected}"
        )
    return selected


def require_campaign_manifest_bytes(payload: bytes) -> tuple[dict[str, object], ...]:
    digest = sha256_bytes(payload)
    if digest == OFFICIAL_MANIFEST_SHA256:
        raise ContractError(
            "T5 manifest bytes are the tracked 3,521-row official manifest"
        )
    if digest != MANIFEST_SHA256:
        raise ContractError(
            f"T5 external manifest SHA-256 drift: expected {MANIFEST_SHA256}, got {digest}"
        )
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ContractError(f"T5 external manifest is not UTF-8: {error}") from error
    if not text.endswith("\n"):
        raise ContractError("T5 external manifest must end with one record newline")
    lines = text.splitlines()
    if len(lines) == OFFICIAL_MANIFEST_SOURCES:
        raise ContractError(
            "T5 external manifest silently became the 3,521-row official selection"
        )
    if len(lines) != EXPECTED_SOURCES:
        raise ContractError(
            f"T5 external manifest cardinality drift: expected {EXPECTED_SOURCES}, "
            f"got {len(lines)}"
        )
    rows: list[dict[str, object]] = []
    for index, line in enumerate(lines):
        if not line:
            raise ContractError(f"T5 external manifest line {index + 1} is blank")
        try:
            row = json.loads(line)
        except json.JSONDecodeError as error:
            raise ContractError(
                f"T5 external manifest line {index + 1} is malformed: {error}"
            ) from error
        if type(row) is not dict or row.get("id") != index:
            raise ContractError(
                f"T5 external manifest line {index + 1} has a noncanonical id"
            )
        rows.append(row)
    return tuple(rows)


def namespace_identity_sha256(
    *,
    namespace_path: str,
    namespace_device: int,
    namespace_inode: int,
    results_device: int,
    results_inode: int,
    submission_nonce: str,
) -> str:
    if not namespace_path.startswith("/"):
        raise ContractError("remote namespace path must be absolute")
    try:
        encoded_path = namespace_path.encode("ascii")
    except UnicodeEncodeError as error:
        raise ContractError("remote namespace path must be ASCII") from error
    identities = (
        namespace_device,
        namespace_inode,
        results_device,
        results_inode,
    )
    if any(type(value) is not int or value < 1 for value in identities):
        raise ContractError("remote namespace inode identities must be positive")
    require_lower_sha256(submission_nonce, "submission nonce")
    fields = (
        encoded_path,
        str(namespace_device).encode("ascii"),
        str(namespace_inode).encode("ascii"),
        str(results_device).encode("ascii"),
        str(results_inode).encode("ascii"),
        submission_nonce.encode("ascii"),
    )
    return sha256_bytes(b"\0".join(fields) + b"\0")


def hostile_environment_names(environment: dict[str, str]) -> tuple[str, ...]:
    return tuple(
        sorted(
            name
            for name in environment
            if name in PROHIBITED_ENVIRONMENT_NAMES
            or any(name.startswith(prefix) for prefix in PROHIBITED_ENVIRONMENT_PREFIXES)
        )
    )


def _sanitized_git_environment() -> dict[str, str]:
    return {
        "PATH": "/usr/bin:/bin",
        "HOME": "/nonexistent",
        "LANG": "C",
        "LC_ALL": "C",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_SYSTEM": "/dev/null",
        "GIT_PAGER": "cat",
    }


def _read_regular_no_follow(path: Path) -> bytes:
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        descriptor_stat = os.fstat(descriptor)
        if not stat.S_ISREG(descriptor_stat.st_mode):
            raise ContractError(f"runtime path is not a regular file: {path}")
        output = bytearray()
        while chunk := os.read(descriptor, 1024 * 1024):
            output.extend(chunk)
        if os.fstat(descriptor).st_size != len(output):
            raise ContractError(f"runtime path changed while read: {path}")
        return bytes(output)
    finally:
        os.close(descriptor)


def verify_runtime_revision_blobs(
    repository_root: Path, revision: str
) -> dict[str, dict[str, object]]:
    if len(revision) != 40 or any(character not in "0123456789abcdef" for character in revision):
        raise ContractError("runtime revision must be a full lowercase Git SHA-1")
    root = Path(os.path.abspath(repository_root))
    environment = _sanitized_git_environment()
    try:
        git_dir = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "--absolute-git-dir"],
            env=environment,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        actual_revision = subprocess.run(
            [
                "git",
                f"--git-dir={git_dir}",
                f"--work-tree={root}",
                "rev-parse",
                "HEAD",
            ],
            env=environment,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError) as error:
        raise ContractError(f"cannot establish sanitized Git identity: {error}") from error
    if actual_revision != revision:
        raise ContractError("sanitized Git HEAD differs from expected revision")
    bindings: dict[str, dict[str, object]] = {}
    for relative_path in RUNTIME_PROJECT_FILES:
        try:
            expected = subprocess.run(
                [
                    "git",
                    f"--git-dir={git_dir}",
                    f"--work-tree={root}",
                    "cat-file",
                    "blob",
                    f"{revision}:{relative_path}",
                ],
                env=environment,
                check=True,
                capture_output=True,
            ).stdout
            tree_line = subprocess.run(
                [
                    "git",
                    f"--git-dir={git_dir}",
                    f"--work-tree={root}",
                    "ls-tree",
                    revision,
                    "--",
                    relative_path,
                ],
                env=environment,
                check=True,
                capture_output=True,
                text=True,
            ).stdout.rstrip("\n")
        except (OSError, subprocess.CalledProcessError) as error:
            raise ContractError(
                f"cannot read expected revision blob {relative_path}: {error}"
            ) from error
        fields = tree_line.split(None, 3)
        if len(fields) != 4 or fields[1] != "blob" or fields[3] != relative_path:
            raise ContractError(f"runtime tree identity drift: {relative_path}")
        if fields[0] not in {"100644", "100755"}:
            raise ContractError(
                f"runtime tree mode is not a regular executable or data file: {relative_path}"
            )
        actual = _read_regular_no_follow(root / relative_path)
        if actual != expected:
            raise ContractError(f"runtime bytes differ from revision: {relative_path}")
        mode = stat.S_IMODE((root / relative_path).stat(follow_symlinks=False).st_mode)
        expected_mode = 0o755 if fields[0] == "100755" else 0o644
        if mode != expected_mode:
            raise ContractError(f"runtime mode differs from revision: {relative_path}")
        bindings[relative_path] = {
            "git_object": fields[2],
            "sha256": sha256_bytes(actual),
            "bytes": len(actual),
            "mode": fields[0],
        }
    if bindings[LOCK_RELATIVE_PATH]["sha256"] != LOCK_SHA256:
        raise ContractError("revision lock blob differs from fixed T5 contract")
    return bindings
