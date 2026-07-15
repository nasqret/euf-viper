#!/usr/bin/env python3
"""Record exact solver binaries and argv configurations for a frozen campaign."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

CERT_DIR = SCRIPT_DIR.parent / "cert"
if str(CERT_DIR) not in sys.path:
    sys.path.insert(0, str(CERT_DIR))

from strict_artifacts import (  # noqa: E402
    StrictArtifactError,
    atomic_write_nofollow,
    canonical_json_bytes,
    open_read_nofollow,
    read_open_descriptor,
    strict_json_loads,
)
from validate_campaign_spec import CampaignSpecError, validate_spec  # noqa: E402


class SolverConfigError(ValueError):
    """Raised when an installed solver cannot be pinned or smoke checked."""


REQUIRED_VIPER_EVIDENCE_FEATURES = frozenset({"production-evidence"})


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def load_versions(spec_path: Path) -> dict[str, str]:
    try:
        spec = strict_json_loads(
            spec_path.read_text(encoding="utf-8"), "campaign specification"
        )
    except (OSError, UnicodeError, StrictArtifactError) as error:
        raise SolverConfigError(f"cannot read campaign specification: {error}") from error
    try:
        validate_spec(spec)
    except CampaignSpecError as error:
        raise SolverConfigError(
            f"invalid campaign specification: {'; '.join(error.errors)}"
        ) from error
    comparators = spec.get("comparators") if isinstance(spec, dict) else None
    if not isinstance(comparators, list):
        raise SolverConfigError("campaign specification lacks comparators")
    versions: dict[str, str] = {}
    for record in comparators:
        if not isinstance(record, dict):
            raise SolverConfigError("comparator record must be an object")
        identifier = record.get("id")
        version = record.get("version")
        if not isinstance(identifier, str) or not isinstance(version, str):
            raise SolverConfigError("comparator requires string id and version")
        if identifier in versions:
            raise SolverConfigError(f"duplicate comparator {identifier!r}")
        versions[identifier] = version
    required = {"z3", "cvc5", "yices2", "opensmt"}
    if set(versions) != required:
        raise SolverConfigError(
            f"campaign comparators must equal {sorted(required)!r}, got {sorted(versions)!r}"
        )
    return versions


def executable(path: Path, identifier: str) -> Path:
    resolved = path.resolve()
    if not resolved.is_file() or not os.access(resolved, os.X_OK):
        raise SolverConfigError(f"{identifier} binary is not executable: {resolved}")
    return resolved


def capture_version(binary: Path, argv: list[str], expected: str) -> str:
    try:
        completed = subprocess.run(
            [str(binary), *argv],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
            env={"LANG": "C", "LC_ALL": "C", "PATH": os.environ.get("PATH", "")},
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise SolverConfigError(f"cannot query {binary} version: {error}") from error
    output = (completed.stdout + completed.stderr).strip()
    if completed.returncode != 0 or not output:
        raise SolverConfigError(
            f"version command for {binary} failed with {completed.returncode}: {output}"
        )
    if expected not in output:
        raise SolverConfigError(
            f"version output for {binary} does not contain {expected!r}: {output!r}"
        )
    return output[:4096]


def require_viper_evidence_features(feature_report: Path) -> frozenset[str]:
    binary = executable(feature_report, "euf-viper feature report")
    try:
        completed = subprocess.run(
            [str(binary)],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
            env={"LANG": "C", "LC_ALL": "C", "PATH": os.environ.get("PATH", "")},
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise SolverConfigError(
            f"cannot query euf-viper build feature report: {error}"
        ) from error
    output = completed.stdout.strip()
    if completed.returncode != 0:
        raise SolverConfigError(
            "euf-viper feature report failed; "
            "the locked evidence binary must include production-evidence"
        )
    values = output.split(",") if output else []
    if any(not value or value.strip() != value for value in values):
        raise SolverConfigError("euf-viper reported malformed build features")
    features = frozenset(values)
    if len(features) != len(values):
        raise SolverConfigError("euf-viper reported duplicate build features")
    missing = REQUIRED_VIPER_EVIDENCE_FEATURES - features
    if missing:
        raise SolverConfigError(
            "euf-viper binary lacks required locked evidence features: "
            + ", ".join(sorted(missing))
        )
    return features


def require_sealed_build_receipt(
    receipt_path: Path,
    viper: Path,
    feature_report: Path,
    features: frozenset[str],
) -> tuple[Path, str]:
    receipt_fd = -1
    try:
        receipt, receipt_fd = open_read_nofollow(
            receipt_path.absolute(), "sealed build receipt"
        )
        raw, receipt_metadata = read_open_descriptor(
            receipt_fd, "sealed build receipt"
        )
        value = strict_json_loads(raw.decode("utf-8"), "sealed build receipt")
    except (OSError, UnicodeError, StrictArtifactError) as error:
        raise SolverConfigError(f"cannot read sealed build receipt: {error}") from error
    finally:
        if receipt_fd >= 0:
            os.close(receipt_fd)
    if stat.S_IMODE(receipt_metadata.st_mode) != 0o400:
        raise SolverConfigError("sealed build receipt mode must be 0400")
    if canonical_json_bytes(value) != raw:
        raise SolverConfigError("sealed build receipt is not canonical JSON")
    expected_keys = {
        "artifacts",
        "build",
        "independent_attestation",
        "schema",
        "sealed_build_manifest_sha256",
        "source",
        "status",
    }
    if type(value) is not dict or set(value) != expected_keys:
        raise SolverConfigError("sealed build receipt does not bind this solver build")
    artifacts = value["artifacts"]
    build = value["build"]
    source = value["source"]
    if (
        value["schema"] != "euf-viper.sealed-build-receipt.v3"
        or value["status"] != "accepted"
        or type(artifacts) is not dict
        or set(artifacts) != {"euf-viper", "euf-viper-build-features"}
        or type(build) is not dict
        or set(build)
        != {"execution_closure_sha256", "features", "profile", "target", "toolchain"}
        or type(source) is not dict
        or set(source) != {"dirty", "revision", "snapshot_manifest_sha256", "tree"}
        or source["dirty"] is not False
        or build["features"] != sorted(features)
        or build["profile"] != "release"
        or type(build["target"]) is not str
        or "linux" not in build["target"]
        or type(build["toolchain"]) is not dict
        or set(build["toolchain"]) != {"cargo", "rustc"}
        or any(
            type(item) is not str or not item for item in build["toolchain"].values()
        )
    ):
        raise SolverConfigError("sealed build receipt does not bind this solver build")

    def valid_hash(item: object) -> bool:
        return (
            type(item) is str
            and len(item) == 64
            and all(character in "0123456789abcdef" for character in item)
        )

    def valid_object_id(item: object) -> bool:
        return (
            type(item) is str
            and len(item) in {40, 64}
            and all(character in "0123456789abcdef" for character in item)
        )

    if (
        not valid_hash(value["sealed_build_manifest_sha256"])
        or not valid_hash(build["execution_closure_sha256"])
        or not valid_hash(source["snapshot_manifest_sha256"])
        or not valid_object_id(source["revision"])
        or not valid_object_id(source["tree"])
    ):
        raise SolverConfigError("sealed build receipt contains a malformed binding")
    expected_artifacts = {
        "euf-viper": viper,
        "euf-viper-build-features": feature_report,
    }
    for name, path in expected_artifacts.items():
        record = artifacts[name]
        metadata = path.stat()
        if (
            type(record) is not dict
            or set(record) != {"bytes", "mode", "sha256"}
            or record["bytes"] != metadata.st_size
            or record["mode"] != f"{stat.S_IMODE(metadata.st_mode):04o}"
            or record["mode"] != "0500"
            or record["sha256"] != sha256_file(path)
        ):
            raise SolverConfigError(
                f"sealed build receipt does not bind {name} bytes and mode"
            )
    attestation_path = receipt.parent / "sealed-build-attestation.json"
    attestation_fd = -1
    try:
        _, attestation_fd = open_read_nofollow(
            attestation_path, "independent sealed build attestation"
        )
        attestation_raw, attestation_metadata = read_open_descriptor(
            attestation_fd, "independent sealed build attestation"
        )
        attestation = strict_json_loads(
            attestation_raw.decode("utf-8"), "independent sealed build attestation"
        )
    except (OSError, UnicodeError, StrictArtifactError) as error:
        raise SolverConfigError(
            f"cannot read independent sealed build attestation: {error}"
        ) from error
    finally:
        if attestation_fd >= 0:
            os.close(attestation_fd)
    if (
        stat.S_IMODE(attestation_metadata.st_mode) != 0o400
        or canonical_json_bytes(attestation) != attestation_raw
        or attestation != value["independent_attestation"]
        or attestation.get("schema") != "euf-viper.sealed-build-attestation.v1"
        or attestation.get("status") != "accepted"
        or attestation.get("artifacts") != artifacts
        or attestation.get("features") != build["features"]
        or attestation.get("toolchain") != build["toolchain"]
        or attestation.get("closure_sha256")
        != build["execution_closure_sha256"]
        or attestation.get("build_manifest_sha256")
        != value["sealed_build_manifest_sha256"]
    ):
        raise SolverConfigError("independent sealed build attestation binding differs")
    return receipt, hashlib.sha256(raw).hexdigest()


def result_token(output: str) -> str | None:
    for line in output.splitlines():
        token = line.strip()
        if token in {"sat", "unsat", "unknown"}:
            return token
    return None


def smoke_solver(
    record: dict[str, Any],
    instance: Path,
    expected: str,
    *,
    sealed_build_receipt: Path | None = None,
) -> None:
    substitutions = {
        "{binary}": record["binary"],
        "{instance}": str(instance.resolve()),
        "{budget_s}": "10",
    }
    command = [substitutions.get(argument, argument) for argument in record["argv_template"]]
    environment = {
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": os.environ.get("PATH", ""),
        **record.get("environment", {}),
    }
    try:
        temporary_root = Path(tempfile.gettempdir()).resolve(strict=True)
        with tempfile.TemporaryDirectory(
            prefix="euf-viper-config-smoke-", dir=temporary_root
        ) as directory:
            evidence_path = Path(directory) / "production-evidence.json"
            evidence = record.get("evidence")
            if evidence is not None:
                receipt = sealed_build_receipt
                if receipt is None:
                    raw_receipt = os.environ.get("EUF_VIPER_SEALED_BUILD_RECEIPT")
                    receipt = Path(raw_receipt) if raw_receipt else None
                if receipt is None:
                    raise SolverConfigError(
                        "external sealed build receipt is required for evidence smoke"
                    )
                environment["EUF_VIPER_SEALED_BUILD_RECEIPT"] = str(
                    receipt.resolve(strict=True)
                )
                environment["EUF_VIPER_RUN_NONCE"] = secrets.token_hex(32)
                environment["EUF_VIPER_TRUSTED_EXECUTABLE_SHA256"] = record["sha256"]
                command.extend([evidence["argv_flag"], str(evidence_path)])
            completed = subprocess.run(
                command,
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
                env=environment,
            )
            if expected in {"sat", "unsat"} and evidence is not None:
                if expected not in evidence["accepted_decisive_statuses"]:
                    raise SolverConfigError(
                        f"evidence contract does not accept smoke status {expected!r}"
                    )
                if not evidence_path.is_file():
                    raise SolverConfigError("euf-viper smoke run omitted production evidence")
                try:
                    payload = strict_json_loads(
                        evidence_path.read_text(encoding="utf-8"),
                        "euf-viper smoke evidence",
                    )
                except (OSError, UnicodeError, StrictArtifactError) as error:
                    raise SolverConfigError(
                        f"cannot read euf-viper smoke evidence: {error}"
                    ) from error
                expected_keys = {
                    "schema",
                    "run_nonce",
                    "status",
                    "backend_status",
                    "source",
                    "solver",
                    "backend_cnf",
                    "model",
                    "limitations",
                }
                if (
                    type(payload) is not dict
                    or set(payload) != expected_keys
                    or payload.get("schema") != evidence["schema"]
                    or payload.get("status") != expected
                ):
                    raise SolverConfigError("euf-viper smoke evidence schema/status mismatch")
    except (OSError, subprocess.TimeoutExpired) as error:
        raise SolverConfigError(f"smoke run failed for {record['id']}: {error}") from error
    observed = result_token(completed.stdout)
    if completed.returncode != 0 or observed != expected:
        raise SolverConfigError(
            f"smoke run for {record['id']} returned code={completed.returncode}, "
            f"result={observed!r}, stderr={completed.stderr.strip()!r}"
        )


def make_records(
    *,
    versions: dict[str, str],
    viper: Path,
    z3: Path,
    cvc5: Path,
    yices2: Path,
    opensmt: Path,
    viper_version: str,
    viper_feature_report: Path,
    viper_sealed_build_receipt: Path,
) -> list[dict[str, Any]]:
    paths = {
        "euf-viper": executable(viper, "euf-viper"),
        "z3": executable(z3, "z3"),
        "cvc5": executable(cvc5, "cvc5"),
        "yices2": executable(yices2, "yices2"),
        "opensmt": executable(opensmt, "opensmt"),
    }
    features = require_viper_evidence_features(viper_feature_report)
    sealed_receipt, sealed_receipt_sha256 = require_sealed_build_receipt(
        viper_sealed_build_receipt,
        paths["euf-viper"],
        viper_feature_report.resolve(strict=True),
        features,
    )
    definitions = [
        {
            "id": "euf-viper",
            "comparator_id": "euf-viper",
            "configuration": "default",
            "version": viper_version,
            "binary": paths["euf-viper"],
            "argv_template": ["{binary}", "solve", "{instance}"],
            "evidence": {
                "schema": "euf-viper.production-evidence.v4",
                "argv_flag": "--evidence-out",
                "accepted_decisive_statuses": ["sat"],
            },
            "environment": {
                "EUF_VIPER_SEALED_BUILD_RECEIPT_SHA256": sealed_receipt_sha256,
            },
            "version_argv": ["--version"],
            "version_output_contains": "euf-viper",
        },
        {
            "id": "z3-default",
            "comparator_id": "z3",
            "configuration": "default",
            "version": versions["z3"],
            "binary": paths["z3"],
            "argv_template": ["{binary}", "{instance}"],
            "version_argv": ["-version"],
            "version_output_contains": versions["z3"],
        },
        {
            "id": "z3-sat-euf",
            "comparator_id": "z3",
            "configuration": "sat.euf=true",
            "version": versions["z3"],
            "binary": paths["z3"],
            "argv_template": ["{binary}", "sat.euf=true", "{instance}"],
            "version_argv": ["-version"],
            "version_output_contains": versions["z3"],
        },
        {
            "id": "cvc5",
            "comparator_id": "cvc5",
            "configuration": "default",
            "version": versions["cvc5"],
            "binary": paths["cvc5"],
            "argv_template": ["{binary}", "{instance}"],
            "version_argv": ["--version"],
            "version_output_contains": versions["cvc5"],
        },
        {
            "id": "yices2",
            "comparator_id": "yices2",
            "configuration": "default",
            "version": versions["yices2"],
            "binary": paths["yices2"],
            "argv_template": ["{binary}", "{instance}"],
            "version_argv": ["--version"],
            "version_output_contains": versions["yices2"],
        },
        {
            "id": "opensmt",
            "comparator_id": "opensmt",
            "configuration": "default",
            "version": versions["opensmt"],
            "binary": paths["opensmt"],
            "argv_template": ["{binary}", "{instance}"],
            "version_argv": ["--version"],
            "version_output_contains": versions["opensmt"],
        },
    ]
    records: list[dict[str, Any]] = []
    for definition in definitions:
        binary = definition.pop("binary")
        assert isinstance(binary, Path)
        capture_version(
            binary,
            definition["version_argv"],
            definition["version_output_contains"],
        )
        records.append(
            {
                **definition,
                "binary": str(binary),
                "sha256": sha256_file(binary),
            }
        )
    return records


def atomic_write(path: Path, payload: dict[str, Any]) -> None:
    try:
        atomic_write_nofollow(
            path,
            canonical_json_bytes(payload),
            "solver configuration",
            immutable=True,
        )
    except StrictArtifactError as error:
        raise SolverConfigError(f"cannot publish solver configuration: {error}") from error


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--campaign", type=Path, required=True)
    parser.add_argument("--viper", type=Path, required=True)
    parser.add_argument("--viper-feature-report", type=Path, required=True)
    parser.add_argument("--viper-sealed-build-receipt", type=Path, required=True)
    parser.add_argument("--viper-version", required=True)
    parser.add_argument("--z3", type=Path, required=True)
    parser.add_argument("--cvc5", type=Path, required=True)
    parser.add_argument("--yices2", type=Path, required=True)
    parser.add_argument("--opensmt", type=Path, required=True)
    parser.add_argument("--smoke-instance", type=Path)
    parser.add_argument("--smoke-expected", choices=("sat", "unsat"))
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    if bool(args.smoke_instance) != bool(args.smoke_expected):
        parser.error("--smoke-instance and --smoke-expected must be provided together")
    try:
        records = make_records(
            versions=load_versions(args.campaign),
            viper=args.viper,
            z3=args.z3,
            cvc5=args.cvc5,
            yices2=args.yices2,
            opensmt=args.opensmt,
            viper_version=args.viper_version,
            viper_feature_report=args.viper_feature_report,
            viper_sealed_build_receipt=args.viper_sealed_build_receipt,
        )
        if args.smoke_instance:
            if not args.smoke_instance.is_file():
                raise SolverConfigError(
                    f"smoke instance is not a file: {args.smoke_instance}"
                )
            for record in records:
                smoke_solver(
                    record,
                    args.smoke_instance,
                    args.smoke_expected,
                    sealed_build_receipt=(
                        args.viper_sealed_build_receipt
                        if record["id"] == "euf-viper"
                        else None
                    ),
                )
    except SolverConfigError as error:
        parser.exit(2, f"record failed: {error}\n")
    payload = {
        "schema_version": 1,
        "campaign": str(args.campaign.resolve()),
        "campaign_sha256": sha256_file(args.campaign),
        "solvers": records,
    }
    try:
        atomic_write(args.out, payload)
    except SolverConfigError as error:
        parser.exit(2, f"record failed: {error}\n")
    print(json.dumps({
        "solvers": [record["id"] for record in records],
        "hashes": {record["id"]: record["sha256"] for record in records},
        "smoke_checked": args.smoke_instance is not None,
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
