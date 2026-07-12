#!/usr/bin/env python3
"""Record exact solver binaries and argv configurations for a frozen campaign."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
from pathlib import Path
from typing import Any


class SolverConfigError(ValueError):
    """Raised when an installed solver cannot be pinned or smoke checked."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def load_versions(spec_path: Path) -> dict[str, str]:
    try:
        spec = json.loads(spec_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise SolverConfigError(f"cannot read campaign specification: {error}") from error
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


def result_token(output: str) -> str | None:
    for line in output.splitlines():
        token = line.strip()
        if token in {"sat", "unsat", "unknown"}:
            return token
    return None


def smoke_solver(record: dict[str, Any], instance: Path, expected: str) -> None:
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
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
            env=environment,
        )
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
) -> list[dict[str, Any]]:
    paths = {
        "euf-viper": executable(viper, "euf-viper"),
        "z3": executable(z3, "z3"),
        "cvc5": executable(cvc5, "cvc5"),
        "yices2": executable(yices2, "yices2"),
        "opensmt": executable(opensmt, "opensmt"),
    }
    definitions = [
        {
            "id": "euf-viper",
            "comparator_id": "euf-viper",
            "configuration": "default",
            "version": viper_version,
            "binary": paths["euf-viper"],
            "argv_template": ["{binary}", "solve", "{instance}"],
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
        version_output = capture_version(
            binary,
            definition["version_argv"],
            definition["version_output_contains"],
        )
        records.append(
            {
                **definition,
                "binary": str(binary),
                "sha256": sha256_file(binary),
                "observed_version_output": version_output,
                "observed_version_output_sha256": hashlib.sha256(
                    version_output.encode("utf-8")
                ).hexdigest(),
            }
        )
    return records


def atomic_write(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    temporary.replace(path)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--campaign", type=Path, required=True)
    parser.add_argument("--viper", type=Path, required=True)
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
        )
        if args.smoke_instance:
            if not args.smoke_instance.is_file():
                raise SolverConfigError(
                    f"smoke instance is not a file: {args.smoke_instance}"
                )
            for record in records:
                smoke_solver(record, args.smoke_instance, args.smoke_expected)
    except SolverConfigError as error:
        parser.exit(2, f"record failed: {error}\n")
    payload = {
        "schema_version": 1,
        "campaign": str(args.campaign.resolve()),
        "campaign_sha256": sha256_file(args.campaign),
        "solvers": records,
    }
    atomic_write(args.out, payload)
    print(json.dumps({
        "solvers": [record["id"] for record in records],
        "hashes": {record["id"]: record["sha256"] for record in records},
        "smoke_checked": args.smoke_instance is not None,
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
