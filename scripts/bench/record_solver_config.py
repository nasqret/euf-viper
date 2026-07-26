#!/usr/bin/env python3
"""Record exact solver binaries and argv configurations for a frozen campaign."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
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


ENVIRONMENT_KEY = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")


def parse_environment(bindings: list[str] | None) -> dict[str, str]:
    environment: dict[str, str] = {}
    for binding in bindings or []:
        key, separator, value = binding.partition("=")
        if not separator or not ENVIRONMENT_KEY.fullmatch(key):
            raise SolverConfigError(
                f"environment binding must use NAME=VALUE syntax: {binding!r}"
            )
        if "\x00" in value:
            raise SolverConfigError(f"environment value contains NUL: {key}")
        if key in environment:
            raise SolverConfigError(f"duplicate environment binding: {key}")
        environment[key] = value
    return dict(sorted(environment.items()))


def capture_version(
    binary: Path,
    argv: list[str],
    expected: str,
    environment: dict[str, str] | None = None,
) -> str:
    try:
        completed = subprocess.run(
            [str(binary), *argv],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
            env={
                "LANG": "C",
                "LC_ALL": "C",
                "PATH": os.environ.get("PATH", ""),
                **(environment or {}),
            },
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


def validate_viper_argv_template(arguments: list[str] | None) -> list[str]:
    template = ["{binary}", "solve", "{instance}"] if arguments is None else arguments
    if not template or any(type(argument) is not str or not argument for argument in template):
        raise SolverConfigError("Viper argv template must contain non-empty strings")
    if template.count("{binary}") != 1 or template.count("{instance}") != 1:
        raise SolverConfigError(
            "Viper argv template requires exactly one {binary} and one {instance}"
        )
    if template[0] != "{binary}":
        raise SolverConfigError("Viper argv template must start with {binary}")
    for argument in template:
        if "{" in argument or "}" in argument:
            if argument not in {"{binary}", "{instance}"}:
                raise SolverConfigError(
                    f"unsupported Viper argv placeholder in {argument!r}"
                )
    return list(template)


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
    viper_argv_template: list[str] | None = None,
    viper_configuration: str = "default",
    z3_environment: dict[str, str] | None = None,
) -> list[dict[str, Any]]:
    if not viper_configuration or viper_configuration != viper_configuration.strip():
        raise SolverConfigError("Viper configuration must be a non-empty trimmed string")
    viper_argv_template = validate_viper_argv_template(viper_argv_template)
    z3_environment = dict(sorted((z3_environment or {}).items()))
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
            "configuration": viper_configuration,
            "version": viper_version,
            "binary": paths["euf-viper"],
            "argv_template": viper_argv_template,
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
            "environment": z3_environment,
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
            "environment": z3_environment,
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
            definition.get("environment"),
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
    parser.add_argument(
        "--viper-arg",
        action="append",
        dest="viper_args",
        help=(
            "one Viper argv token; repeat to override the default command and "
            "include literal {binary} and {instance} tokens"
        ),
    )
    parser.add_argument("--viper-configuration", default="default")
    parser.add_argument("--z3", type=Path, required=True)
    parser.add_argument(
        "--z3-env",
        action="append",
        default=[],
        help="one NAME=VALUE environment binding for both Z3 configurations",
    )
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
            viper_argv_template=args.viper_args,
            viper_configuration=args.viper_configuration,
            z3_environment=parse_environment(args.z3_env),
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
