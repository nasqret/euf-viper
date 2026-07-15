#!/usr/bin/env python3
"""Record exact CI runner and Python identity as explicitly non-evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import stat
import sys
from pathlib import Path


IDENTITY_SCHEMA = "euf-viper.t5-ci-execution-identity.v1"


class CiIdentityError(ValueError):
    """A CI identity record is incomplete or malformed."""


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def capture_identity(
    *,
    scope: str,
    scheduler_evidence: str,
    environment: dict[str, str] | None = None,
    require_hosted_image: bool = False,
) -> dict[str, object]:
    environment = dict(os.environ if environment is None else environment)
    if scope not in {
        "ordinary_linux_publication_procfs_diagnostic",
        "provisioned_7503_semantic_pipeline_integration",
    }:
        raise CiIdentityError("unsupported T5 CI identity scope")
    if scheduler_evidence not in {"not_queried", "synthetic_injected_root_row"}:
        raise CiIdentityError("unsupported scheduler-evidence label")
    executable = Path(sys.executable).resolve(strict=True)
    executable_stat = executable.stat()
    uname = platform.uname()
    runner = {
        "runner_os": environment.get("RUNNER_OS"),
        "runner_arch": environment.get("RUNNER_ARCH"),
        "runner_name": environment.get("RUNNER_NAME"),
        "image_os": environment.get("ImageOS"),
        "image_version": environment.get("ImageVersion"),
    }
    if require_hosted_image and any(
        type(runner[field]) is not str or not runner[field]
        for field in ("runner_os", "runner_arch", "image_os", "image_version")
    ):
        raise CiIdentityError("hosted runner image identity is incomplete")
    value = {
        "schema": IDENTITY_SCHEMA,
        "status": "execution_identity_non_evidence",
        "decisive": False,
        "authoritative": False,
        "scope": scope,
        "scheduler_evidence": scheduler_evidence,
        "scheduler_query_performed": False,
        "runner": runner,
        "github": {
            "actions": environment.get("GITHUB_ACTIONS"),
            "repository": environment.get("GITHUB_REPOSITORY"),
            "run_id": environment.get("GITHUB_RUN_ID"),
            "run_attempt": environment.get("GITHUB_RUN_ATTEMPT"),
            "sha": environment.get("GITHUB_SHA"),
        },
        "python": {
            "realpath": str(executable),
            "version": platform.python_version(),
            "implementation": platform.python_implementation(),
            "sha256": _sha256_file(executable),
            "bytes": executable_stat.st_size,
            "device": executable_stat.st_dev,
            "inode": executable_stat.st_ino,
            "mode": f"{stat.S_IMODE(executable_stat.st_mode):04o}",
        },
        "platform": {
            "system": uname.system,
            "node": uname.node,
            "release": uname.release,
            "version": uname.version,
            "machine": uname.machine,
        },
    }
    return validate_identity(value)


def validate_identity(value: object) -> dict[str, object]:
    if type(value) is not dict or set(value) != {
        "schema",
        "status",
        "decisive",
        "authoritative",
        "scope",
        "scheduler_evidence",
        "scheduler_query_performed",
        "runner",
        "github",
        "python",
        "platform",
    }:
        raise CiIdentityError("T5 CI identity field set drift")
    if (
        value["schema"] != IDENTITY_SCHEMA
        or value["status"] != "execution_identity_non_evidence"
        or value["decisive"] is not False
        or value["authoritative"] is not False
        or value["scheduler_query_performed"] is not False
    ):
        raise CiIdentityError("T5 CI identity evidence status drift")
    if value["scope"] not in {
        "ordinary_linux_publication_procfs_diagnostic",
        "provisioned_7503_semantic_pipeline_integration",
    } or value["scheduler_evidence"] not in {
        "not_queried",
        "synthetic_injected_root_row",
    }:
        raise CiIdentityError("T5 CI identity scope drift")
    expected_scheduler_evidence = {
        "ordinary_linux_publication_procfs_diagnostic": "not_queried",
        "provisioned_7503_semantic_pipeline_integration": (
            "synthetic_injected_root_row"
        ),
    }[value["scope"]]
    if value["scheduler_evidence"] != expected_scheduler_evidence:
        raise CiIdentityError("T5 CI scope and scheduler-evidence label disagree")
    runner = value["runner"]
    github = value["github"]
    if type(runner) is not dict or set(runner) != {
        "runner_os",
        "runner_arch",
        "runner_name",
        "image_os",
        "image_version",
    } or type(github) is not dict or set(github) != {
        "actions",
        "repository",
        "run_id",
        "run_attempt",
        "sha",
    }:
        raise CiIdentityError("T5 CI runner field set drift")
    if any(item is not None and type(item) is not str for item in runner.values()):
        raise CiIdentityError("T5 CI runner identity type drift")
    if any(item is not None and type(item) is not str for item in github.values()):
        raise CiIdentityError("T5 CI GitHub identity type drift")
    python = value["python"]
    if type(python) is not dict or set(python) != {
        "realpath",
        "version",
        "implementation",
        "sha256",
        "bytes",
        "device",
        "inode",
        "mode",
    }:
        raise CiIdentityError("T5 CI Python field set drift")
    if (
        type(python["realpath"]) is not str
        or not python["realpath"].startswith("/")
        or any(
            type(python[field]) is not str or not python[field]
            for field in ("version", "implementation", "mode")
        )
        or type(python["sha256"]) is not str
        or len(python["sha256"]) != 64
        or any(character not in "0123456789abcdef" for character in python["sha256"])
        or any(
            type(python[field]) is not int or python[field] < 1
            for field in ("bytes", "inode")
        )
        or type(python["device"]) is not int
        or python["device"] < 0
    ):
        raise CiIdentityError("T5 CI Python identity is malformed")
    platform_value = value["platform"]
    if type(platform_value) is not dict or set(platform_value) != {
        "system",
        "node",
        "release",
        "version",
        "machine",
    } or any(
        type(item) is not str or not item for item in platform_value.values()
    ):
        raise CiIdentityError("T5 CI platform identity is malformed")
    return value


def _canonical(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
        + "\n"
    ).encode("ascii")


def write_identity_no_replace(path: Path, value: dict[str, object]) -> None:
    payload = _canonical(validate_identity(value))
    path = Path(os.path.abspath(path))
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise CiIdentityError("T5 CI identity write made no progress")
            offset += written
        os.fsync(descriptor)
        os.fchmod(descriptor, 0o444)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    directory = os.open(
        path.parent,
        os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_DIRECTORY", 0),
    )
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--scope", required=True)
    parser.add_argument("--scheduler-evidence", required=True)
    parser.add_argument("--require-hosted-image", action="store_true")
    arguments = parser.parse_args(argv)
    try:
        value = capture_identity(
            scope=arguments.scope,
            scheduler_evidence=arguments.scheduler_evidence,
            require_hosted_image=arguments.require_hosted_image,
        )
        write_identity_no_replace(arguments.output, value)
    except (OSError, CiIdentityError) as error:
        print(f"cannot record T5 CI identity: {error}", file=sys.stderr)
        return 2
    print(json.dumps(value, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
