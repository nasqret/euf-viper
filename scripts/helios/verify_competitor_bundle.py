#!/usr/bin/env python3
"""Verify and optionally execute a prepared comparator bundle."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import subprocess
import sys
from pathlib import Path, PurePosixPath
from typing import Any


SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import prepare_competitor_bundle as preparer  # noqa: E402


class VerificationError(ValueError):
    """Raised when a bundle does not match its receipt."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def safe_relative(value: Any) -> str:
    if not isinstance(value, str):
        raise VerificationError("receipt path must be a string")
    path = PurePosixPath(value)
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        raise VerificationError(f"unsafe receipt path: {value!r}")
    return value


def check_elf_x86_64(path: Path) -> None:
    header = path.read_bytes()[:20]
    if len(header) < 20 or header[:4] != b"\x7fELF":
        raise VerificationError(f"not an ELF file: {path}")
    if header[4] != 2 or header[5] != 1:
        raise VerificationError(f"ELF is not 64-bit little-endian: {path}")
    if int.from_bytes(header[18:20], "little") != 62:
        raise VerificationError(f"ELF is not x86-64: {path}")


def verify(bundle_root: Path, receipt_path: Path, release_lock: Path, execute: bool) -> dict[str, Any]:
    bundle_root = bundle_root.resolve(strict=True)
    receipt_path = receipt_path.resolve(strict=True)
    if receipt_path.parent != bundle_root or receipt_path.name != "receipt.json":
        raise VerificationError("receipt must be bundle_root/receipt.json")
    if receipt_path.is_symlink() or not receipt_path.is_file():
        raise VerificationError("receipt must be a regular file")
    try:
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise VerificationError(f"invalid receipt: {error}") from error
    required_keys = {
        "archives",
        "files",
        "platform",
        "release_lock_sha256",
        "schema_version",
        "solvers",
    }
    if not isinstance(receipt, dict) or set(receipt) != required_keys:
        raise VerificationError("receipt has an invalid top-level schema")
    if receipt["schema_version"] != preparer.SCHEMA_VERSION:
        raise VerificationError("receipt schema version drifted")
    if receipt["platform"] != preparer.PLATFORM:
        raise VerificationError("receipt platform drifted")
    expected_archives, lock_hash = preparer.expected_artifacts(release_lock)
    if receipt["release_lock_sha256"] != lock_hash or receipt["archives"] != expected_archives:
        raise VerificationError("release lock or archive provenance drifted")

    expected_files: set[str] = set()
    for record in receipt["files"]:
        if not isinstance(record, dict) or set(record) != {"bytes", "mode", "path", "sha256"}:
            raise VerificationError("invalid file receipt")
        relative = safe_relative(record["path"])
        if relative in expected_files:
            raise VerificationError(f"duplicate file receipt: {relative}")
        expected_files.add(relative)
        path = bundle_root / relative
        if path.is_symlink() or not path.is_file():
            raise VerificationError(f"bundle file is not regular: {relative}")
        if path.stat().st_size != record["bytes"]:
            raise VerificationError(f"bundle file size drifted: {relative}")
        if oct(stat.S_IMODE(path.stat().st_mode)) != record["mode"]:
            raise VerificationError(f"bundle file mode drifted: {relative}")
        if sha256_file(path) != record["sha256"]:
            raise VerificationError(f"bundle file hash drifted: {relative}")
        check_elf_x86_64(path)
    actual_files = {
        path.relative_to(bundle_root).as_posix()
        for path in bundle_root.rglob("*")
        if path.is_file() and path != receipt_path
    }
    if actual_files != expected_files:
        raise VerificationError("bundle contains missing or unrecorded files")

    expected_solvers = []
    observations = []
    for identifier, definition in preparer.ARTIFACTS.items():
        archive = next(record for record in expected_archives if record["id"] == identifier)
        environment = (
            {"LD_LIBRARY_PATH": "{bundle_root}/lib"} if identifier == "z3" else {}
        )
        expected_solvers.append(
            {
                "binary": definition["binary"],
                "environment": environment,
                "id": identifier,
                "version": archive["version"],
                "version_argv": definition["version_argv"],
            }
        )
    if receipt["solvers"] != expected_solvers:
        raise VerificationError("solver command provenance drifted")

    for solver in expected_solvers:
        binary = bundle_root / solver["binary"]
        file_record = next(record for record in receipt["files"] if record["path"] == solver["binary"])
        version_output = None
        if execute:
            environment = {"LANG": "C", "LC_ALL": "C", "PATH": os.environ.get("PATH", "")}
            environment.update(
                {
                    key: value.replace("{bundle_root}", str(bundle_root))
                    for key, value in solver["environment"].items()
                }
            )
            completed = subprocess.run(
                [str(binary), *solver["version_argv"]],
                check=False,
                capture_output=True,
                text=True,
                timeout=15,
                env=environment,
            )
            version_output = (completed.stdout + completed.stderr).strip()
            if completed.returncode != 0 or solver["version"] not in version_output:
                raise VerificationError(
                    f"version check failed for {solver['id']}: {version_output!r}"
                )
        observations.append(
            {
                "id": solver["id"],
                "path": str(binary),
                "sha256": file_record["sha256"],
                "version_output": version_output,
            }
        )
    return {
        "bundle_root": str(bundle_root),
        "receipt_sha256": sha256_file(receipt_path),
        "solvers": observations,
        "z3_library_path": str(bundle_root / "lib"),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle-root", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--release-lock", type=Path, required=True)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--format", choices=("json", "tsv"), default="json")
    args = parser.parse_args()
    try:
        summary = verify(args.bundle_root, args.receipt, args.release_lock, args.execute)
    except (VerificationError, preparer.BundleError, OSError, subprocess.TimeoutExpired) as error:
        parser.exit(2, f"bundle verification failed: {error}\n")
    if args.format == "json":
        print(json.dumps(summary, indent=2, sort_keys=True))
    else:
        print("kind\tid\tpath\tsha256")
        print(
            "bundle\tbundle\t"
            + summary["bundle_root"]
            + "\t"
            + summary["receipt_sha256"]
        )
        for solver in summary["solvers"]:
            print("solver", solver["id"], solver["path"], solver["sha256"], sep="\t")
        print("environment\tz3-library\t" + summary["z3_library_path"] + "\t-")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
