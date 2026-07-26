#!/usr/bin/env python3
"""Prepare a minimal, hash-locked Linux x86-64 comparator bundle."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import tarfile
import tempfile
import zipfile
from pathlib import Path
from typing import Any, BinaryIO


SCHEMA_VERSION = "euf-viper.comparator-bundle.v1"
PLATFORM = "linux-x86_64"
ARTIFACTS = {
    "z3": {
        "artifact": "linux-x86_64-manylinux-2.27-wheel",
        "kind": "zip",
        "members": {
            "z3_solver-4.16.0.0.data/data/bin/z3": ("bin/z3", 0o555),
            "z3/lib/libz3.so.4.16": ("lib/libz3.so.4.16", 0o444),
        },
        "binary": "bin/z3",
        "version_argv": ["-version"],
    },
    "cvc5": {
        "artifact": "linux-x86_64",
        "kind": "zip",
        "members": {
            "cvc5-Linux-x86_64-static/bin/cvc5": ("bin/cvc5", 0o555),
        },
        "binary": "bin/cvc5",
        "version_argv": ["--version"],
    },
    "yices2": {
        "artifact": "linux-x86_64",
        "kind": "tar",
        "members": {
            "yices-2.7.0/bin/yices-smt2": ("bin/yices-smt2", 0o555),
        },
        "binary": "bin/yices-smt2",
        "version_argv": ["--version"],
    },
    "opensmt": {
        "artifact": "linux-x86_64",
        "kind": "tar",
        "members": {"opensmt": ("bin/opensmt", 0o555)},
        "binary": "bin/opensmt",
        "version_argv": ["--version"],
    },
}


class BundleError(ValueError):
    """Raised when an archive or release lock is not exact."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def load_release_lock(path: Path) -> tuple[dict[str, dict[str, Any]], str]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise BundleError(f"cannot read release lock: {error}") from error
    if not isinstance(payload, dict) or payload.get("schema_version") != 1:
        raise BundleError("release lock must use schema_version 1")
    records = payload.get("solvers")
    if not isinstance(records, list):
        raise BundleError("release lock lacks solvers")
    indexed = {
        record.get("id"): record
        for record in records
        if isinstance(record, dict) and record.get("id") in ARTIFACTS
    }
    if set(indexed) != set(ARTIFACTS):
        raise BundleError("release lock lacks the exact comparator set")
    return indexed, sha256_file(path)


def expected_artifacts(path: Path) -> tuple[list[dict[str, Any]], str]:
    records, lock_hash = load_release_lock(path)
    expected = []
    for identifier, definition in ARTIFACTS.items():
        record = records[identifier]
        artifacts = record.get("artifacts")
        artifact = artifacts.get(definition["artifact"]) if isinstance(artifacts, dict) else None
        if not isinstance(artifact, dict):
            raise BundleError(f"{identifier} lacks {definition['artifact']!r}")
        url = artifact.get("url")
        digest = artifact.get("sha256")
        if not isinstance(url, str) or not url.startswith("https://"):
            raise BundleError(f"{identifier} artifact URL is invalid")
        if not isinstance(digest, str) or len(digest) != 64:
            raise BundleError(f"{identifier} artifact hash is invalid")
        expected.append(
            {
                "artifact": definition["artifact"],
                "id": identifier,
                "sha256": digest,
                "tag": record.get("tag"),
                "url": url,
                "version": record.get("version"),
            }
        )
    return expected, lock_hash


def parse_artifacts(values: list[str]) -> dict[str, Path]:
    artifacts: dict[str, Path] = {}
    for value in values:
        identifier, separator, raw_path = value.partition("=")
        if not separator or identifier not in ARTIFACTS or not raw_path:
            raise BundleError(f"artifact must use known ID=PATH syntax: {value!r}")
        if identifier in artifacts:
            raise BundleError(f"duplicate artifact: {identifier}")
        artifacts[identifier] = Path(raw_path).resolve(strict=True)
    if set(artifacts) != set(ARTIFACTS):
        raise BundleError(f"artifacts must equal {sorted(ARTIFACTS)!r}")
    return artifacts


def copy_stream(source: BinaryIO, destination: Path, mode: int) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("xb") as output:
        shutil.copyfileobj(source, output)
        output.flush()
        os.fsync(output.fileno())
    destination.chmod(mode)


def extract_members(archive: Path, definition: dict[str, Any], root: Path) -> None:
    members = definition["members"]
    if definition["kind"] == "zip":
        with zipfile.ZipFile(archive) as handle:
            if not set(members).issubset(handle.namelist()):
                raise BundleError(f"archive {archive} lacks required members")
            for source_name, (target_name, mode) in members.items():
                with handle.open(source_name) as source:
                    copy_stream(source, root / target_name, mode)
        return
    with tarfile.open(archive, mode="r:*") as handle:
        for source_name, (target_name, mode) in members.items():
            member = handle.getmember(source_name)
            if not member.isfile():
                raise BundleError(f"archive member is not a regular file: {source_name}")
            source = handle.extractfile(member)
            if source is None:
                raise BundleError(f"cannot extract archive member: {source_name}")
            with source:
                copy_stream(source, root / target_name, mode)


def prepare(release_lock: Path, artifact_arguments: list[str], output: Path) -> dict[str, Any]:
    if output.exists() or output.is_symlink():
        raise BundleError(f"refuse to replace bundle: {output}")
    expected, lock_hash = expected_artifacts(release_lock)
    provided = parse_artifacts(artifact_arguments)
    parent = output.resolve().parent
    parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=f".{output.name}.", dir=parent))
    try:
        for record in expected:
            archive = provided[record["id"]]
            actual_hash = sha256_file(archive)
            if actual_hash != record["sha256"]:
                raise BundleError(
                    f"{record['id']} archive hash mismatch: expected "
                    f"{record['sha256']}, got {actual_hash}"
                )
            extract_members(archive, ARTIFACTS[record["id"]], temporary)

        files = []
        for path in sorted(temporary.rglob("*")):
            if path.is_file():
                relative = path.relative_to(temporary).as_posix()
                files.append(
                    {
                        "bytes": path.stat().st_size,
                        "mode": oct(path.stat().st_mode & 0o777),
                        "path": relative,
                        "sha256": sha256_file(path),
                    }
                )
        solvers = []
        for record in expected:
            definition = ARTIFACTS[record["id"]]
            environment = (
                {"LD_LIBRARY_PATH": "{bundle_root}/lib"}
                if record["id"] == "z3"
                else {}
            )
            solvers.append(
                {
                    "binary": definition["binary"],
                    "environment": environment,
                    "id": record["id"],
                    "version": record["version"],
                    "version_argv": definition["version_argv"],
                }
            )
        receipt = {
            "archives": expected,
            "files": files,
            "platform": PLATFORM,
            "release_lock_sha256": lock_hash,
            "schema_version": SCHEMA_VERSION,
            "solvers": solvers,
        }
        receipt_path = temporary / "receipt.json"
        receipt_path.write_text(
            json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        receipt_path.chmod(0o444)
        for directory in sorted(
            (path for path in temporary.rglob("*") if path.is_dir()), reverse=True
        ):
            directory.chmod(0o555)
        temporary.replace(output)
        output.chmod(0o555)
        return receipt
    except Exception:
        shutil.rmtree(temporary, ignore_errors=True)
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    list_parser = subparsers.add_parser("list", help="list required archives as TSV")
    list_parser.add_argument("--release-lock", type=Path, required=True)
    prepare_parser = subparsers.add_parser("prepare", help="prepare a verified bundle")
    prepare_parser.add_argument("--release-lock", type=Path, required=True)
    prepare_parser.add_argument("--artifact", action="append", default=[])
    prepare_parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command == "list":
            records, _ = expected_artifacts(args.release_lock)
            print("id\turl\tsha256")
            for record in records:
                print(record["id"], record["url"], record["sha256"], sep="\t")
            return 0
        receipt = prepare(args.release_lock, args.artifact, args.out)
    except (BundleError, OSError, tarfile.TarError, zipfile.BadZipFile) as error:
        parser.exit(2, f"bundle preparation failed: {error}\n")
    print(
        json.dumps(
            {
                "files": len(receipt["files"]),
                "output": str(args.out.resolve()),
                "receipt_sha256": sha256_file(args.out / "receipt.json"),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
