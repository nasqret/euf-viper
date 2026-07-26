#!/usr/bin/env python3
"""Inventory, verify, and path-rebase an immutable corpus snapshot."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any, Iterable


class CorpusError(ValueError):
    """Raised when a corpus is not an exact regular-file tree."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def canonical_record(value: dict[str, Any]) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")


def safe_relative_path(value: Any, context: str) -> PurePosixPath:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise CorpusError(f"{context} must be a non-empty POSIX path")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise CorpusError(f"{context} must stay below the corpus root")
    return path


def regular_files(root: Path) -> Iterable[tuple[str, Path]]:
    root = root.resolve(strict=True)
    if not root.is_dir():
        raise CorpusError(f"corpus root is not a directory: {root}")
    for directory, names, files in os.walk(root, followlinks=False):
        directory_path = Path(directory)
        for name in list(names):
            path = directory_path / name
            if path.is_symlink():
                raise CorpusError(f"corpus directory is a symlink: {path}")
        for name in files:
            if name == ".DS_Store":
                continue
            path = directory_path / name
            metadata = path.lstat()
            if not stat.S_ISREG(metadata.st_mode):
                raise CorpusError(f"corpus entry is not a regular file: {path}")
            relative = path.relative_to(root).as_posix()
            safe_relative_path(relative, f"corpus path {relative!r}")
            yield relative, path


def build_inventory(root: Path) -> bytes:
    records = []
    for relative, path in regular_files(root):
        records.append(
            {
                "bytes": path.stat().st_size,
                "relative_path": relative,
                "sha256": sha256_file(path),
            }
        )
    if not records:
        raise CorpusError("corpus contains no regular files")
    records.sort(key=lambda item: item["relative_path"])
    return b"".join(canonical_record(record) for record in records)


def atomic_create(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() or path.is_symlink():
        raise CorpusError(f"refuse to replace existing artifact: {path}")
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent, prefix=f".{path.name}.", suffix=".tmp"
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.link(temporary, path)
        path.chmod(0o444)
        temporary.unlink()
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def load_inventory(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    seen: set[str] = set()
    for line_number, line in enumerate(path.read_text(encoding="ascii").splitlines(), 1):
        if not line:
            raise CorpusError(f"inventory has a blank line at {line_number}")
        try:
            record = json.loads(line)
        except json.JSONDecodeError as error:
            raise CorpusError(f"invalid inventory line {line_number}: {error}") from error
        if not isinstance(record, dict) or set(record) != {
            "bytes",
            "relative_path",
            "sha256",
        }:
            raise CorpusError(f"inventory line {line_number} has invalid fields")
        relative = safe_relative_path(
            record["relative_path"], f"inventory line {line_number} relative_path"
        ).as_posix()
        if relative in seen:
            raise CorpusError(f"duplicate inventory path: {relative}")
        if not isinstance(record["bytes"], int) or record["bytes"] < 0:
            raise CorpusError(f"invalid byte count for {relative}")
        digest = record["sha256"]
        if not isinstance(digest, str) or len(digest) != 64 or any(
            character not in "0123456789abcdef" for character in digest
        ):
            raise CorpusError(f"invalid SHA-256 for {relative}")
        records.append(record)
        seen.add(relative)
    if not records:
        raise CorpusError("inventory is empty")
    if records != sorted(records, key=lambda item: item["relative_path"]):
        raise CorpusError("inventory paths are not sorted")
    return records


def verify_inventory(root: Path, inventory: Path) -> None:
    root = root.resolve(strict=True)
    records = load_inventory(inventory)
    observed = {relative: path for relative, path in regular_files(root)}
    expected = {record["relative_path"] for record in records}
    if set(observed) != expected:
        missing = sorted(expected - set(observed))[:3]
        extra = sorted(set(observed) - expected)[:3]
        raise CorpusError(f"corpus tree differs: missing={missing!r} extra={extra!r}")
    for record in records:
        relative = record["relative_path"]
        path = observed[relative]
        if path.stat().st_size != record["bytes"]:
            raise CorpusError(f"corpus size drift: {relative}")
        if sha256_file(path) != record["sha256"]:
            raise CorpusError(f"corpus hash drift: {relative}")


def rebase_manifest(source: Path, instance_root: Path) -> bytes:
    instance_root = instance_root.resolve(strict=True)
    if not instance_root.is_dir():
        raise CorpusError(f"instance root is not a directory: {instance_root}")
    output = bytearray()
    seen: set[str] = set()
    for line_number, line in enumerate(source.read_text(encoding="utf-8").splitlines(), 1):
        if not line:
            raise CorpusError(f"manifest has a blank line at {line_number}")
        try:
            row = json.loads(line)
        except json.JSONDecodeError as error:
            raise CorpusError(f"invalid manifest line {line_number}: {error}") from error
        if not isinstance(row, dict):
            raise CorpusError(f"manifest line {line_number} must be an object")
        relative = safe_relative_path(
            row.get("relative_path"), f"manifest line {line_number} relative_path"
        ).as_posix()
        if relative in seen:
            raise CorpusError(f"duplicate manifest path: {relative}")
        instance = instance_root.joinpath(*PurePosixPath(relative).parts).resolve(strict=True)
        try:
            instance.relative_to(instance_root)
        except ValueError as error:
            raise CorpusError(f"manifest path escapes instance root: {relative}") from error
        if not instance.is_file():
            raise CorpusError(f"manifest instance is not a file: {instance}")
        expected_hash = row.get("sha256")
        if isinstance(expected_hash, str) and sha256_file(instance) != expected_hash:
            raise CorpusError(f"manifest instance hash drift: {relative}")
        expected_bytes = row.get("bytes")
        if isinstance(expected_bytes, int) and instance.stat().st_size != expected_bytes:
            raise CorpusError(f"manifest instance size drift: {relative}")
        row["path"] = str(instance)
        output.extend(canonical_record(row))
        seen.add(relative)
    if not seen:
        raise CorpusError("manifest is empty")
    return bytes(output)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    inventory_parser = subparsers.add_parser("inventory")
    inventory_parser.add_argument("--root", type=Path, required=True)
    inventory_parser.add_argument("--out", type=Path, required=True)
    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("--root", type=Path, required=True)
    verify_parser.add_argument("--inventory", type=Path, required=True)
    rebase_parser = subparsers.add_parser("rebase-manifest")
    rebase_parser.add_argument("--manifest", type=Path, required=True)
    rebase_parser.add_argument("--instance-root", type=Path, required=True)
    rebase_parser.add_argument("--out", type=Path, required=True)
    verify_manifest_parser = subparsers.add_parser("verify-rebased-manifest")
    verify_manifest_parser.add_argument("--manifest", type=Path, required=True)
    verify_manifest_parser.add_argument("--instance-root", type=Path, required=True)
    verify_manifest_parser.add_argument("--rebased", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command == "inventory":
            atomic_create(args.out, build_inventory(args.root))
            print(sha256_file(args.out))
        elif args.command == "verify":
            verify_inventory(args.root, args.inventory)
            print(sha256_file(args.inventory))
        elif args.command == "rebase-manifest":
            atomic_create(
                args.out, rebase_manifest(args.manifest, args.instance_root)
            )
            print(sha256_file(args.out))
        else:
            expected = rebase_manifest(args.manifest, args.instance_root)
            if args.rebased.read_bytes() != expected:
                raise CorpusError("rebased manifest differs from the canonical rewrite")
            print(sha256_file(args.rebased))
    except (CorpusError, OSError, UnicodeError) as error:
        parser.exit(2, f"corpus error: {error}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
