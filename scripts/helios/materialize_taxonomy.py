#!/usr/bin/env python3
"""Materialize a content-addressed, hash-checked EUF taxonomy cache entry."""

from __future__ import annotations

import argparse
import errno
import fcntl
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Sequence


SCHEMA_VERSION = "euf-viper.taxonomy-cache.v1"
RECEIPT_KEYS = {
    "schema_version",
    "cache_key",
    "manifest_sha256",
    "builder_sha256",
    "path_resolution",
    "taxonomy_sha256",
    "split_sha256",
}


class TaxonomyCacheError(ValueError):
    """The taxonomy cache is malformed, stale, or cannot be materialized."""


def canonical_bytes(value: object) -> bytes:
    return (
        json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode("ascii")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _regular_file(path: Path, context: str) -> Path:
    resolved = path.expanduser().resolve(strict=True)
    if path.is_symlink() or not resolved.is_file():
        raise TaxonomyCacheError(f"{context} must be a regular non-symlink file")
    return resolved


def _path_resolution(manifest: Path, repository_root: Path) -> str:
    try:
        lines = manifest.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as error:
        raise TaxonomyCacheError(f"cannot read manifest {manifest}: {error}") from error
    if not lines:
        raise TaxonomyCacheError("manifest is empty")
    all_absolute = True
    for line_number, line in enumerate(lines, start=1):
        try:
            row = json.loads(line)
        except json.JSONDecodeError as error:
            raise TaxonomyCacheError(
                f"manifest line {line_number} is invalid JSON: {error.msg}"
            ) from error
        if type(row) is not dict or type(row.get("path")) is not str:
            raise TaxonomyCacheError(f"manifest line {line_number} lacks a path")
        all_absolute &= Path(row["path"]).is_absolute()
    return "absolute-manifest" if all_absolute else str(repository_root)


def _load_receipt(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="ascii"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise TaxonomyCacheError(f"cannot read cache receipt {path}: {error}") from error
    if type(value) is not dict or set(value) != RECEIPT_KEYS:
        raise TaxonomyCacheError(f"cache receipt schema drifted: {path}")
    return value


def _validated_entry(
    entry: Path,
    *,
    cache_key: str,
    manifest_sha256: str,
    builder_sha256: str,
    path_resolution: str,
) -> tuple[Path, Path, dict[str, Any]] | None:
    if not entry.exists():
        return None
    if entry.is_symlink() or not entry.is_dir():
        raise TaxonomyCacheError(f"cache entry is not a regular directory: {entry}")
    receipt_path = entry / "receipt.json"
    taxonomy = entry / "taxonomy.jsonl"
    split = entry / "taxonomy-split.json"
    for path, context in (
        (receipt_path, "cache receipt"),
        (taxonomy, "cached taxonomy"),
        (split, "cached taxonomy split"),
    ):
        if path.is_symlink() or not path.is_file():
            raise TaxonomyCacheError(f"{context} is missing or not regular: {path}")
    receipt = _load_receipt(receipt_path)
    expected = {
        "schema_version": SCHEMA_VERSION,
        "cache_key": cache_key,
        "manifest_sha256": manifest_sha256,
        "builder_sha256": builder_sha256,
        "path_resolution": path_resolution,
    }
    for key, value in expected.items():
        if receipt[key] != value:
            raise TaxonomyCacheError(f"cache receipt {key} drifted")
    for path, key in ((taxonomy, "taxonomy_sha256"), (split, "split_sha256")):
        if sha256_file(path) != receipt[key]:
            raise TaxonomyCacheError(f"cached output hash drifted: {path}")
    return taxonomy, split, receipt


def _require_regular_output(path: Path, context: str) -> None:
    if path.is_symlink() or not path.is_file():
        raise TaxonomyCacheError(f"{context} was not produced as a regular file")


def _publish_output(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists() or destination.is_symlink():
        raise TaxonomyCacheError(f"refuse to replace taxonomy output: {destination}")
    try:
        os.link(source, destination)
        return
    except OSError as error:
        if error.errno != errno.EXDEV:
            raise
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as output, source.open("rb") as input_handle:
            shutil.copyfileobj(input_handle, output)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temporary, 0o444)
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)


def materialize(
    *,
    manifest: Path,
    repository_root: Path,
    builder: Path,
    cache_root: Path,
    taxonomy_out: Path,
    split_out: Path,
) -> dict[str, Any]:
    manifest = _regular_file(manifest, "manifest")
    builder = _regular_file(builder, "taxonomy builder")
    repository_root = repository_root.expanduser().resolve(strict=True)
    if not repository_root.is_dir():
        raise TaxonomyCacheError("repository root is not a directory")
    if taxonomy_out.resolve() == split_out.resolve():
        raise TaxonomyCacheError("taxonomy outputs must be different paths")
    manifest_sha256 = sha256_file(manifest)
    builder_sha256 = sha256_file(builder)
    path_resolution = _path_resolution(manifest, repository_root)
    cache_identity = {
        "schema_version": SCHEMA_VERSION,
        "manifest_sha256": manifest_sha256,
        "builder_sha256": builder_sha256,
        "path_resolution": path_resolution,
    }
    cache_key = hashlib.sha256(canonical_bytes(cache_identity)).hexdigest()

    cache_root = cache_root.expanduser()
    if cache_root.is_symlink():
        raise TaxonomyCacheError("cache root must not be a symlink")
    cache_root.mkdir(parents=True, exist_ok=True)
    if cache_root.is_symlink():
        raise TaxonomyCacheError("cache root must not be a symlink")
    cache_root = cache_root.resolve(strict=True)
    if not cache_root.is_dir():
        raise TaxonomyCacheError("cache root must be a regular directory")
    locks = cache_root / ".locks"
    locks.mkdir(exist_ok=True)
    if locks.is_symlink() or not locks.is_dir():
        raise TaxonomyCacheError("cache lock root must be a regular directory")
    entry = cache_root / cache_key
    lock_path = locks / f"{cache_key}.lock"
    cache_hit = True
    with lock_path.open("a+b") as lock_handle:
        fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX)
        validated = _validated_entry(
            entry,
            cache_key=cache_key,
            manifest_sha256=manifest_sha256,
            builder_sha256=builder_sha256,
            path_resolution=path_resolution,
        )
        if validated is None:
            cache_hit = False
            temporary = Path(
                tempfile.mkdtemp(prefix=f".{cache_key}.", dir=cache_root)
            )
            try:
                taxonomy = temporary / "taxonomy.jsonl"
                split = temporary / "taxonomy-split.json"
                completed = subprocess.run(
                    [
                        sys.executable,
                        str(builder),
                        str(manifest),
                        "--repository-root",
                        str(repository_root),
                        "--taxonomy-out",
                        str(taxonomy),
                        "--split-out",
                        str(split),
                    ],
                    check=False,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                if completed.returncode != 0:
                    raise TaxonomyCacheError(
                        "taxonomy builder failed with exit "
                        f"{completed.returncode}: {completed.stderr.strip()}"
                    )
                _require_regular_output(taxonomy, "taxonomy")
                _require_regular_output(split, "taxonomy split")
                receipt = {
                    **cache_identity,
                    "cache_key": cache_key,
                    "taxonomy_sha256": sha256_file(taxonomy),
                    "split_sha256": sha256_file(split),
                }
                (temporary / "builder.stdout").write_text(
                    completed.stdout, encoding="utf-8"
                )
                (temporary / "receipt.json").write_bytes(canonical_bytes(receipt))
                validated_temporary = _validated_entry(
                    temporary,
                    cache_key=cache_key,
                    manifest_sha256=manifest_sha256,
                    builder_sha256=builder_sha256,
                    path_resolution=path_resolution,
                )
                assert validated_temporary is not None
                for path in temporary.iterdir():
                    path.chmod(0o444)
                published = False
                try:
                    os.rename(temporary, entry)
                    published = True
                    entry.chmod(0o555)
                except BaseException:
                    cleanup = entry if published else temporary
                    cleanup.chmod(0o755)
                    for path in cleanup.iterdir():
                        path.chmod(0o644)
                    shutil.rmtree(cleanup, ignore_errors=True)
                    raise
            except BaseException:
                shutil.rmtree(temporary, ignore_errors=True)
                raise
            validated = _validated_entry(
                entry,
                cache_key=cache_key,
                manifest_sha256=manifest_sha256,
                builder_sha256=builder_sha256,
                path_resolution=path_resolution,
            )
            assert validated is not None
        taxonomy, split, receipt = validated

    _publish_output(taxonomy, taxonomy_out)
    try:
        _publish_output(split, split_out)
    except BaseException:
        taxonomy_out.unlink(missing_ok=True)
        raise
    return {
        "schema_version": SCHEMA_VERSION,
        "cache_hit": cache_hit,
        "cache_key": cache_key,
        "cache_entry": str(entry),
        "manifest_sha256": manifest_sha256,
        "builder_sha256": builder_sha256,
        "taxonomy_sha256": receipt["taxonomy_sha256"],
        "split_sha256": receipt["split_sha256"],
    }


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--repository-root", type=Path, required=True)
    parser.add_argument("--builder", type=Path, required=True)
    parser.add_argument("--cache-root", type=Path, required=True)
    parser.add_argument("--taxonomy-out", type=Path, required=True)
    parser.add_argument("--split-out", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = build_argument_parser().parse_args(argv)
    try:
        report = materialize(
            manifest=arguments.manifest,
            repository_root=arguments.repository_root,
            builder=arguments.builder,
            cache_root=arguments.cache_root,
            taxonomy_out=arguments.taxonomy_out,
            split_out=arguments.split_out,
        )
    except (TaxonomyCacheError, OSError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    print(json.dumps(report, allow_nan=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
