#!/usr/bin/env python3
"""Build a deterministic JSONL manifest for SMT-LIB files."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import unicodedata
from pathlib import Path


STATUS_RE = re.compile(r"\(set-info\s+:status\s+([a-zA-Z_]+)\)")
LOGIC_RE = re.compile(r"\(set-logic\s+([^\s\)]+)\)")


def first_match(path: Path, regex: re.Pattern[str]) -> str | None:
    try:
        with path.open("r", encoding="utf-8", errors="ignore") as fh:
            for idx, line in enumerate(fh):
                if idx > 200:
                    break
                match = regex.search(line)
                if match:
                    return match.group(1)
    except OSError:
        return None
    return None


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def absolute_lexical(path: Path) -> Path:
    """Return an absolute normalized path without resolving symlinks."""

    return Path(os.path.abspath(path))


def descriptor_path(path: Path, descriptor_parent: Path) -> str:
    try:
        relative = path.relative_to(descriptor_parent)
    except ValueError as error:
        raise ValueError(
            f"source {path} is outside manifest directory {descriptor_parent}"
        ) from error
    value = relative.as_posix()
    if (
        not value
        or value.startswith("/")
        or "\\" in value
        or "//" in value
        or unicodedata.normalize("NFC", value) != value
        or any(part in {"", ".", ".."} for part in value.split("/"))
        or any(
            unicodedata.category(character) in {"Cc", "Cf"} for character in value
        )
    ):
        raise ValueError(f"non-canonical descriptor-relative source path {value!r}")
    return value


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path)
    parser.add_argument("--logic", default="QF_UF")
    parser.add_argument("--source-doi", default="")
    parser.add_argument("--source-url", default="")
    parser.add_argument("--archive-md5", default="")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()

    root = absolute_lexical(args.root)
    output = absolute_lexical(args.out)
    descriptor_parent = output.parent
    if not root.is_dir():
        parser.error(f"corpus root is not a directory: {root}")
    try:
        root.relative_to(descriptor_parent)
    except ValueError:
        parser.error(
            f"corpus root must be below manifest directory {descriptor_parent}: {root}"
        )

    files = sorted(
        root.rglob("*.smt2"),
        key=lambda path: path.relative_to(root).as_posix().encode("utf-8"),
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8", newline="\n") as out:
        for idx, path in enumerate(files):
            rel = path.relative_to(root).as_posix()
            row = {
                "id": idx,
                "path": descriptor_path(path, descriptor_parent),
                "relative_path": rel,
                "logic": first_match(path, LOGIC_RE) or args.logic,
                "status": first_match(path, STATUS_RE) or "unknown",
                "bytes": path.stat().st_size,
                "sha256": sha256(path),
                "source_doi": args.source_doi,
                "source_url": args.source_url,
                "archive_md5": args.archive_md5,
            }
            out.write(json.dumps(row, allow_nan=False, sort_keys=True) + "\n")
    print(f"manifest={output} files={len(files)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
