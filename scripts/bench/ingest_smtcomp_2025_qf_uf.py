#!/usr/bin/env python3
"""Reconstruct the exact SMT-COMP 2025 QF_UF selection from official results."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import shutil
import urllib.request
from collections import Counter
from pathlib import Path, PurePosixPath
from typing import Any


SOURCE_COMMIT = "82b2c91eb186a846dff0109bf96bf8fe71d2ded5"
SOURCE_URL = (
    "https://raw.githubusercontent.com/SMT-COMP/smt-comp.github.io/"
    f"{SOURCE_COMMIT}/data/results-sq-2025.json.gz"
)
SOURCE_SHA256 = "d79dd5d693e9cc645817ecbcad8ccc3cb92fba97418dbe011be3f181a6dd4a1e"
EXPECTED_SELECTION_COUNT = 3521
DECISIVE = {"sat", "unsat"}


class IngestError(ValueError):
    """Raised when the official selection cannot be reconstructed exactly."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def download_official(destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(f".{destination.name}.tmp")
    request = urllib.request.Request(
        SOURCE_URL, headers={"User-Agent": "euf-viper-campaign/1"}
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            with temporary.open("wb") as output:
                shutil.copyfileobj(response, output)
    except OSError as error:
        temporary.unlink(missing_ok=True)
        raise IngestError(f"cannot download official results: {error}") from error
    actual = sha256_file(temporary)
    if actual != SOURCE_SHA256:
        temporary.unlink(missing_ok=True)
        raise IngestError(
            f"official download hash mismatch: expected {SOURCE_SHA256}, got {actual}"
        )
    temporary.replace(destination)


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    try:
        with path.open(encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                if not line.strip():
                    continue
                try:
                    value = json.loads(line)
                except json.JSONDecodeError as error:
                    raise IngestError(
                        f"manifest {path}:{line_number} is invalid JSON: {error}"
                    ) from error
                if not isinstance(value, dict):
                    raise IngestError(
                        f"manifest {path}:{line_number} must contain an object"
                    )
                rows.append(value)
    except (OSError, UnicodeError) as error:
        raise IngestError(f"cannot read manifest {path}: {error}") from error
    if not rows:
        raise IngestError(f"manifest {path} is empty")
    return rows


def official_selection(
    results_path: Path,
    *,
    expected_sha256: str | None = SOURCE_SHA256,
    expected_count: int = EXPECTED_SELECTION_COUNT,
) -> tuple[set[tuple[tuple[str, ...], str]], dict[tuple[tuple[str, ...], str], int]]:
    if expected_sha256 is not None:
        actual = sha256_file(results_path)
        if actual != expected_sha256:
            raise IngestError(
                f"official results hash mismatch: expected {expected_sha256}, got {actual}"
            )
    try:
        with gzip.open(results_path, "rt", encoding="utf-8") as handle:
            payload = json.load(handle)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise IngestError(f"cannot read official results {results_path}: {error}") from error
    if not isinstance(payload, dict) or set(payload) != {"results"}:
        raise IngestError("official result root must contain exactly 'results'")
    records = payload["results"]
    if not isinstance(records, list):
        raise IngestError("official results must be an array")

    selected: set[tuple[tuple[str, ...], str]] = set()
    run_counts: Counter[tuple[tuple[str, ...], str]] = Counter()
    for index, record in enumerate(records):
        if not isinstance(record, dict):
            raise IngestError(f"official result {index} must be an object")
        file_record = record.get("file")
        if not isinstance(file_record, dict):
            raise IngestError(f"official result {index} lacks a file record")
        if file_record.get("logic") != "QF_UF":
            continue
        if record.get("track") != "SingleQuery":
            raise IngestError(f"QF_UF result {index} is not SingleQuery")
        family = file_record.get("family")
        name = file_record.get("name")
        if not isinstance(family, list) or not family or any(
            not isinstance(component, str) or not component for component in family
        ):
            raise IngestError(f"QF_UF result {index} has invalid family")
        if not isinstance(name, str) or not name or "/" in name:
            raise IngestError(f"QF_UF result {index} has invalid name")
        key = (tuple(family), name)
        selected.add(key)
        run_counts[key] += 1
    if len(selected) != expected_count:
        raise IngestError(
            f"official QF_UF selection has {len(selected)} files, expected {expected_count}"
        )
    if any(count <= 0 for count in run_counts.values()):
        raise IngestError("official selection contains a benchmark without a result")
    return selected, dict(run_counts)


def _manifest_key(row: dict[str, Any], index: int) -> tuple[tuple[str, ...], str]:
    relative = row.get("relative_path")
    if not isinstance(relative, str) or not relative:
        raise IngestError(f"manifest record {index} lacks relative_path")
    parts = PurePosixPath(relative).parts
    if len(parts) < 3 or parts[0] != "QF_UF":
        raise IngestError(
            f"manifest path {relative!r} must be QF_UF/<family>/<name>"
        )
    return tuple(parts[1:-1]), parts[-1]


def join_selection(
    manifest_path: Path,
    selected: set[tuple[tuple[str, ...], str]],
    run_counts: dict[tuple[tuple[str, ...], str], int],
) -> list[dict[str, Any]]:
    lookup: dict[tuple[tuple[str, ...], str], dict[str, Any]] = {}
    for index, row in enumerate(_read_jsonl(manifest_path)):
        key = _manifest_key(row, index)
        if key in lookup:
            raise IngestError(f"full manifest contains duplicate official key {key!r}")
        status = row.get("status")
        digest = row.get("sha256")
        byte_count = row.get("bytes")
        if status not in DECISIVE:
            raise IngestError(f"manifest {row.get('relative_path')!r} lacks status")
        if not isinstance(digest, str) or len(digest) != 64:
            raise IngestError(f"manifest {row.get('relative_path')!r} lacks sha256")
        if not isinstance(byte_count, int) or byte_count < 0:
            raise IngestError(f"manifest {row.get('relative_path')!r} lacks bytes")
        lookup[key] = row

    missing = sorted(selected - set(lookup))
    if missing:
        raise IngestError(
            f"full manifest is missing {len(missing)} official files; first={missing[0]!r}"
        )
    output: list[dict[str, Any]] = []
    for identifier, key in enumerate(sorted(selected)):
        row = lookup[key]
        family, name = key
        output.append(
            {
                "id": identifier,
                "logic": "QF_UF",
                "relative_path": row["relative_path"],
                "path": str(
                    PurePosixPath("benchmarks/smtlib-2025/QF_UF")
                    / row["relative_path"]
                ),
                "sha256": row["sha256"],
                "bytes": row["bytes"],
                "status": row["status"],
                "official_family": list(family),
                "official_name": name,
                "official_result_rows": run_counts[key],
                "selection_source_commit": SOURCE_COMMIT,
                "selection_source_sha256": SOURCE_SHA256,
            }
        )
    return output


def canonical_jsonl(rows: list[dict[str, Any]]) -> bytes:
    return b"".join(
        (
            json.dumps(row, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
            + "\n"
        ).encode("ascii")
        for row in rows
    )


def atomic_write_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_bytes(data)
    temporary.replace(path)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--full-manifest", type=Path, required=True)
    parser.add_argument("--official-results", type=Path, required=True)
    parser.add_argument("--download", action="store_true")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--metadata", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.download:
            if args.official_results.exists():
                actual = sha256_file(args.official_results)
                if actual != SOURCE_SHA256:
                    raise IngestError(
                        f"existing official results have wrong hash {actual}"
                    )
            else:
                download_official(args.official_results)
        selected, run_counts = official_selection(args.official_results)
        rows = join_selection(args.full_manifest, selected, run_counts)
        encoded = canonical_jsonl(rows)
        metadata = {
            "schema_version": 1,
            "logic": "QF_UF",
            "track": "SingleQuery",
            "year": 2025,
            "instances": len(rows),
            "source_url": SOURCE_URL,
            "source_commit": SOURCE_COMMIT,
            "source_sha256": SOURCE_SHA256,
            "full_manifest_path": str(args.full_manifest),
            "full_manifest_sha256": sha256_file(args.full_manifest),
            "selected_manifest_sha256": hashlib.sha256(encoded).hexdigest(),
        }
    except IngestError as error:
        parser.exit(2, f"ingest failed: {error}\n")
    atomic_write_bytes(args.out, encoded)
    atomic_write_bytes(
        args.metadata,
        (json.dumps(metadata, indent=2, sort_keys=True) + "\n").encode("ascii"),
    )
    print(json.dumps(metadata, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
