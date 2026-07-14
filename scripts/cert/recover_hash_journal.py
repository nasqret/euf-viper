#!/usr/bin/env python3
"""Recover an authenticated journal prefix as a non-promotional forensic copy."""

from __future__ import annotations

import argparse
import hashlib
import re
import sys
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from strict_artifacts import (
    StrictArtifactError,
    atomic_write_nofollow,
    canonical_json_bytes,
    read_regular_nofollow,
    strict_json_loads,
)


HEX64 = re.compile(r"[0-9a-f]{64}\Z")


class RecoveryError(ValueError):
    """Raised when no authenticated recovery prefix can be produced."""


def _record_digest(record: dict[str, Any]) -> str:
    unsigned = dict(record)
    unsigned.pop("record_sha256", None)
    return hashlib.sha256(canonical_json_bytes(unsigned)).hexdigest()


def recover(source: Path, output: Path) -> dict[str, Any]:
    try:
        source, raw = read_regular_nofollow(source, "source journal")
    except StrictArtifactError as error:
        raise RecoveryError(str(error)) from error
    if not raw or raw.endswith(b"\n"):
        raise RecoveryError("source journal does not have an incomplete trailing frame")
    final_newline = raw.rfind(b"\n")
    if final_newline < 0:
        raise RecoveryError("source journal has no complete authenticated frame")
    prefix = raw[: final_newline + 1]
    tail = raw[final_newline + 1 :]
    try:
        lines = prefix.decode("utf-8").splitlines()
    except UnicodeError as error:
        raise RecoveryError(f"complete journal prefix is not UTF-8: {error}") from error

    previous: str | None = None
    for line_number, line in enumerate(lines, start=1):
        try:
            value = strict_json_loads(line, f"journal frame {line_number}")
        except StrictArtifactError as error:
            raise RecoveryError(str(error)) from error
        if type(value) is not dict:
            raise RecoveryError(f"journal frame {line_number} is not an object")
        if canonical_json_bytes(value) != (line + "\n").encode("utf-8"):
            raise RecoveryError(f"journal frame {line_number} is not canonical JSON")
        if value.get("previous_record_sha256") != previous:
            raise RecoveryError(f"journal frame {line_number} breaks the hash chain")
        record_hash = value.get("record_sha256")
        if type(record_hash) is not str or not HEX64.fullmatch(record_hash):
            raise RecoveryError(f"journal frame {line_number} has an invalid record hash")
        if _record_digest(value) != record_hash:
            raise RecoveryError(f"journal frame {line_number} has record hash drift")
        previous = record_hash

    marker: dict[str, Any] = {
        "record_type": "non_promotional_recovery",
        "schema_version": 1,
        "promotion_eligible": False,
        "source_journal": str(source),
        "source_journal_sha256": hashlib.sha256(raw).hexdigest(),
        "source_journal_bytes": len(raw),
        "authenticated_frames": len(lines),
        "discarded_tail_sha256": hashlib.sha256(tail).hexdigest(),
        "discarded_tail_bytes": len(tail),
        "previous_record_sha256": previous,
        "record_sha256": "",
    }
    marker["record_sha256"] = _record_digest(marker)
    recovered = prefix + canonical_json_bytes(marker)
    try:
        atomic_write_nofollow(
            output,
            recovered,
            "non-promotional recovered journal",
            immutable=True,
        )
    except StrictArtifactError as error:
        raise RecoveryError(str(error)) from error
    return marker


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    try:
        marker = recover(args.source, args.output)
    except RecoveryError as error:
        print(f"journal recovery failed: {error}", file=sys.stderr)
        return 2
    print(canonical_json_bytes(marker).decode("utf-8"), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
