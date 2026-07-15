#!/usr/bin/env python3
"""Record hosted-runner identity as diagnostic, non-attesting evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
import sys
from pathlib import Path


def canonical_bytes(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def command(arguments: list[str]) -> str:
    completed = subprocess.run(arguments, capture_output=True, check=False, text=True)
    if completed.returncode != 0:
        raise SystemExit(
            f"runner identity command failed ({completed.returncode}): {arguments!r}"
        )
    return completed.stdout.strip()


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def atomic_create(path: Path, content: bytes) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor = os.open(
        path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
    )
    try:
        offset = 0
        while offset < len(content):
            offset += os.write(descriptor, content[offset:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    os_release = Path("/etc/os-release").resolve(strict=True)
    python = Path(sys.executable).resolve(strict=True)
    hosted = {
        name: os.environ.get(name)
        for name in (
            "ImageOS",
            "ImageRelease",
            "ImageVersion",
            "RUNNER_ARCH",
            "RUNNER_NAME",
            "RUNNER_OS",
        )
    }
    payload = {
        "classification": "diagnostic-non-attesting",
        "hosted_environment": hosted,
        "kernel": platform.uname()._asdict(),
        "os_release": {
            "path": str(os_release),
            "sha256": sha256(os_release),
        },
        "python": {
            "executable": str(python),
            "sha256": sha256(python),
            "version": sys.version,
        },
        "schema": "euf-viper.hosted-runner-diagnostic.v1",
        "toolchain": {
            "cargo": command(["cargo", "-V"]),
            "rustc": command(["rustc", "-Vv"]),
        },
    }
    atomic_create(args.out, canonical_bytes(payload))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
