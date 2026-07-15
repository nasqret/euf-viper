#!/usr/bin/env python3
"""Record the pinned baseline CLI before the candidate comparison phase."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CERT_DIR = ROOT / "scripts" / "cert"
if str(CERT_DIR) not in sys.path:
    sys.path.insert(0, str(CERT_DIR))
if str(Path(__file__).resolve().parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parent))

from ordinary_cli_cases import cases  # noqa: E402
from strict_artifacts import (  # noqa: E402
    StrictArtifactError,
    atomic_write_nofollow,
    canonical_json_bytes,
    open_verified_sealed_memfd,
)


SCHEMA = "euf-viper.ordinary-cli-oracle.v1"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def execute(
    descriptor: int, root: Path, arguments: list[str], stdin: bytes
) -> tuple[int, bytes, bytes]:
    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("EUF_VIPER_")
    }
    environment.update({"LANG": "C", "LC_ALL": "C"})
    completed = __import__("subprocess").run(
        [f"/proc/self/fd/{descriptor}", *arguments],
        cwd=root,
        input=stdin,
        capture_output=True,
        check=False,
        env=environment,
        pass_fds=(descriptor,),
    )
    return completed.returncode, completed.stdout, completed.stderr


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-binary", type=Path, required=True)
    parser.add_argument("--baseline-receipt", type=Path, required=True)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    try:
        root = args.repository.resolve(strict=True)
        binary = args.baseline_binary.resolve(strict=True)
        receipt = args.baseline_receipt.resolve(strict=True)
        binary_sha256 = sha256(binary)
        descriptor = open_verified_sealed_memfd(
            binary, binary_sha256, "ordinary CLI baseline"
        )
        try:
            records = []
            for label, arguments, stdin in cases(root):
                code, stdout, stderr = execute(descriptor, root, arguments, stdin)
                records.append(
                    {
                        "arguments": arguments,
                        "label": label,
                        "result": {
                            "exit_code": code,
                            "stderr_base64": base64.b64encode(stderr).decode("ascii"),
                            "stdout_base64": base64.b64encode(stdout).decode("ascii"),
                        },
                        "stdin_base64": base64.b64encode(stdin).decode("ascii"),
                        "stdin_sha256": hashlib.sha256(stdin).hexdigest(),
                    }
                )
        finally:
            os.close(descriptor)
        if sha256(binary) != binary_sha256:
            raise StrictArtifactError("ordinary CLI baseline path changed after recording")
        payload = {
            "baseline": {
                "bytes": binary.stat().st_size,
                "receipt_sha256": sha256(receipt),
                "sha256": binary_sha256,
            },
            "cases": records,
            "schema": SCHEMA,
            "status": "recorded",
        }
        atomic_write_nofollow(
            args.out,
            canonical_json_bytes(payload),
            "ordinary CLI baseline oracle",
            immutable=True,
            mode=0o400,
        )
    except (OSError, StrictArtifactError, ValueError) as error:
        print(f"ordinary CLI oracle rejected: {error}", file=sys.stderr)
        return 2
    print(canonical_json_bytes(payload).decode("utf-8"), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
