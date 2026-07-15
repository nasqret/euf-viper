#!/usr/bin/env python3
"""Check out and build the independent ordinary-CLI baseline."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
from pathlib import Path


REVISION = "f8d9205"
SCHEMA = "euf-viper.cli-baseline-build.v1"
PINNED_TOOLCHAIN = "1.96.0"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(arguments: list[str], *, cwd: Path, environment: dict[str, str]) -> bytes:
    completed = subprocess.run(
        arguments,
        cwd=cwd,
        env=environment,
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        raise SystemExit(
            f"baseline command failed ({completed.returncode}): {arguments!r}\n"
            f"{(completed.stderr or completed.stdout).decode('utf-8', 'replace')}"
        )
    return completed.stdout


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--cargo", type=Path, default=Path("cargo"))
    parser.add_argument("--rustc", type=Path, default=Path("rustc"))
    parser.add_argument("--git", type=Path, default=Path("git"))
    args = parser.parse_args()
    repository = args.repository.resolve(strict=True)
    output = args.output_dir.resolve()
    if output.exists():
        raise SystemExit(f"baseline output directory already exists: {output}")
    output.mkdir(mode=0o700, parents=True)
    checkout = output / "source"
    target = output / "target"
    environment = {
        **os.environ,
        "CARGO_TARGET_DIR": str(target),
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_SYSTEM": os.devnull,
        "LANG": "C",
        "LC_ALL": "C",
    }
    git = str(args.git)
    cargo = str(args.cargo)
    rustc = str(args.rustc)
    run(
        [git, "clone", "--quiet", "--no-hardlinks", "--no-checkout", str(repository), str(checkout)],
        cwd=output,
        environment=environment,
    )
    run([git, "-C", str(checkout), "checkout", "--quiet", "--detach", REVISION], cwd=output, environment=environment)
    revision = run([git, "-C", str(checkout), "rev-parse", "HEAD"], cwd=output, environment=environment).decode().strip()
    tree = run([git, "-C", str(checkout), "rev-parse", "HEAD^{tree}"], cwd=output, environment=environment).decode().strip()
    if not revision.startswith(REVISION):
        raise SystemExit(f"independent baseline resolved to wrong revision: {revision}")
    if run([git, "-C", str(checkout), "status", "--porcelain=v1", "--untracked-files=all"], cwd=output, environment=environment):
        raise SystemExit("independent baseline checkout is not clean")
    cargo_version = run([cargo, "-V"], cwd=checkout, environment=environment).decode().strip()
    rustc_version = run([rustc, "-Vv"], cwd=checkout, environment=environment).decode().strip()
    rustc_release = next(
        (
            line.partition(":")[2].strip()
            for line in rustc_version.splitlines()
            if line.startswith("release:")
        ),
        None,
    )
    if rustc_release != PINNED_TOOLCHAIN or not cargo_version.startswith(
        f"cargo {PINNED_TOOLCHAIN} "
    ):
        raise SystemExit(
            "baseline toolchain differs from pinned "
            f"{PINNED_TOOLCHAIN}: rustc={rustc_release!r}, cargo={cargo_version!r}"
        )
    run(
        [cargo, "build", "--locked", "--release", "--features", "certificates"],
        cwd=checkout,
        environment=environment,
    )
    binary = (target / "release" / "euf-viper").resolve(strict=True)
    payload = {
        "schema": SCHEMA,
        "status": "built",
        "revision": revision,
        "revision_short": REVISION,
        "tree": tree,
        "checkout": str(checkout.resolve(strict=True)),
        "cargo_lock_sha256": sha256(checkout / "Cargo.lock"),
        "toolchain": {"cargo": cargo_version, "rustc": rustc_version},
        "executable": {
            "bytes": binary.stat().st_size,
            "path": str(binary),
            "sha256": sha256(binary),
        },
    }
    receipt = output / "baseline-build.json"
    descriptor = os.open(
        receipt,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o600,
    )
    try:
        content = canonical(payload)
        os.write(descriptor, content)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    directory = os.open(output, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    print(canonical({
        "binary": str(binary),
        "receipt": str(receipt.resolve(strict=True)),
        "revision": revision,
        "status": "built",
    }).decode(), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
