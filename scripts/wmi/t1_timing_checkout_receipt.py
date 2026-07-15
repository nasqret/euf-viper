#!/usr/bin/env python3
"""Create a canonical fail-closed receipt for a pristine T1 checkout."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
from pathlib import Path


RUNTIME_PATHS = (
    "Cargo.lock",
    "Cargo.toml",
    "campaigns/t1-typed-parser-timing-v1.json",
    "results/wmi/typed-parser-parity-146510/audit.json",
    "results/wmi/typed-parser-parity-146510/prepare.json",
    "results/wmi/typed-parser-parity-146510/preflight.json",
    "results/wmi/typed-parser-parity-146510/receipt.json",
    "results/wmi/typed-parser-parity-146510/submission.json",
    "results/wmi/typed-parser-parity-146510/typed-parser-parity-20260713T221314Z-66099-independent.json",
    "scripts/bench/typed_parser_timing.py",
    "scripts/wmi/t1_timing_build_guard.py",
    "scripts/wmi/t1_timing_checkout_receipt.py",
    "scripts/wmi/t1_timing_common.sh",
    "scripts/wmi/t1_timing_remote_submit.py",
    "scripts/wmi/euf_viper_t1_timing_prepare.sbatch",
    "scripts/wmi/euf_viper_t1_timing_array.sbatch",
    "scripts/wmi/euf_viper_t1_timing_audit.sbatch",
    "scripts/wmi/submit_t1_timing.sh",
    "src/main.rs",
    "src/smt2_stream.rs",
)


def git(repo: Path, *args: str) -> bytes:
    env = {
        "HOME": str(Path.home()),
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
    }
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
    ).stdout


def reject_cargo_configs(repo: Path) -> None:
    candidates: set[Path] = set()
    for parent in (repo, *repo.parents):
        candidates.update(
            (parent / ".cargo" / "config", parent / ".cargo" / "config.toml")
        )
    candidates.update(
        (Path.home() / ".cargo" / "config", Path.home() / ".cargo" / "config.toml")
    )
    candidates.update((Path("/.cargo/config"), Path("/.cargo/config.toml")))
    present = sorted(str(path) for path in candidates if path.exists())
    if present:
        raise SystemExit(f"cargo configuration can influence build: {present}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--published-ref", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    repo = args.repository.resolve(strict=True)
    revision = git(repo, "rev-parse", "--verify", "HEAD^{commit}").decode().strip()
    published = (
        git(repo, "rev-parse", "--verify", f"{args.published_ref}^{{commit}}")
        .decode()
        .strip()
    )
    if revision != args.revision or published != revision or len(revision) != 40:
        raise SystemExit("checkout, expected revision, and published ref differ")
    status = git(repo, "status", "--porcelain=v1", "--untracked-files=all")
    ignored = git(repo, "ls-files", "--others", "--ignored", "--exclude-standard")
    if status:
        raise SystemExit(f"checkout contains tracked or untracked influence: {status[:512]!r}")
    if ignored:
        raise SystemExit(f"checkout contains ignored influence: {ignored[:512]!r}")
    abnormal = [
        line
        for line in git(repo, "ls-files", "-v").decode().splitlines()
        if not line.startswith("H ")
    ]
    if abnormal:
        raise SystemExit(f"checkout has hidden index flags: {abnormal[:4]}")
    reject_cargo_configs(repo)
    blobs: dict[str, dict[str, str]] = {}
    for path in RUNTIME_PATHS:
        fields = git(repo, "ls-tree", revision, "--", path).decode().strip().split()
        if len(fields) != 4 or fields[1] != "blob" or fields[3] != path:
            raise SystemExit(f"runtime path is not a committed blob: {path}")
        actual = git(repo, "hash-object", "--no-filters", "--", path).decode().strip()
        if actual != fields[2]:
            raise SystemExit(f"runtime blob differs from revision: {path}")
        blobs[path] = {"blob": fields[2], "mode": fields[0]}
    payload = {
        "cargo_configs": [],
        "ignored_sha256": hashlib.sha256(ignored).hexdigest(),
        "published_ref": args.published_ref,
        "repository": str(repo),
        "revision": revision,
        "runtime_blobs": blobs,
        "schema": "euf-viper.t1-clean-checkout-receipt.v1",
        "status_sha256": hashlib.sha256(status).hexdigest(),
        "tree": git(repo, "rev-parse", f"{revision}^{{tree}}").decode().strip(),
    }
    rendered = json.dumps(
        payload, allow_nan=False, separators=(",", ":"), sort_keys=True
    )
    content = (rendered + "\n").encode("ascii")
    descriptor = os.open(
        args.output,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o400,
    )
    try:
        offset = 0
        while offset < len(content):
            written = os.write(descriptor, content[offset:])
            if written <= 0:
                raise SystemExit("short checkout receipt write")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    directory = os.open(args.output.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
