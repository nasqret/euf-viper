#!/usr/bin/env python3
"""Check out and build the independent ordinary-CLI baseline."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shlex
import subprocess
from pathlib import Path


REVISION = "f8d9205e8a18e3496d236fb9b94ed181add93e80"
REVISION_SHORT = "f8d9205"
SCHEMA = "euf-viper.cli-baseline-build.v2"
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


def run_verbose_build(
    arguments: list[str], *, cwd: Path, environment: dict[str, str]
) -> bytes:
    completed = subprocess.run(
        arguments,
        cwd=cwd,
        env=environment,
        capture_output=True,
        check=False,
    )
    output = completed.stdout + completed.stderr
    if completed.returncode != 0:
        raise SystemExit(
            f"baseline build failed ({completed.returncode}): {arguments!r}\n"
            f"{output.decode('utf-8', 'replace')}"
        )
    return output


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def atomic_create(path: Path, content: bytes, mode: int = 0o600) -> None:
    descriptor = os.open(
        path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode
    )
    try:
        offset = 0
        while offset < len(content):
            offset += os.write(descriptor, content[offset:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def effective_rustc_invocations(build_log: bytes, rustc: Path) -> int:
    expected = str(rustc)
    count = 0
    for raw_line in build_log.decode("utf-8", "strict").splitlines():
        marker = "Running `"
        if marker not in raw_line or not raw_line.endswith("`"):
            continue
        command = shlex.split(raw_line.split(marker, 1)[1][:-1])
        rustc_tokens = [
            token
            for token in command
            if token == expected or Path(token).name in {"rustc", "rustc.exe"}
        ]
        if any(token != expected for token in rustc_tokens):
            raise SystemExit(
                "verbose baseline build invoked a compiler other than supplied RUSTC"
            )
        count += rustc_tokens.count(expected)
    if count == 0:
        raise SystemExit("verbose baseline build recorded no supplied RUSTC invocation")
    return count


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
    cargo_path = args.cargo.resolve(strict=True)
    rustc_path = args.rustc.resolve(strict=True)
    git_path = args.git.resolve(strict=True)
    private_home = output / "home"
    cargo_home = output / "cargo-home"
    temporary = output / "tmp"
    for path in (private_home, cargo_home, temporary):
        path.mkdir(mode=0o700)
    path_entries = list(
        dict.fromkeys(
            [
                str(cargo_path.parent),
                str(rustc_path.parent),
                str(git_path.parent),
                "/usr/bin",
                "/bin",
            ]
        )
    )
    environment = {
        "CARGO_HOME": str(cargo_home),
        "CARGO_INCREMENTAL": "0",
        "CARGO_TARGET_DIR": str(target),
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_SYSTEM": os.devnull,
        "HOME": str(private_home),
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": os.pathsep.join(path_entries),
        "RUSTC": str(rustc_path),
        "TMPDIR": str(temporary),
        "TZ": "UTC",
    }
    git = str(git_path)
    cargo = str(cargo_path)
    rustc = str(rustc_path)
    run(
        [git, "clone", "--quiet", "--no-hardlinks", "--no-checkout", str(repository), str(checkout)],
        cwd=output,
        environment=environment,
    )
    run([git, "-C", str(checkout), "checkout", "--quiet", "--detach", REVISION], cwd=output, environment=environment)
    revision = run([git, "-C", str(checkout), "rev-parse", "HEAD"], cwd=output, environment=environment).decode().strip()
    tree = run([git, "-C", str(checkout), "rev-parse", "HEAD^{tree}"], cwd=output, environment=environment).decode().strip()
    if revision != REVISION:
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
    build_log = run_verbose_build(
        [
            cargo,
            "build",
            "--locked",
            "--release",
            "--features",
            "certificates",
            "-vv",
        ],
        cwd=checkout,
        environment=environment,
    )
    rustc_invocations = effective_rustc_invocations(build_log, rustc_path)
    forbidden_controls = {
        "RUSTC_WRAPPER",
        "RUSTC_WORKSPACE_WRAPPER",
        "RUSTFLAGS",
        "CARGO_ENCODED_RUSTFLAGS",
    }
    if forbidden_controls & environment.keys():
        raise SystemExit("baseline environment retained an ambient Rust build control")
    binary = (target / "release" / "euf-viper").resolve(strict=True)
    build_log_path = output / "baseline-build.log"
    atomic_create(build_log_path, build_log)
    payload = {
        "schema": SCHEMA,
        "status": "built",
        "revision": revision,
        "revision_short": REVISION_SHORT,
        "tree": tree,
        "checkout": str(checkout.resolve(strict=True)),
        "cargo_lock_sha256": sha256(checkout / "Cargo.lock"),
        "toolchain": {"cargo": cargo_version, "rustc": rustc_version},
        "effective_compiler": {
            "path": str(rustc_path),
            "sha256": sha256(rustc_path),
            "version": rustc_version,
            "verbose_invocations": rustc_invocations,
        },
        "build_environment": {key: environment[key] for key in sorted(environment)},
        "build_log": {
            "bytes": len(build_log),
            "path": str(build_log_path.resolve(strict=True)),
            "sha256": hashlib.sha256(build_log).hexdigest(),
        },
        "build_tools": {
            "cargo": {"path": str(cargo_path), "sha256": sha256(cargo_path)},
            "git": {"path": str(git_path), "sha256": sha256(git_path)},
            "rustc": {"path": str(rustc_path), "sha256": sha256(rustc_path)},
        },
        "executable": {
            "bytes": binary.stat().st_size,
            "path": str(binary),
            "sha256": sha256(binary),
        },
    }
    receipt = output / "baseline-build.json"
    atomic_create(receipt, canonical(payload))
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
