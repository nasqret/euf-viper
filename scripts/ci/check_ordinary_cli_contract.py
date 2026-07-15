#!/usr/bin/env python3
"""Compare the ordinary CLI byte-for-byte with an independently built baseline."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import shlex
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CERT_DIR = ROOT / "scripts" / "cert"
if str(CERT_DIR) not in __import__("sys").path:
    __import__("sys").path.insert(0, str(CERT_DIR))
if str(Path(__file__).resolve().parent) not in __import__("sys").path:
    __import__("sys").path.insert(0, str(Path(__file__).resolve().parent))

from ordinary_cli_cases import cases as ordinary_cli_cases  # noqa: E402
from strict_artifacts import (  # noqa: E402
    StrictArtifactError,
    open_verified_sealed_memfd,
    read_regular_nofollow,
    strict_json_loads,
)


BASELINE_REVISION = "f8d9205e8a18e3496d236fb9b94ed181add93e80"
BASELINE_REVISION_SHORT = "f8d9205"
BASELINE_TREE = "c568afb1760f7f8a74fb6aceae58de6749683e5c"
BASELINE_CARGO_LOCK_SHA256 = (
    "66c19c2bdd228d51c2c2d6f31822125b3ce1d8cb1f8f34e03bdec65a5bbfa52f"
)
PINNED_TOOLCHAIN = "1.96.0"
HEX_DIGITS = frozenset("0123456789abcdef")


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


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
                "baseline build log records a compiler other than supplied RUSTC"
            )
        count += rustc_tokens.count(expected)
    if count == 0:
        raise SystemExit("baseline build log records no supplied RUSTC invocation")
    return count


def execute(
    descriptor: int, root: Path, arguments: list[str], stdin: bytes = b""
) -> subprocess.CompletedProcess[bytes]:
    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("EUF_VIPER_")
    }
    environment.update({"LANG": "C", "LC_ALL": "C"})
    return subprocess.run(
        [f"/proc/self/fd/{descriptor}", *arguments],
        cwd=root,
        input=stdin,
        capture_output=True,
        check=False,
        env=environment,
        pass_fds=(descriptor,),
    )


def result(completed: subprocess.CompletedProcess[bytes]) -> tuple[int, bytes, bytes]:
    return completed.returncode, completed.stdout, completed.stderr


def verify_baseline_receipt(receipt: Path, binary: Path) -> dict[str, object]:
    raw = receipt.read_bytes()
    try:
        value = json.loads(raw)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise SystemExit(f"invalid baseline build receipt: {error}") from error
    canonical = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
    if raw != canonical:
        raise SystemExit("baseline build receipt is not canonical JSON")
    expected_keys = {
        "schema",
        "status",
        "revision",
        "revision_short",
        "tree",
        "checkout",
        "cargo_lock_sha256",
        "toolchain",
        "effective_compiler",
        "build_environment",
        "build_log",
        "build_tools",
        "executable",
    }
    if type(value) is not dict or set(value) != expected_keys:
        raise SystemExit("baseline build receipt keys differ")
    if (
        value["schema"] != "euf-viper.cli-baseline-build.v2"
        or value["status"] != "built"
    ):
        raise SystemExit("baseline build receipt schema mismatch")
    revision = value["revision"]
    tree = value["tree"]
    if (
        value["revision_short"] != BASELINE_REVISION_SHORT
        or type(revision) is not str
        or revision != BASELINE_REVISION
        or len(revision) not in {40, 64}
        or any(character not in HEX_DIGITS for character in revision)
        or type(tree) is not str
        or tree != BASELINE_TREE
    ):
        raise SystemExit("baseline build receipt is not for f8d9205")
    if value["cargo_lock_sha256"] != BASELINE_CARGO_LOCK_SHA256:
        raise SystemExit("baseline Cargo.lock binding differs from f8d9205")
    toolchain = value["toolchain"]
    if (
        type(toolchain) is not dict
        or set(toolchain) != {"cargo", "rustc"}
        or not str(toolchain["cargo"]).startswith(f"cargo {PINNED_TOOLCHAIN} ")
        or f"release: {PINNED_TOOLCHAIN}" not in str(toolchain["rustc"])
    ):
        raise SystemExit("baseline toolchain differs from the pinned release")
    compiler = value["effective_compiler"]
    if (
        type(compiler) is not dict
        or set(compiler) != {"path", "sha256", "verbose_invocations", "version"}
        or compiler["version"] != toolchain["rustc"]
        or type(compiler["path"]) is not str
        or type(compiler["sha256"]) is not str
        or len(compiler["sha256"]) != 64
        or type(compiler["verbose_invocations"]) is not int
        or compiler["verbose_invocations"] < 1
    ):
        raise SystemExit("baseline effective compiler binding is malformed")
    compiler_path = Path(compiler["path"]).resolve(strict=True)
    if sha256(compiler_path) != compiler["sha256"]:
        raise SystemExit("baseline effective compiler bytes drifted")
    build_environment = value["build_environment"]
    expected_environment_keys = {
        "CARGO_HOME",
        "CARGO_INCREMENTAL",
        "CARGO_NET_GIT_FETCH_WITH_CLI",
        "CARGO_TARGET_DIR",
        "GIT_CONFIG_GLOBAL",
        "GIT_CONFIG_NOSYSTEM",
        "GIT_CONFIG_SYSTEM",
        "HOME",
        "LANG",
        "LC_ALL",
        "PATH",
        "RUSTC",
        "RUSTUP_TOOLCHAIN",
        "TMPDIR",
        "TZ",
    }
    if (
        type(build_environment) is not dict
        or set(build_environment) != expected_environment_keys
        or build_environment.get("RUSTC") != compiler["path"]
        or build_environment.get("RUSTUP_TOOLCHAIN") != PINNED_TOOLCHAIN
        or any(
            key in build_environment
            for key in (
                "RUSTC_WRAPPER",
                "RUSTC_WORKSPACE_WRAPPER",
                "RUSTFLAGS",
                "CARGO_ENCODED_RUSTFLAGS",
            )
        )
    ):
        raise SystemExit("baseline build environment did not force a clean RUSTC")
    build_log = value["build_log"]
    if type(build_log) is not dict or set(build_log) != {"bytes", "path", "sha256"}:
        raise SystemExit("baseline verbose build log binding is malformed")
    build_log_path = Path(str(build_log["path"])).resolve(strict=True)
    build_log_bytes = build_log_path.read_bytes()
    if (
        build_log.get("bytes") != len(build_log_bytes)
        or build_log.get("sha256")
        != hashlib.sha256(build_log_bytes).hexdigest()
    ):
        raise SystemExit("baseline verbose build log bytes drifted")
    if effective_rustc_invocations(build_log_bytes, compiler_path) != compiler[
        "verbose_invocations"
    ]:
        raise SystemExit("baseline effective compiler invocation count differs")
    tools = value["build_tools"]
    if type(tools) is not dict or set(tools) != {"cargo", "git", "rustc"}:
        raise SystemExit("baseline build tool set differs")
    for name, item in tools.items():
        if type(item) is not dict or set(item) != {"path", "sha256"}:
            raise SystemExit(f"baseline build tool {name} binding is malformed")
        tool_path = Path(str(item["path"])).resolve(strict=True)
        if item["sha256"] != sha256(tool_path):
            raise SystemExit(f"baseline build tool {name} bytes drifted")
    if tools["rustc"] != {"path": compiler["path"], "sha256": compiler["sha256"]}:
        raise SystemExit("baseline build tool and effective compiler disagree")
    executable = value["executable"]
    if not isinstance(executable, dict) or set(executable) != {"bytes", "path", "sha256"}:
        raise SystemExit("baseline receipt lacks an executable binding")
    if Path(str(executable.get("path"))).resolve(strict=True) != binary:
        raise SystemExit("baseline executable path differs from its build receipt")
    if executable.get("sha256") != sha256(binary):
        raise SystemExit("baseline executable SHA-256 differs from its build receipt")
    if executable.get("bytes") != binary.stat().st_size:
        raise SystemExit("baseline executable size differs from its build receipt")
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--baseline-binary", type=Path, required=True)
    parser.add_argument("--baseline-receipt", type=Path, required=True)
    parser.add_argument("--oracle", type=Path, required=True)
    parser.add_argument("--repository", type=Path, required=True)
    args = parser.parse_args()
    root = args.repository.resolve(strict=True)
    binary = args.binary.resolve(strict=True)
    baseline = args.baseline_binary.resolve(strict=True)
    if binary == baseline or sha256(binary) == sha256(baseline):
        raise SystemExit("candidate and independent baseline must be distinct build artifacts")
    baseline_receipt = args.baseline_receipt.resolve(strict=True)
    verify_baseline_receipt(baseline_receipt, baseline)
    try:
        _, oracle_raw = read_regular_nofollow(
            args.oracle.resolve(strict=True), "ordinary CLI oracle"
        )
        oracle = strict_json_loads(oracle_raw.decode("ascii"), "ordinary CLI oracle")
    except (OSError, UnicodeError, StrictArtifactError) as error:
        raise SystemExit(f"invalid ordinary CLI oracle: {error}") from error
    canonical_oracle = (
        json.dumps(oracle, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()
    if oracle_raw != canonical_oracle or type(oracle) is not dict or set(oracle) != {
        "baseline",
        "cases",
        "schema",
        "status",
    }:
        raise SystemExit("ordinary CLI oracle is not canonical or has wrong keys")
    baseline_binding = oracle["baseline"]
    if (
        oracle["schema"] != "euf-viper.ordinary-cli-oracle.v1"
        or oracle["status"] != "recorded"
        or type(baseline_binding) is not dict
        or baseline_binding
        != {
            "bytes": baseline.stat().st_size,
            "receipt_sha256": sha256(baseline_receipt),
            "sha256": sha256(baseline),
        }
    ):
        raise SystemExit("ordinary CLI oracle baseline binding differs")
    expected_cases = ordinary_cli_cases(root)
    if type(oracle["cases"]) is not list or len(oracle["cases"]) != len(expected_cases):
        raise SystemExit("ordinary CLI oracle case count differs")
    candidate_sha256 = sha256(binary)
    try:
        descriptor = open_verified_sealed_memfd(
            binary, candidate_sha256, "ordinary CLI candidate"
        )
    except StrictArtifactError as error:
        raise SystemExit(str(error)) from error
    try:
        for record_value, (label, arguments, stdin) in zip(
            oracle["cases"], expected_cases, strict=True
        ):
            if type(record_value) is not dict or set(record_value) != {
                "arguments",
                "label",
                "result",
                "stdin_base64",
                "stdin_sha256",
            }:
                raise SystemExit("ordinary CLI oracle case keys differ")
            if (
                record_value["label"] != label
                or record_value["arguments"] != arguments
                or base64.b64decode(record_value["stdin_base64"], validate=True) != stdin
                or record_value["stdin_sha256"] != hashlib.sha256(stdin).hexdigest()
            ):
                raise SystemExit(f"ordinary CLI oracle input differs for {label}")
            expected_result = record_value["result"]
            if type(expected_result) is not dict or set(expected_result) != {
                "exit_code",
                "stderr_base64",
                "stdout_base64",
            }:
                raise SystemExit(f"ordinary CLI oracle result differs for {label}")
            expected = (
                expected_result["exit_code"],
                base64.b64decode(expected_result["stdout_base64"], validate=True),
                base64.b64decode(expected_result["stderr_base64"], validate=True),
            )
            actual = result(execute(descriptor, root, arguments, stdin))
            if actual != expected:
                raise SystemExit(
                    f"{label} differs from independently recorded f8d9205:\n"
                    f"  baseline code/stdout/stderr={expected!r}\n"
                    f"  candidate code/stdout/stderr={actual!r}"
                )
    except (ValueError, TypeError, base64.binascii.Error) as error:
        raise SystemExit(f"ordinary CLI oracle encoding is invalid: {error}") from error
    finally:
        os.close(descriptor)
    print("ordinary CLI matches independently built f8d9205 byte-for-byte")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
