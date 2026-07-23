#!/usr/bin/env python3
"""Build a source-family-disjoint, provenance-bound Rust PGO binary."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import math
import os
import platform
import re
import shutil
import stat
import subprocess
import tempfile
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Sequence


SCRIPT_DIR = Path(__file__).resolve().parent
SPLITTER_SPEC = importlib.util.spec_from_file_location(
    "euf_viper_build_pgo_split", SCRIPT_DIR / "build_pgo_split.py"
)
assert SPLITTER_SPEC is not None and SPLITTER_SPEC.loader is not None
SPLITTER = importlib.util.module_from_spec(SPLITTER_SPEC)
SPLITTER_SPEC.loader.exec_module(SPLITTER)

SCHEMA_VERSION = "euf-viper.rust-pgo.v1"
SOLVER_ENV_RE = re.compile(r"EUF_VIPER_[A-Z0-9_]+\Z")
RUSTC_LLVM_VERSION_RE = re.compile(r"(?m)^LLVM version:\s*([0-9]+(?:\.[0-9]+)+)\s*$")
PROFDATA_LLVM_VERSION_RE = re.compile(
    r"(?m)^[ \t]*(?:Apple )?LLVM version\s+([0-9]+(?:\.[0-9]+)+)(?![0-9.])"
)
RESERVED_ENV = frozenset(
    {
        "CARGO_BUILD_TARGET",
        "CARGO_ENCODED_RUSTFLAGS",
        "CARGO_INCREMENTAL",
        "CARGO_TARGET_DIR",
        "LLVM_PROFILE_FILE",
        "RUSTC",
        "RUSTC_BOOTSTRAP",
        "RUSTC_WRAPPER",
        "RUSTC_WORKSPACE_WRAPPER",
        "RUSTFLAGS",
    }
)
RESERVED_PREFIXES = ("CARGO_PROFILE_",)


class PgoError(RuntimeError):
    """Raised when a PGO artifact cannot be built without ambiguity."""


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def decode_output(data: bytes) -> str:
    return data.decode("utf-8", errors="replace")


def output_summary(data: bytes, *, tail_bytes: int = 16_384) -> dict[str, Any]:
    return {
        "bytes": len(data),
        "sha256": sha256_bytes(data),
        "tail": decode_output(data[-tail_bytes:]),
        "truncated": len(data) > tail_bytes,
    }


def parse_solver_env(values: Sequence[str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for value in values:
        if "=" not in value:
            raise PgoError(f"solver environment assignment lacks '=': {value!r}")
        key, setting = value.split("=", 1)
        if not SOLVER_ENV_RE.fullmatch(key):
            raise PgoError(
                f"solver environment key must match EUF_VIPER_[A-Z0-9_]+: {key!r}"
            )
        if key in result:
            raise PgoError(f"solver environment key is repeated: {key}")
        result[key] = setting
    return result


def reject_ambient_build_overrides(environment: Mapping[str, str]) -> None:
    rejected = sorted(
        key
        for key in environment
        if key in RESERVED_ENV or key.startswith(RESERVED_PREFIXES)
    )
    if rejected:
        raise PgoError(
            "ambient build overrides are forbidden; unset " + ", ".join(rejected)
        )


def resolve_program(value: str, label: str) -> Path:
    if "/" in value or (os.altsep and os.altsep in value):
        candidate = Path(os.path.abspath(Path(value).expanduser()))
        if not candidate.is_file() or not os.access(candidate, os.X_OK):
            raise PgoError(f"{label} is not an executable file: {candidate}")
        return candidate
    found = shutil.which(value)
    if found is None:
        raise PgoError(f"cannot find {label} executable {value!r} on PATH")
    # rustup is a basename-dispatched multicall shim. Keep the rustc/cargo
    # symlink name instead of resolving it to the underlying rustup binary.
    return Path(os.path.abspath(found))


def run_process(
    command: Sequence[str | Path],
    *,
    cwd: Path,
    environment: Mapping[str, str],
    timeout: float,
) -> tuple[subprocess.CompletedProcess[bytes], dict[str, Any]]:
    rendered = [str(item) for item in command]
    started = time.monotonic_ns()
    try:
        completed = subprocess.run(
            rendered,
            cwd=cwd,
            env=dict(environment),
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
        )
    except OSError as error:
        raise PgoError(f"cannot execute command {rendered!r}: {error}") from error
    except subprocess.TimeoutExpired as error:
        stdout = error.stdout or b""
        stderr = error.stderr or b""
        raise PgoError(
            f"command timed out after {timeout:.3f}s: {rendered!r}; "
            f"stderr tail: {decode_output(stderr[-4096:])!r}; "
            f"stdout tail: {decode_output(stdout[-4096:])!r}"
        ) from error
    elapsed_ns = time.monotonic_ns() - started
    record = {
        "command": rendered,
        "cwd": str(cwd),
        "elapsed_ns": elapsed_ns,
        "returncode": completed.returncode,
        "stderr": output_summary(completed.stderr),
        "stdout": output_summary(completed.stdout),
    }
    return completed, record


def require_success(
    command: Sequence[str | Path],
    *,
    cwd: Path,
    environment: Mapping[str, str],
    timeout: float,
    label: str,
) -> dict[str, Any]:
    completed, record = run_process(
        command, cwd=cwd, environment=environment, timeout=timeout
    )
    if completed.returncode != 0:
        raise PgoError(
            f"{label} failed with exit {completed.returncode}: "
            f"{record['stderr']['tail']!r}"
        )
    return record


def command_text(
    command: Sequence[str | Path],
    *,
    cwd: Path,
    environment: Mapping[str, str],
    timeout: float = 30.0,
) -> str:
    completed, record = run_process(
        command, cwd=cwd, environment=environment, timeout=timeout
    )
    if completed.returncode != 0:
        raise PgoError(
            f"command failed while collecting provenance: {record['command']!r}: "
            f"{record['stderr']['tail']!r}"
        )
    return decode_output(completed.stdout).strip()


def git_provenance(
    repository: Path, environment: Mapping[str, str], *, allow_dirty: bool
) -> dict[str, Any]:
    git = resolve_program("git", "git")
    root = Path(
        command_text(
            [git, "rev-parse", "--show-toplevel"],
            cwd=repository,
            environment=environment,
        )
    ).resolve()
    if root != repository:
        raise PgoError(f"repository root mismatch: requested {repository}, git reports {root}")
    head = command_text(
        [git, "rev-parse", "HEAD"], cwd=repository, environment=environment
    )
    commit_timestamp = command_text(
        [git, "show", "-s", "--format=%ct", "HEAD"],
        cwd=repository,
        environment=environment,
    )
    status_bytes = subprocess.run(
        [str(git), "status", "--porcelain=v1", "-z", "--untracked-files=all"],
        cwd=repository,
        env=dict(environment),
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).stdout
    dirty = bool(status_bytes)
    if dirty and not allow_dirty:
        preview = decode_output(status_bytes.replace(b"\0", b"\n"))[:4096]
        raise PgoError(f"repository is dirty; commit or pass --allow-dirty:\n{preview}")
    diff = subprocess.run(
        [str(git), "diff", "--binary", "--no-ext-diff", "HEAD", "--"],
        cwd=repository,
        env=dict(environment),
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).stdout
    return {
        "allow_dirty": allow_dirty,
        "commit_timestamp": int(commit_timestamp),
        "dirty": dirty,
        "head": head,
        "promotable": not dirty,
        "root": str(root),
        "tracked_diff_sha256": sha256_bytes(diff),
        "tracked_diff_bytes": len(diff),
        "status_sha256": sha256_bytes(status_bytes),
        "status": decode_output(status_bytes.replace(b"\0", b"\n")).splitlines(),
    }


def load_split_report(path: Path, training_manifest_sha256: str) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
        report = SPLITTER.strict_json_loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, ValueError, json.JSONDecodeError) as error:
        raise PgoError(f"cannot read strict split report {path}: {error}") from error
    if type(report) is not dict:
        raise PgoError("split report is not a JSON object")
    if SPLITTER.canonical_json_bytes(report) != raw:
        raise PgoError("split report is not canonical JSON generated by build_pgo_split.py")
    if report.get("schema_version") != SPLITTER.SCHEMA_VERSION:
        raise PgoError("split report schema version is unsupported")
    if report.get("family_disjoint") is not True:
        raise PgoError("split report does not certify family disjointness")
    try:
        reported_training_hash = report["outputs"]["training_manifest_sha256"]
        training = report["families"]["training"]
        holdout = report["families"]["holdout"]
        training_count = report["counts"]["training"]
    except (KeyError, TypeError) as error:
        raise PgoError(f"split report lacks a required field: {error}") from error
    if reported_training_hash != training_manifest_sha256:
        raise PgoError("training manifest hash does not match the split report")
    for label, families in (("training", training), ("holdout", holdout)):
        if (
            type(families) is not list
            or any(type(family) is not str or not family for family in families)
            or families != sorted(set(families))
        ):
            raise PgoError(f"split report {label} families are not unique and sorted")
    if set(training).intersection(holdout):
        raise PgoError("split report leaks a source family across train and holdout")
    if type(training_count) is not int or training_count < 1:
        raise PgoError("split report training count is invalid")
    return {"raw_sha256": sha256_bytes(raw), "report": report}


def validate_training_sources(
    rows: Sequence[dict[str, Any]], source_root: Path
) -> list[dict[str, Any]]:
    try:
        root = source_root.resolve(strict=True)
    except OSError as error:
        raise PgoError(f"cannot resolve source root {source_root}: {error}") from error
    if not root.is_dir():
        raise PgoError(f"source root is not a directory: {root}")

    seen_physical: set[tuple[int, int]] = set()
    validated: list[dict[str, Any]] = []
    for ordinal, row in enumerate(rows):
        relative_path = row["relative_path"]
        parts = PurePosixPath(relative_path).parts
        candidate = root.joinpath(*parts)
        try:
            resolved = candidate.resolve(strict=True)
            resolved.relative_to(root)
        except (OSError, ValueError) as error:
            raise PgoError(
                f"training source {relative_path!r} is missing or escapes source root"
            ) from error
        if not resolved.is_file():
            raise PgoError(f"training source is not a regular file: {resolved}")
        metadata = resolved.stat()
        identity = (metadata.st_dev, metadata.st_ino)
        if identity in seen_physical:
            raise PgoError(f"training sources alias the same physical file: {resolved}")
        seen_physical.add(identity)
        actual_size = metadata.st_size
        if actual_size != row["bytes"]:
            raise PgoError(
                f"training source size drift for {relative_path}: "
                f"manifest={row['bytes']} actual={actual_size}"
            )
        actual_hash = sha256_file(resolved)
        if actual_hash != row["sha256"]:
            raise PgoError(f"training source SHA-256 drift for {relative_path}")
        validated.append(
            {
                "bytes": actual_size,
                "expected": row["status"],
                "family": SPLITTER.family_of(relative_path),
                "id": row["id"],
                "ordinal": ordinal,
                "relative_path": relative_path,
                "resolved_path": str(resolved),
                "sha256": actual_hash,
            }
        )
    return validated


def classify_solver_output(
    completed: subprocess.CompletedProcess[bytes],
    expected: str,
    *,
    allow_unknown: bool = False,
) -> str:
    if completed.returncode != 0:
        raise PgoError(f"solver exited with code {completed.returncode}")
    lines = [line.strip() for line in decode_output(completed.stdout).splitlines() if line.strip()]
    if len(lines) != 1 or lines[0] not in {"sat", "unsat", "unknown"}:
        actual = lines[0] if len(lines) == 1 else repr(lines)
        raise PgoError(f"solver output is not one exact SMT status: {actual}")
    actual = lines[0]
    if actual != expected and not (allow_unknown and actual == "unknown"):
        raise PgoError(f"solver result mismatch: expected {expected}, got {actual}")
    return actual


def ensure_output_contract(
    output_root: Path, binary_out: Path, report_out: Path
) -> None:
    if binary_out == report_out:
        raise PgoError("binary and report outputs must be distinct")
    if binary_out.exists() or binary_out.is_symlink():
        raise PgoError(f"binary output already exists: {binary_out}")
    if report_out.exists() or report_out.is_symlink():
        raise PgoError(f"report output already exists: {report_out}")
    for label, path in (("binary", binary_out), ("report", report_out)):
        if path == output_root:
            raise PgoError(f"{label} output must not be the output root itself")
        try:
            relative = path.relative_to(output_root)
        except ValueError:
            continue
        if relative.parts and (
            relative.parts[0] in {"generate", "raw", "use"}
            or relative == Path("merged.profdata")
        ):
            raise PgoError(f"{label} output collides with internal PGO state: {path}")
    if output_root.exists():
        if not output_root.is_dir():
            raise PgoError(f"output root is not a directory: {output_root}")
        if any(output_root.iterdir()):
            raise PgoError(f"output root is not empty: {output_root}")


def locate_llvm_profdata(
    explicit: str | None,
    *,
    rustc: Path,
    repository: Path,
    environment: Mapping[str, str],
) -> Path:
    if explicit is not None:
        return resolve_program(explicit, "llvm-profdata")
    sysroot = Path(
        command_text(
            [rustc, "--print", "sysroot"],
            cwd=repository,
            environment=environment,
        )
    )
    host = ""
    for line in command_text(
        [rustc, "-vV"], cwd=repository, environment=environment
    ).splitlines():
        if line.startswith("host: "):
            host = line.removeprefix("host: ")
            break
    if host:
        candidate = sysroot / "lib" / "rustlib" / host / "bin" / "llvm-profdata"
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return candidate.resolve()
    found = shutil.which("llvm-profdata")
    if found is not None:
        return Path(found).resolve()
    xcrun = shutil.which("xcrun")
    if xcrun is not None:
        completed = subprocess.run(
            [xcrun, "--find", "llvm-profdata"],
            cwd=repository,
            env=dict(environment),
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if completed.returncode == 0:
            candidate = Path(decode_output(completed.stdout).strip()).resolve()
            if candidate.is_file() and os.access(candidate, os.X_OK):
                return candidate
    raise PgoError(
        "cannot find llvm-profdata; install llvm-tools-preview or pass --llvm-profdata"
    )


def require_matching_llvm(
    rustc_version: str, llvm_profdata_version: str
) -> str:
    rustc_match = RUSTC_LLVM_VERSION_RE.search(rustc_version)
    profdata_match = PROFDATA_LLVM_VERSION_RE.search(llvm_profdata_version)
    if rustc_match is None:
        raise PgoError("rustc -vV did not report a canonical LLVM version")
    if profdata_match is None:
        raise PgoError("llvm-profdata --version did not report a canonical LLVM version")
    rustc_llvm = rustc_match.group(1)
    profdata_llvm = profdata_match.group(1)
    if rustc_llvm != profdata_llvm:
        raise PgoError(
            "llvm-profdata is incompatible with rustc: "
            f"rustc LLVM {rustc_llvm}, llvm-profdata LLVM {profdata_llvm}"
        )
    return rustc_llvm


def cargo_build_command(cargo: Path, repository: Path) -> list[str | Path]:
    return [
        cargo,
        "build",
        "--manifest-path",
        repository / "Cargo.toml",
        "--release",
        "--features",
        "fabric",
        "--locked",
    ]


def build_environment(
    base: Mapping[str, str],
    *,
    rustc: Path,
    target: Path,
    rustflags: Sequence[str],
    source_date_epoch: int,
) -> dict[str, str]:
    result = dict(base)
    result.update(
        {
            "CARGO_ENCODED_RUSTFLAGS": "\x1f".join(rustflags),
            "CARGO_INCREMENTAL": "0",
            "CARGO_TARGET_DIR": str(target),
            "CARGO_TERM_COLOR": "never",
            "RUSTC": str(rustc),
            "SOURCE_DATE_EPOCH": str(source_date_epoch),
        }
    )
    return result


def run_solver(
    binary: Path,
    source: Mapping[str, Any],
    *,
    environment: Mapping[str, str],
    timeout: float,
    expected: str | None = None,
    allow_unknown: bool = False,
) -> dict[str, Any]:
    completed, record = run_process(
        [binary, "fabric-solve", "--engine", "cadical-up", source["resolved_path"]],
        cwd=binary.parent,
        environment=environment,
        timeout=timeout,
    )
    try:
        required = source["expected"] if expected is None else expected
        actual = classify_solver_output(
            completed, required, allow_unknown=allow_unknown
        )
    except PgoError as error:
        raise PgoError(f"{source['relative_path']}: {error}") from error
    record.update(
        {
            "actual": actual,
            "expected": required,
            "manifest_expected": source["expected"],
            "id": source["id"],
            "relative_path": source["relative_path"],
        }
    )
    return record


def stage_binary(path: Path, source: Path) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    os.close(descriptor)
    try:
        shutil.copyfile(source, temporary)
        with open(temporary, "r+b") as staged:
            os.fsync(staged.fileno())
        os.chmod(temporary, stat.S_IMODE(source.stat().st_mode))
        return temporary
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def publish_artifacts(
    binary_source: Path,
    binary_out: Path,
    report_out: Path,
    report_data: bytes,
) -> None:
    binary_temp: str | None = None
    report_temp: str | None = None
    try:
        binary_temp = stage_binary(binary_out, binary_source)
        report_temp = SPLITTER.stage_file(report_out, report_data)
        os.replace(binary_temp, binary_out)
        binary_temp = None
        # The report is the commit marker and is always published last.
        os.replace(report_temp, report_out)
        report_temp = None
    finally:
        for temporary in (binary_temp, report_temp):
            if temporary is not None:
                try:
                    os.unlink(temporary)
                except FileNotFoundError:
                    pass


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("training_manifest", type=Path)
    parser.add_argument("--split-report", type=Path, required=True)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--repository", type=Path, default=Path.cwd())
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--binary-out", type=Path, required=True)
    parser.add_argument("--report-out", type=Path, required=True)
    parser.add_argument("--cargo", default="cargo")
    parser.add_argument("--rustc", default="rustc")
    parser.add_argument("--llvm-profdata")
    parser.add_argument("--training-repeats", type=int, default=1)
    parser.add_argument("--solver-timeout", type=float, default=120.0)
    parser.add_argument("--build-timeout", type=float, default=1800.0)
    parser.add_argument("--solver-env", action="append", default=[])
    parser.add_argument(
        "--allow-unknown-training",
        action="store_true",
        help=(
            "profile exact unknown outcomes but still reject wrong decisive answers; "
            "the optimized binary must reproduce each outcome"
        ),
    )
    parser.add_argument("--allow-dirty", action="store_true")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    if args.training_repeats < 1:
        raise PgoError("training repeats must be positive")
    if (
        not math.isfinite(args.solver_timeout)
        or not math.isfinite(args.build_timeout)
        or args.solver_timeout <= 0
        or args.build_timeout <= 0
    ):
        raise PgoError("timeouts must be positive and finite")

    repository = args.repository.resolve()
    output_root = args.output_root.resolve()
    binary_out = args.binary_out.resolve()
    report_out = args.report_out.resolve()
    training_manifest = args.training_manifest.resolve()
    split_report_path = args.split_report.resolve()
    source_root = args.source_root.resolve()
    if training_manifest in {binary_out, report_out} or split_report_path in {
        binary_out,
        report_out,
    }:
        raise PgoError("published outputs must not overwrite input contracts")

    reject_ambient_build_overrides(os.environ)
    solver_env = parse_solver_env(args.solver_env)
    ensure_output_contract(output_root, binary_out, report_out)

    base_environment = dict(os.environ)
    cargo = resolve_program(args.cargo, "cargo")
    rustc = resolve_program(args.rustc, "rustc")
    git = git_provenance(repository, base_environment, allow_dirty=args.allow_dirty)
    llvm_profdata = locate_llvm_profdata(
        args.llvm_profdata,
        rustc=rustc,
        repository=repository,
        environment=base_environment,
    )
    cargo_version = command_text(
        [cargo, "-Vv"], cwd=repository, environment=base_environment
    )
    rustc_version = command_text(
        [rustc, "-vV"], cwd=repository, environment=base_environment
    )
    llvm_profdata_version = command_text(
        [llvm_profdata, "--version"],
        cwd=repository,
        environment=base_environment,
    )
    llvm_version = require_matching_llvm(rustc_version, llvm_profdata_version)

    rows, training_manifest_sha256 = SPLITTER.load_manifest(training_manifest)
    split = load_split_report(split_report_path, training_manifest_sha256)
    if split["report"]["counts"]["training"] != len(rows):
        raise PgoError("training manifest row count does not match split report")
    sources = validate_training_sources(rows, source_root)
    actual_training_families = sorted({source["family"] for source in sources})
    if actual_training_families != split["report"]["families"]["training"]:
        raise PgoError("training manifest families do not match split report")
    actual_family_counts = dict(
        sorted(Counter(source["family"] for source in sources).items())
    )
    if actual_family_counts != split["report"]["families"]["training_selected_counts"]:
        raise PgoError("training manifest family counts do not match split report")

    output_root.mkdir(parents=True, exist_ok=True)
    raw_directory = output_root / "raw"
    generation_target = output_root / "generate"
    use_target = output_root / "use"
    raw_directory.mkdir()

    build_command = cargo_build_command(cargo, repository)
    generation_flags = [f"-Cprofile-generate={raw_directory}"]
    generation_environment = build_environment(
        base_environment,
        rustc=rustc,
        target=generation_target,
        rustflags=generation_flags,
        source_date_epoch=git["commit_timestamp"],
    )
    generation_environment["LLVM_PROFILE_FILE"] = str(
        raw_directory / "build-%m-%p.profraw"
    )
    generation_build = require_success(
        build_command,
        cwd=repository,
        environment=generation_environment,
        timeout=args.build_timeout,
        label="instrumented Cargo build",
    )
    executable_name = "euf-viper.exe" if os.name == "nt" else "euf-viper"
    generation_binary = generation_target / "release" / executable_name
    if not generation_binary.is_file():
        raise PgoError(f"instrumented binary was not produced: {generation_binary}")

    training_runs: list[dict[str, Any]] = []
    training_outcomes: dict[str, str] = {}
    run_ordinal = 0
    for repeat in range(args.training_repeats):
        for source in sources:
            before = set(raw_directory.glob("train-*.profraw"))
            environment = dict(base_environment)
            environment.update(solver_env)
            environment["LLVM_PROFILE_FILE"] = str(
                raw_directory / f"train-{run_ordinal:06d}-%p-%m.profraw"
            )
            record = run_solver(
                generation_binary,
                source,
                environment=environment,
                timeout=args.solver_timeout,
                allow_unknown=args.allow_unknown_training,
            )
            previous_outcome = training_outcomes.setdefault(
                source["relative_path"], record["actual"]
            )
            if previous_outcome != record["actual"]:
                raise PgoError(
                    f"training outcome changed across repeats for "
                    f"{source['relative_path']}: {previous_outcome} -> {record['actual']}"
                )
            record["repeat"] = repeat
            after = set(raw_directory.glob("train-*.profraw"))
            created = sorted(after.difference(before))
            if not created or any(path.stat().st_size == 0 for path in created):
                raise PgoError(
                    f"training run emitted no nonempty profile: {source['relative_path']}"
                )
            record["profiles"] = [path.name for path in created]
            training_runs.append(record)
            run_ordinal += 1

    raw_profiles = sorted(raw_directory.glob("train-*.profraw"))
    if not raw_profiles:
        raise PgoError("training emitted no raw profiles")
    merged_profile = output_root / "merged.profdata"
    merge_command: list[str | Path] = [
        llvm_profdata,
        "merge",
        "-sparse",
        "-o",
        merged_profile,
        *raw_profiles,
    ]
    merge_record = require_success(
        merge_command,
        cwd=repository,
        environment=base_environment,
        timeout=args.build_timeout,
        label="llvm-profdata merge",
    )
    if not merged_profile.is_file() or merged_profile.stat().st_size == 0:
        raise PgoError("llvm-profdata did not produce a nonempty merged profile")

    use_flags = [
        f"-Cprofile-use={merged_profile}",
        "-Cllvm-args=-pgo-warn-missing-function",
    ]
    use_environment = build_environment(
        base_environment,
        rustc=rustc,
        target=use_target,
        rustflags=use_flags,
        source_date_epoch=git["commit_timestamp"],
    )
    use_build = require_success(
        build_command,
        cwd=repository,
        environment=use_environment,
        timeout=args.build_timeout,
        label="profile-use Cargo build",
    )
    use_binary = use_target / "release" / executable_name
    if not use_binary.is_file():
        raise PgoError(f"profile-use binary was not produced: {use_binary}")

    verification_runs: list[dict[str, Any]] = []
    verification_environment = dict(base_environment)
    verification_environment.update(solver_env)
    verification_environment.pop("LLVM_PROFILE_FILE", None)
    for source in sources:
        verification_runs.append(
            run_solver(
                use_binary,
                source,
                environment=verification_environment,
                timeout=args.solver_timeout,
                expected=training_outcomes[source["relative_path"]],
            )
        )

    raw_records = [
        {
            "bytes": path.stat().st_size,
            "name": path.name,
            "sha256": sha256_file(path),
        }
        for path in raw_profiles
    ]
    binary_sha256 = sha256_file(use_binary)
    binary_bytes = use_binary.stat().st_size
    report = {
        "schema_version": SCHEMA_VERSION,
        "artifact": {
            "binary_bytes": binary_bytes,
            "binary_out": str(binary_out),
            "binary_sha256": binary_sha256,
            "report_out": str(report_out),
        },
        "build_contract": {
            "cargo_locked": True,
            "engine": "cadical-up",
            "features": ["fabric"],
            "generation_rustflags": generation_flags,
            "incremental": False,
            "profile_use_rustflags": use_flags,
            "release": True,
            "unknown_training_allowed": args.allow_unknown_training,
            "solver_environment": dict(sorted(solver_env.items())),
        },
        "builds": {
            "generation": generation_build,
            "generation_binary_sha256": sha256_file(generation_binary),
            "profile_use": use_build,
        },
        "created_at": datetime.now(timezone.utc).isoformat(),
        "git": git,
        "host": {
            "machine": platform.machine(),
            "platform": platform.platform(),
            "python": platform.python_version(),
        },
        "repository_inputs": {
            name: {
                "bytes": (repository / name).stat().st_size,
                "sha256": sha256_file(repository / name),
            }
            for name in ("Cargo.lock", "Cargo.toml")
        },
        "profiles": {
            "merge": merge_record,
            "merged_bytes": merged_profile.stat().st_size,
            "merged_path": str(merged_profile),
            "merged_sha256": sha256_file(merged_profile),
            "raw": raw_records,
        },
        "source_root": str(source_root),
        "split": {
            "definition_sha256": split["report"]["definition_sha256"],
            "holdout_families": split["report"]["families"]["holdout"],
            "report_path": str(split_report_path),
            "report_sha256": split["raw_sha256"],
            "training_families": split["report"]["families"]["training"],
            "training_manifest_path": str(training_manifest),
            "training_manifest_sha256": training_manifest_sha256,
        },
        "toolchain": {
            "cargo": {
                "bytes": cargo.stat().st_size,
                "path": str(cargo),
                "sha256": sha256_file(cargo),
                "version": cargo_version,
            },
            "llvm_profdata": {
                "bytes": llvm_profdata.stat().st_size,
                "llvm_version": llvm_version,
                "path": str(llvm_profdata),
                "sha256": sha256_file(llvm_profdata),
                "version": llvm_profdata_version,
            },
            "rustc": {
                "bytes": rustc.stat().st_size,
                "llvm_version": llvm_version,
                "path": str(rustc),
                "sha256": sha256_file(rustc),
                "version": rustc_version,
            },
        },
        "training": {
            "expected_statuses": dict(
                sorted(Counter(source["expected"] for source in sources).items())
            ),
            "instrumented_outcomes": dict(
                sorted(Counter(training_outcomes.values()).items())
            ),
            "repeats": args.training_repeats,
            "runs": training_runs,
            "sources": sources,
        },
        "verification": {
            "optimized_binary_all_training_sources": True,
            "runs": verification_runs,
        },
    }
    report_data = SPLITTER.canonical_json_bytes(report)
    publish_artifacts(use_binary, binary_out, report_out, report_data)
    print(
        f"binary={binary_out} sha256={binary_sha256} "
        f"training_sources={len(sources)} profiles={len(raw_profiles)}"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (PgoError, SPLITTER.SplitError) as error:
        print(f"error: {error}", file=__import__("sys").stderr)
        raise SystemExit(2)
