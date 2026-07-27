#!/usr/bin/env python3
"""Collect bounded CaDiCaL prefix telemetry without running fallback search."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import selectors
import subprocess
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "euf-viper.cadical-prefix-probe.v1"
FINITE_PREFIX = "profile_finite_analysis "
PROBE_PREFIX = "profile_finite_dense7_braided_probe "
CNF_PREFIX = "profile_cnf_ns="


class ProbeError(RuntimeError):
    pass


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def parse_fields(line: str, prefix: str) -> dict[str, int | str]:
    if not line.startswith(prefix):
        raise ProbeError(f"profile line does not start with {prefix!r}")
    fields: dict[str, int | str] = {}
    for token in line[len(prefix) :].split():
        if "=" not in token:
            raise ProbeError(f"malformed profile token: {token!r}")
        name, value = token.split("=", 1)
        if not name or not value or name in fields:
            raise ProbeError(f"invalid or repeated profile field: {name!r}")
        try:
            fields[name] = int(value)
        except ValueError:
            fields[name] = value
    return fields


def parse_phase(line: str, prefix: str) -> dict[str, int]:
    tokens = line.split()
    if len(tokens) != 2 or not tokens[0].startswith(prefix):
        raise ProbeError(f"malformed phase profile: {line!r}")
    try:
        elapsed_ns = int(tokens[0][len(prefix) :])
        count_name, count_text = tokens[1].split("=", 1)
        count = int(count_text)
    except (ValueError, TypeError) as error:
        raise ProbeError(f"malformed phase profile: {line!r}") from error
    if count_name != "count":
        raise ProbeError(f"malformed phase profile: {line!r}")
    return {"elapsed_ns": elapsed_ns, "count": count}


def load_manifest(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line_number, line in enumerate(path.read_text(encoding="ascii").splitlines(), 1):
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as error:
            raise ProbeError(f"invalid manifest JSON at line {line_number}: {error}") from error
        for key in ("id", "relative_path", "sha256", "status"):
            if key not in row:
                raise ProbeError(f"manifest line {line_number} lacks {key!r}")
        rows.append(row)
    if not rows:
        raise ProbeError("manifest is empty")
    return rows


def terminate(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=0.25)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


def run_probe(
    solver: Path,
    source: Path,
    prefix_conflicts: int,
    timeout_s: float,
) -> dict[str, Any]:
    environment = os.environ.copy()
    for name in tuple(environment):
        if name.startswith("EUF_VIPER_CADICAL_") or name.startswith(
            "EUF_VIPER_FINITE_DENSE7"
        ):
            environment.pop(name)
    environment.update(
        {
            "EUF_VIPER_PROFILE": "1",
            "EUF_VIPER_FINITE_DENSE7": "0",
            "EUF_VIPER_FINITE_DENSE7_STAGED": "0",
            "EUF_VIPER_FINITE_DENSE7_BRAIDED": "1",
            "EUF_VIPER_FINITE_DENSE7_CADICAL_PREFIX_CONFLICTS": str(
                prefix_conflicts
            ),
            "EUF_VIPER_FINITE_DENSE7_CADICAL_SPRINT_CONFLICTS": "0",
            "EUF_VIPER_FINITE_DENSE7_KISSAT_CONFLICTS": "0",
        }
    )
    command = [
        str(solver),
        "fabric-solve",
        "--engine",
        "quotient-portfolio",
        str(source),
    ]
    started = time.monotonic()
    process = subprocess.Popen(
        command,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert process.stdout is not None
    assert process.stderr is not None
    os.set_blocking(process.stderr.fileno(), False)
    selector = selectors.DefaultSelector()
    selector.register(process.stderr, selectors.EVENT_READ)
    buffer = b""
    finite: dict[str, int | str] | None = None
    cnf: dict[str, int] | None = None
    probe: dict[str, int | str] | None = None
    solved_before_probe: str | None = None
    try:
        deadline = started + timeout_s
        while probe is None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ProbeError(f"probe timed out after {timeout_s:.3f}s")
            events = selector.select(remaining)
            if not events:
                raise ProbeError(f"probe timed out after {timeout_s:.3f}s")
            chunk = os.read(process.stderr.fileno(), 64 * 1024)
            if not chunk:
                return_code = process.wait()
                stdout = process.stdout.read().decode("ascii").strip()
                if return_code != 0 or stdout not in {"sat", "unsat"}:
                    raise ProbeError(
                        "solver exited before probe telemetry with "
                        f"code {return_code} and stdout {stdout!r}"
                    )
                solved_before_probe = stdout
                break
            buffer += chunk
            while b"\n" in buffer:
                raw_line, buffer = buffer.split(b"\n", 1)
                line = raw_line.decode("ascii")
                if line.startswith(FINITE_PREFIX):
                    finite = parse_fields(line, FINITE_PREFIX)
                elif line.startswith(CNF_PREFIX):
                    cnf = parse_phase(line, CNF_PREFIX)
                elif line.startswith(PROBE_PREFIX):
                    probe = parse_fields(line, PROBE_PREFIX)
                    break
    finally:
        selector.close()
        terminate(process)
    if solved_before_probe is not None:
        return {
            "elapsed_to_probe_s": None,
            "cnf": cnf,
            "finite": finite,
            "prefix": None,
            "reached_probe": False,
            "solver_result": solved_before_probe,
            "terminated_after_probe": False,
        }
    if cnf is None or finite is None or probe is None:
        raise ProbeError("solver omitted required profile telemetry")
    return {
        "elapsed_to_probe_s": time.monotonic() - started,
        "cnf": cnf,
        "finite": finite,
        "prefix": probe,
        "reached_probe": True,
        "solver_result": None,
        "terminated_after_probe": True,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--instance-root", required=True, type=Path)
    parser.add_argument("--solver", required=True, type=Path)
    parser.add_argument("--prefix", action="append", required=True, type=int)
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--out", required=True, type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    manifest = args.manifest.resolve()
    instance_root = args.instance_root.resolve()
    solver = args.solver.resolve()
    output = args.out.resolve()
    if output.exists():
        raise ProbeError(f"output already exists: {output}")
    if not solver.is_file() or not os.access(solver, os.X_OK):
        raise ProbeError(f"solver is not an executable regular file: {solver}")
    if args.timeout <= 0:
        raise ProbeError("timeout must be positive")
    prefixes = list(dict.fromkeys(args.prefix))
    if any(prefix < 0 for prefix in prefixes):
        raise ProbeError("prefix conflicts must be nonnegative")

    rows = load_manifest(manifest)
    observations: list[dict[str, Any]] = []
    for row_index, row in enumerate(rows):
        relative_path = Path(row["relative_path"])
        if relative_path.is_absolute() or ".." in relative_path.parts:
            raise ProbeError(f"unsafe relative path: {relative_path}")
        source = instance_root / relative_path
        if not source.is_file():
            raise ProbeError(f"missing source: {source}")
        actual_sha256 = sha256_file(source)
        if actual_sha256 != row["sha256"]:
            raise ProbeError(
                f"source hash mismatch for {relative_path}: {actual_sha256}"
            )
        for prefix in prefixes:
            try:
                observation = run_probe(solver, source, prefix, args.timeout)
            except ProbeError as error:
                raise ProbeError(
                    f"{relative_path} at prefix {prefix}: {error}"
                ) from error
            observation.update(
                {
                    "row_index": row_index,
                    "id": row["id"],
                    "relative_path": relative_path.as_posix(),
                    "source_sha256": actual_sha256,
                    "expected_status": row["status"],
                    "prefix_conflicts": prefix,
                }
            )
            observations.append(observation)

    report = {
        "schema_version": SCHEMA_VERSION,
        "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "solver": {"path": str(solver), "sha256": sha256_file(solver)},
        "manifest": {"path": str(manifest), "sha256": sha256_file(manifest)},
        "instance_root": str(instance_root),
        "prefixes": prefixes,
        "observations": observations,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="ascii", dir=output.parent, delete=False
    ) as stream:
        temporary = Path(stream.name)
        json.dump(report, stream, indent=2, sort_keys=True)
        stream.write("\n")
    os.replace(temporary, output)
    print(
        f"observations={len(observations)} prefixes={','.join(map(str, prefixes))} "
        f"out={output}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
