#!/usr/bin/env python3
"""Run staged, fail-fast ABBA gates for the Quotient-JIT campaign."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence


class FastCycleError(ValueError):
    """Raised when a campaign contract or measured result is invalid."""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def atomic_write_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent, prefix=f".{path.name}.", suffix=".tmp"
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="ascii") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True, allow_nan=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise FastCycleError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def _require_exact_keys(value: Mapping[str, Any], keys: set[str], context: str) -> None:
    missing = keys - value.keys()
    extra = value.keys() - keys
    if missing or extra:
        raise FastCycleError(
            f"{context} keys differ: missing={sorted(missing)!r} extra={sorted(extra)!r}"
        )


def _command(value: Any, context: str) -> list[str]:
    if not isinstance(value, list) or not value:
        raise FastCycleError(f"{context} must be a nonempty token list")
    if any(type(token) is not str or not token or "\x00" in token for token in value):
        raise FastCycleError(f"{context} contains an invalid token")
    if sum(token.count("{input}") for token in value) != 1:
        raise FastCycleError(f"{context} must contain exactly one {{input}} placeholder")
    return list(value)


def _environment(value: Any, context: str) -> dict[str, str]:
    if type(value) is not dict:
        raise FastCycleError(f"{context} must be an object")
    result: dict[str, str] = {}
    for key, setting in value.items():
        if type(key) is not str or not key or "=" in key or "\x00" in key:
            raise FastCycleError(f"{context} has an invalid environment name")
        if type(setting) is not str or "\x00" in setting:
            raise FastCycleError(f"{context}.{key} must be a string without NUL")
        result[key] = setting
    return result


def load_spec(path: Path) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
        text = raw.decode("ascii")
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=lambda token: (_ for _ in ()).throw(
                FastCycleError(f"non-finite JSON number {token}")
            ),
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise FastCycleError(f"cannot load campaign spec {path}: {error}") from error
    if type(value) is not dict:
        raise FastCycleError("campaign spec must be an object")
    required = {
        "schema_version",
        "campaign_id",
        "status",
        "objective",
        "corpus_root",
        "candidate",
        "comparators",
        "preflight",
        "stages",
        "global_gates",
        "forbidden_runtime_features",
    }
    _require_exact_keys(value, required, "campaign")
    if value["schema_version"] != 2:
        raise FastCycleError("schema_version must be 2")
    if type(value["campaign_id"]) is not str or not value["campaign_id"]:
        raise FastCycleError("campaign_id must be a nonempty string")
    if type(value["corpus_root"]) is not str or not value["corpus_root"]:
        raise FastCycleError("corpus_root must be a nonempty string")

    candidate = value["candidate"]
    if type(candidate) is not dict:
        raise FastCycleError("candidate must be an object")
    _require_exact_keys(
        candidate,
        {"argv", "environment", "standalone", "default_behavior_change_authorized"},
        "candidate",
    )
    candidate["argv"] = _command(candidate["argv"], "candidate.argv")
    candidate["environment"] = _environment(candidate["environment"], "candidate.environment")
    if candidate["standalone"] is not True:
        raise FastCycleError("candidate.standalone must remain true")
    if candidate["default_behavior_change_authorized"] is not False:
        raise FastCycleError("default behavior change is not authorized")

    comparators = value["comparators"]
    if type(comparators) is not dict or not comparators:
        raise FastCycleError("comparators must be a nonempty object")
    for identifier, comparator in comparators.items():
        if type(identifier) is not str or not identifier or type(comparator) is not dict:
            raise FastCycleError("comparator entries must be named objects")
        _require_exact_keys(comparator, {"argv", "environment"}, f"comparators.{identifier}")
        comparator["argv"] = _command(comparator["argv"], f"comparators.{identifier}.argv")
        comparator["environment"] = _environment(
            comparator["environment"], f"comparators.{identifier}.environment"
        )

    preflight = value["preflight"]
    if not isinstance(preflight, list):
        raise FastCycleError("preflight must be a command list")
    for index, command in enumerate(preflight):
        if not isinstance(command, list) or not command:
            raise FastCycleError(f"preflight[{index}] must be a nonempty token list")
        if any(type(token) is not str or not token or "\x00" in token for token in command):
            raise FastCycleError(f"preflight[{index}] contains an invalid token")

    stages = value["stages"]
    if not isinstance(stages, list) or not stages:
        raise FastCycleError("stages must be a nonempty list")
    stage_keys = {
        "id",
        "name",
        "site",
        "manifest",
        "comparators",
        "timeout_s",
        "repeats",
        "warmups",
        "minimum_common_aggregate_speedup",
        "minimum_common_geometric_speedup",
        "minimum_reference_aggregate_speedup",
        "minimum_reference_geometric_speedup",
        "performance_blocking_comparators",
        "require_no_coverage_loss",
        "enabled_by_default",
    }
    seen: set[str] = set()
    for index, stage in enumerate(stages):
        if type(stage) is not dict:
            raise FastCycleError(f"stages[{index}] must be an object")
        _require_exact_keys(stage, stage_keys, f"stages[{index}]")
        identifier = stage["id"]
        if type(identifier) is not str or not identifier or identifier in seen:
            raise FastCycleError(f"stages[{index}].id is empty or duplicated")
        seen.add(identifier)
        if (
            not isinstance(stage["comparators"], list)
            or not stage["comparators"]
            or any(item not in comparators for item in stage["comparators"])
        ):
            raise FastCycleError(f"stages[{index}].comparators is invalid")
        blocking = stage["performance_blocking_comparators"]
        if (
            not isinstance(blocking, list)
            or len(set(blocking)) != len(blocking)
            or any(item not in stage["comparators"] for item in blocking)
        ):
            raise FastCycleError(
                f"stages[{index}].performance_blocking_comparators is invalid"
            )
        for field in (
            "timeout_s",
            "minimum_common_aggregate_speedup",
            "minimum_common_geometric_speedup",
            "minimum_reference_aggregate_speedup",
            "minimum_reference_geometric_speedup",
        ):
            number = stage[field]
            if type(number) not in (int, float) or not math.isfinite(number) or number <= 0:
                raise FastCycleError(f"stages[{index}].{field} must be finite and positive")
        for field, minimum in (("repeats", 1), ("warmups", 0)):
            number = stage[field]
            if type(number) is not int or number < minimum:
                raise FastCycleError(f"stages[{index}].{field} is invalid")
        if type(stage["require_no_coverage_loss"]) is not bool:
            raise FastCycleError(f"stages[{index}].require_no_coverage_loss must be Boolean")
        if type(stage["enabled_by_default"]) is not bool:
            raise FastCycleError(f"stages[{index}].enabled_by_default must be Boolean")

    gates = value["global_gates"]
    if type(gates) is not dict:
        raise FastCycleError("global_gates must be an object")
    for zero_field in (
        "wrong_answers_allowed",
        "execution_errors_allowed",
        "candidate_timeouts_not_shared_with_baseline_allowed",
    ):
        if gates.get(zero_field) != 0:
            raise FastCycleError(f"global_gates.{zero_field} must remain zero")
    if gates.get("stop_at_first_failure") is not True:
        raise FastCycleError("global_gates.stop_at_first_failure must remain true")
    if gates.get("atomic_ledger_required") is not True:
        raise FastCycleError("global_gates.atomic_ledger_required must remain true")
    return value


def gate_summary(
    summary: Mapping[str, Any],
    stage: Mapping[str, Any],
    *,
    enforce_performance: bool = True,
    reference: bool = False,
) -> list[str]:
    failures: list[str] = []
    accounting = summary.get("accounting", {})
    if accounting.get("wrong_answers") != 0:
        failures.append(f"wrong_answers={accounting.get('wrong_answers')}")
    if accounting.get("execution_errors") != 0:
        failures.append(f"execution_errors={accounting.get('execution_errors')}")
    if stage["require_no_coverage_loss"] and summary.get("coverage_delta", -1) < 0:
        failures.append(f"coverage_delta={summary.get('coverage_delta')}")
    if summary.get("baseline_only_correct", 0) != 0:
        failures.append(f"baseline_only_correct={summary.get('baseline_only_correct')}")
    common = summary.get("common_correct", 0)
    coverage_dominance = (
        summary.get("baseline_only_correct", 0) == 0
        and type(summary.get("candidate_only_correct")) is int
        and summary.get("candidate_only_correct", 0) > 0
        and type(summary.get("coverage_delta")) is int
        and summary.get("coverage_delta", 0) > 0
    )
    has_common = type(common) is int and common >= 1
    if not has_common and not coverage_dominance:
        failures.append("no common correct instances")
    if enforce_performance and has_common:
        prefix = "minimum_reference" if reference else "minimum_common"
        for metric in ("aggregate", "geometric"):
            summary_key = f"common_{metric}_speedup"
            threshold_key = f"{prefix}_{metric}_speedup"
            speedup = summary.get(summary_key)
            if type(speedup) not in (int, float) or not math.isfinite(speedup):
                failures.append(f"common {metric} speedup is unavailable")
            elif speedup < stage[threshold_key]:
                failures.append(
                    f"{summary_key}={speedup:.6f} < {stage[threshold_key]:.6f}"
                )
    return failures


def resolve_corpus_root(
    repository: Path,
    configured: str,
    override: Path | None,
) -> Path:
    if override is not None:
        return override.expanduser().resolve(strict=True)
    configured_path = Path(configured).expanduser()
    candidates = [
        configured_path if configured_path.is_absolute() else repository / configured_path
    ]
    if not configured_path.is_absolute():
        completed = subprocess.run(
            ["git", "-C", str(repository), "rev-parse", "--git-common-dir"],
            check=False,
            capture_output=True,
            text=True,
        )
        if completed.returncode == 0 and completed.stdout.strip():
            common = Path(completed.stdout.strip())
            if not common.is_absolute():
                common = repository / common
            common = common.resolve()
            shared_repository = common.parent if common.name == ".git" else common
            candidates.append(shared_repository / configured_path)
    for candidate in candidates:
        if candidate.is_dir():
            return candidate.resolve(strict=True)
    rendered = ", ".join(str(candidate) for candidate in candidates)
    raise FastCycleError(f"corpus root does not exist; checked {rendered}")


def git_state(repository: Path) -> dict[str, Any]:
    def run(*args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["git", "-C", str(repository), *args],
            check=False,
            capture_output=True,
            text=True,
        )

    revision = run("rev-parse", "HEAD")
    status = run("status", "--porcelain")
    return {
        "revision": revision.stdout.strip() if revision.returncode == 0 else None,
        "clean": status.returncode == 0 and not status.stdout,
    }


def selected_stages(
    spec: Mapping[str, Any], explicit: Sequence[str], through: str | None
) -> list[dict[str, Any]]:
    stages = list(spec["stages"])
    by_id = {stage["id"]: stage for stage in stages}
    if explicit:
        unknown = [identifier for identifier in explicit if identifier not in by_id]
        if unknown:
            raise FastCycleError(f"unknown stages: {unknown!r}")
        return [by_id[identifier] for identifier in explicit]
    if through is not None:
        if through not in by_id:
            raise FastCycleError(f"unknown --through stage {through!r}")
        index = next(index for index, stage in enumerate(stages) if stage["id"] == through)
        return stages[: index + 1]
    return [stage for stage in stages if stage["enabled_by_default"]]


def selected_comparators(
    spec: Mapping[str, Any],
    stages: Sequence[Mapping[str, Any]],
    explicit: Sequence[str],
) -> dict[str, list[str]]:
    if len(set(explicit)) != len(explicit):
        raise FastCycleError("--comparator values must be unique")
    unknown = [identifier for identifier in explicit if identifier not in spec["comparators"]]
    if unknown:
        raise FastCycleError(f"unknown comparators: {unknown!r}")

    selection: dict[str, list[str]] = {}
    for stage in stages:
        comparators = list(stage["comparators"])
        if explicit:
            comparators = [identifier for identifier in explicit if identifier in comparators]
            if not comparators:
                raise FastCycleError(
                    f"stage {stage['id']} supports none of the requested comparators"
                )
        selection[stage["id"]] = comparators
    return selection


def _expanded_command(tokens: Sequence[str], repository: Path) -> list[str]:
    return [token.replace("{repo}", str(repository)) for token in tokens]


def resolve_manifest(
    source_manifest: Path,
    corpus_root: Path,
    destination: Path,
) -> Path:
    rows: list[dict[str, Any]] = []
    changed = False
    for line_number, line in enumerate(
        source_manifest.read_text(encoding="utf-8").splitlines(), start=1
    ):
        if not line.strip():
            raise FastCycleError(f"{source_manifest}: blank line {line_number}")
        row = json.loads(line)
        if type(row) is not dict or type(row.get("path")) is not str or not row["path"]:
            raise FastCycleError(f"{source_manifest}: invalid row {line_number}")
        path = Path(row["path"]).expanduser()
        if not path.is_absolute():
            path = corpus_root / path
            changed = True
        row["path"] = str(path.resolve(strict=True))
        rows.append(row)
    if not rows:
        raise FastCycleError(f"{source_manifest}: manifest is empty")
    if not changed:
        return source_manifest
    destination.parent.mkdir(parents=True, exist_ok=True)
    payload = "".join(
        json.dumps(row, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n"
        for row in rows
    ).encode("ascii")
    descriptor, temporary_name = tempfile.mkstemp(
        dir=destination.parent, prefix=f".{destination.name}.", suffix=".tmp"
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    return destination


def run_cycle(args: argparse.Namespace) -> int:
    spec_path = args.spec.resolve(strict=True)
    repository = spec_path.parent.parent.resolve(strict=True)
    spec = load_spec(spec_path)
    stages = selected_stages(spec, args.stage, args.through)
    comparator_selection = selected_comparators(spec, stages, args.comparator)
    if not args.allow_nonlocal:
        nonlocal_stages = [
            stage["id"] for stage in stages if stage["site"] not in {"local", "local_or_wmi"}
        ]
        if nonlocal_stages:
            raise FastCycleError(
                f"nonlocal stages require --allow-nonlocal: {nonlocal_stages!r}"
            )

    output = args.output
    if output is None:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        output = repository / "research-vault" / "06-results" / "fast-cycle" / stamp
    output = output.resolve()
    ledger_path = output / "ledger.json"
    ledger: dict[str, Any] = {
        "schema_version": 2,
        "campaign_id": spec["campaign_id"],
        "started_at": utc_now(),
        "finished_at": None,
        "status": "running",
        "spec": {
            "path": str(spec_path),
            "sha256": sha256_file(spec_path),
        },
        "repository": git_state(repository),
        "reference_binary": (
            str(args.reference_binary.expanduser())
            if args.reference_binary is not None
            else None
        ),
        "selected_stages": [stage["id"] for stage in stages],
        "selected_comparators": comparator_selection,
        "preflight": [],
        "runs": [],
    }
    atomic_write_json(ledger_path, ledger)

    if args.dry_run:
        ledger["status"] = "dry_run"
        ledger["finished_at"] = utc_now()
        atomic_write_json(ledger_path, ledger)
        print(ledger_path)
        return 0

    if not args.skip_preflight:
        for command in spec["preflight"]:
            started = utc_now()
            completed = subprocess.run(
                command,
                cwd=repository,
                check=False,
                capture_output=True,
                text=True,
            )
            record = {
                "argv": command,
                "started_at": started,
                "finished_at": utc_now(),
                "returncode": completed.returncode,
                "stdout_tail": completed.stdout[-4000:],
                "stderr_tail": completed.stderr[-4000:],
            }
            ledger["preflight"].append(record)
            atomic_write_json(ledger_path, ledger)
            if completed.returncode != 0:
                ledger["status"] = "preflight_failed"
                ledger["finished_at"] = utc_now()
                atomic_write_json(ledger_path, ledger)
                return 2

    compare_script = repository / "scripts" / "bench" / "compare_commands_abba.py"
    corpus_root = resolve_corpus_root(repository, spec["corpus_root"], args.corpus_root)
    candidate = _expanded_command(spec["candidate"]["argv"], repository)
    if args.candidate_binary is not None:
        candidate[0] = str(args.candidate_binary.expanduser().resolve(strict=True))
    reference: list[str] | None = None
    if args.reference_binary is not None:
        reference = list(candidate)
        reference[0] = str(args.reference_binary.expanduser().resolve(strict=True))

    for stage in stages:
        manifest = Path(stage["manifest"])
        if not manifest.is_absolute():
            manifest = repository / manifest
        manifest = manifest.resolve(strict=True)
        manifest = resolve_manifest(
            manifest,
            corpus_root,
            output / f"{stage['id'].lower()}-resolved-manifest.jsonl",
        )
        comparisons: list[dict[str, Any]] = []
        if reference is not None:
            comparisons.append(
                {
                    "id": "viper-reference",
                    "kind": "reference",
                    "baseline": reference,
                    "environment": spec["candidate"]["environment"],
                    "blocking_performance": True,
                    "reference_thresholds": True,
                }
            )
        for comparator_id in comparator_selection[stage["id"]]:
            comparator = spec["comparators"][comparator_id]
            comparisons.append(
                {
                    "id": comparator_id,
                    "kind": "competitor",
                    "baseline": _expanded_command(comparator["argv"], repository),
                    "environment": comparator["environment"],
                    "blocking_performance": comparator_id
                    in stage["performance_blocking_comparators"],
                    "reference_thresholds": False,
                }
            )
        for comparison in comparisons:
            comparator_id = comparison["id"]
            baseline = comparison["baseline"]
            stem = f"{stage['id'].lower()}-{comparator_id}"
            csv_path = output / f"{stem}.csv"
            summary_path = output / f"{stem}.json"
            command = [sys.executable, str(compare_script), str(manifest)]
            command.extend(f"--baseline-arg={token}" for token in baseline)
            command.extend(f"--candidate-arg={token}" for token in candidate)
            command.extend(
                f"--baseline-env={key}={value}"
                for key, value in sorted(comparison["environment"].items())
            )
            command.extend(
                f"--candidate-env={key}={value}"
                for key, value in sorted(spec["candidate"]["environment"].items())
            )
            command.extend(
                [
                    "--timeout",
                    str(stage["timeout_s"]),
                    "--repeats",
                    str(stage["repeats"]),
                    "--warmups",
                    str(stage["warmups"]),
                    "--out",
                    str(csv_path),
                    "--summary",
                    str(summary_path),
                ]
            )
            completed = subprocess.run(
                command,
                cwd=repository,
                check=False,
                capture_output=True,
                text=True,
            )
            failures: list[str]
            summary: dict[str, Any] | None = None
            if completed.returncode != 0 or not summary_path.is_file():
                failures = [f"benchmark command returned {completed.returncode}"]
                performance_target_failures = list(failures)
            else:
                summary = json.loads(summary_path.read_text(encoding="utf-8"))
                performance_target_failures = gate_summary(
                    summary,
                    stage,
                    reference=comparison["reference_thresholds"],
                )
                failures = gate_summary(
                    summary,
                    stage,
                    enforce_performance=comparison["blocking_performance"],
                    reference=comparison["reference_thresholds"],
                )
            record = {
                "stage": stage["id"],
                "comparator": comparator_id,
                "kind": comparison["kind"],
                "blocking_performance": comparison["blocking_performance"],
                "passed": not failures,
                "failures": failures,
                "performance_target_met": not performance_target_failures,
                "performance_target_failures": performance_target_failures,
                "command_returncode": completed.returncode,
                "stdout_tail": completed.stdout[-4000:],
                "stderr_tail": completed.stderr[-4000:],
                "csv": str(csv_path),
                "summary": str(summary_path),
                "coverage_delta": summary.get("coverage_delta") if summary else None,
                "common_aggregate_speedup": (
                    summary.get("common_aggregate_speedup") if summary else None
                ),
                "common_geometric_speedup": (
                    summary.get("common_geometric_speedup") if summary else None
                ),
                "coverage_dominance": (
                    summary is not None
                    and summary.get("baseline_only_correct", 0) == 0
                    and summary.get("candidate_only_correct", 0) > 0
                    and summary.get("coverage_delta", 0) > 0
                ),
            }
            ledger["runs"].append(record)
            atomic_write_json(ledger_path, ledger)
            if failures:
                ledger["status"] = "gate_failed"
                ledger["finished_at"] = utc_now()
                atomic_write_json(ledger_path, ledger)
                print(ledger_path)
                return 1

    ledger["status"] = "passed"
    ledger["finished_at"] = utc_now()
    atomic_write_json(ledger_path, ledger)
    print(ledger_path)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("spec", type=Path)
    parser.add_argument("--stage", action="append", default=[])
    parser.add_argument("--comparator", action="append", default=[])
    parser.add_argument("--through")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--candidate-binary", type=Path)
    parser.add_argument("--reference-binary", type=Path)
    parser.add_argument("--corpus-root", type=Path)
    parser.add_argument("--skip-preflight", action="store_true")
    parser.add_argument("--allow-nonlocal", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.stage and args.through:
        parser.error("--stage and --through are mutually exclusive")
    try:
        return run_cycle(args)
    except (FastCycleError, OSError, json.JSONDecodeError) as error:
        print(f"fast-cycle error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
