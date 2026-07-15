#!/usr/bin/env python3
"""Independently validate every T6 census row and write WMI metadata."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import sys
from pathlib import Path
from typing import Any


MANIFEST_SHA256 = "33a9f0016570dc07dc4c9aed2f575633eb5a2ee10d21177c97a4e86b65507c78"
PATH_LIST_SHA256 = "1fd24c2c5fa8eafd07a39f28c96d828e0e0aa1072fd032db413c60f34270b6fa"
SOURCE_RECORDS_SHA256 = "f274424dcfdf3bd155fe12f7aedb99f8a80dfcb54c0625899dfba8377fff5b0b"
TOOLCHAIN_CONTRACT_SHA256 = (
    "db825fa64cf03e20d07842d063638ecdf7193a1eba4966be5d9e5f7e5c108baa"
)
HISTORICAL_JOB_DISPOSITION_SHA256 = (
    "b22f3bfdb10d2a379d5777e206eacd1e85453ee69c7380d8b68d995bda3fcbda"
)
EXPECTED_SOURCES = 12
REQUIRED_QUALIFYING_SOURCES = 10
REQUIRED_D_REDUCTION_PPM = 250_000
REQUIRED_INCREMENT_OVER_B_PPM = 50_000
REQUIRED_INCREMENT_OVER_C_PPM = 50_000
HISTORICAL_HARD10_JOB_ID = 146075
REPORT_SCHEMA = "euf-viper.t6-theory-dag-census.v2"
MANIFEST_SCHEMA = "euf-viper.t6-theory-dag-manifest.v2"
BUILD_ENVIRONMENT_ALLOWLIST = frozenset(
    {
        "AR",
        "CARGO_BUILD_JOBS",
        "CARGO_HOME",
        "CARGO_INCREMENTAL",
        "CARGO_TARGET_DIR",
        "CC",
        "CXX",
        "EUF_VIPER_EXPECTED_REVISION",
        "EUF_VIPER_T6_CORPUS_ROOT",
        "EUF_VIPER_T6_MANIFEST",
        "EUF_VIPER_T6_OUTPUT",
        "HOME",
        "LANG",
        "LC_ALL",
        "OMP_NUM_THREADS",
        "OPENBLAS_NUM_THREADS",
        "PATH",
        "RANLIB",
        "RAYON_NUM_THREADS",
        "RUSTC",
        "RUST_MIN_STACK",
        "TMPDIR",
        "TZ",
    }
)
REQUIRED_ABSENT_ENVIRONMENT = [
    "CARGO_ENCODED_RUSTFLAGS",
    "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER",
    "LD_LIBRARY_PATH",
    "RUSTC_WRAPPER",
    "RUSTC_WORKSPACE_WRAPPER",
    "RUSTDOCFLAGS",
    "RUSTFLAGS",
    "RUSTUP_HOME",
    "RUSTUP_TOOLCHAIN",
]
ARMS = (
    "A_tree_no_sharing",
    "B_generic_source_dag",
    "C_root_union_dag",
    "D_full_typed_euf_dag",
)
REPORT_FIELDS = frozenset(
    {
        "schema",
        "analysis_revision",
        "contract",
        "manifest",
        "gate",
        "implementation_or_promotion_eligible",
        "population_status",
        "projection_status",
        "sources",
    }
)
SOURCE_FIELDS = frozenset(
    {
        "sequence",
        "relative_path",
        "source_bytes",
        "source_sha256",
        "taxonomy",
        "shape",
        "theory",
        "projections",
        "reductions",
    }
)
THEORY_FIELDS = frozenset(
    {
        "unconditional_equality_facts",
        "root_equality_unions",
        "congruence_unions",
        "congruence_rounds",
        "congruence_signature_entries",
    }
)
PROJECTION_FIELDS = frozenset(
    {
        "source_occurrences",
        "assertion_roots",
        "boolean_data_roots",
        "gate_definitions",
        "gate_edges",
        "cnf",
    }
)
CNF_FIELDS = frozenset(
    {
        "atom_variables",
        "constant_variables",
        "tseitin_variables",
        "variables",
        "clauses",
        "literal_slots",
        "unit_clauses",
        "two_watch_entries",
    }
)
REDUCTION_FIELDS = frozenset(
    {
        "b_reduction_from_a_ppm",
        "c_reduction_from_a_ppm",
        "d_reduction_from_a_ppm",
        "d_increment_over_b_ppm",
        "d_increment_over_c_ppm",
        "qualifies",
    }
)
SHA256_RE = re.compile(r"[0-9a-f]{64}")


class ReportError(ValueError):
    """Raised when emitted census evidence is internally inconsistent."""


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ReportError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def reject_nonfinite(value: str) -> None:
    raise ReportError(f"non-finite JSON number {value!r}")


def strict_load(path: Path) -> tuple[Any, bytes]:
    data = path.read_bytes()
    try:
        value = json.loads(
            data.decode("ascii"),
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=reject_nonfinite,
        )
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ReportError(f"invalid strict JSON in {path}: {error}") from error
    return value, data


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def require_fields(value: Any, fields: frozenset[str], context: str) -> dict[str, Any]:
    if not isinstance(value, dict) or frozenset(value) != fields:
        raise ReportError(f"{context} field drift")
    return value


def require_nonnegative_int(value: Any, context: str) -> int:
    if type(value) is not int or value < 0:
        raise ReportError(f"{context} must be a nonnegative integer")
    return value


def require_signed_int(value: Any, context: str) -> int:
    if type(value) is not int:
        raise ReportError(f"{context} must be an integer")
    return value


def truncating_division(numerator: int, denominator: int) -> int:
    quotient = abs(numerator) // denominator
    return quotient if numerator >= 0 else -quotient


def reduction_ppm(baseline: int, candidate: int) -> int:
    if baseline == 0:
        if candidate == 0:
            return 0
        raise ReportError("nonzero candidate projection with zero baseline")
    return truncating_division((baseline - candidate) * 1_000_000, baseline)


def validate_projection(
    projection: Any, row_index: int, arm: str, shape: dict[str, Any]
) -> int:
    projection = require_fields(
        projection, PROJECTION_FIELDS, f"row {row_index} projection {arm}"
    )
    for field in PROJECTION_FIELDS - {"cnf"}:
        require_nonnegative_int(projection[field], f"row {row_index} {arm}.{field}")
    for field in ("source_occurrences", "assertion_roots", "boolean_data_roots"):
        if projection[field] != shape[field]:
            raise ReportError(f"row {row_index} {arm} does not match source shape")
    cnf = require_fields(projection["cnf"], CNF_FIELDS, f"row {row_index} {arm}.cnf")
    for field in CNF_FIELDS:
        require_nonnegative_int(cnf[field], f"row {row_index} {arm}.cnf.{field}")
    if cnf["variables"] != (
        cnf["atom_variables"] + cnf["constant_variables"] + cnf["tseitin_variables"]
    ):
        raise ReportError(f"row {row_index} {arm} variable accounting drift")
    if projection["gate_definitions"] != cnf["tseitin_variables"]:
        raise ReportError(f"row {row_index} {arm} gate/Tseitin accounting drift")
    if cnf["unit_clauses"] > cnf["clauses"]:
        raise ReportError(f"row {row_index} {arm} unit-clause accounting drift")
    expected_watches = 2 * (cnf["clauses"] - cnf["unit_clauses"])
    if cnf["two_watch_entries"] != expected_watches:
        raise ReportError(f"row {row_index} {arm} two-watch accounting drift")
    minimum_slots = cnf["unit_clauses"] + expected_watches
    if cnf["literal_slots"] < minimum_slots:
        raise ReportError(f"row {row_index} {arm} literal-slot accounting drift")
    return cnf["literal_slots"]


def validate_source_row(
    row: Any, manifest_source: dict[str, Any], row_index: int
) -> bool:
    row = require_fields(row, SOURCE_FIELDS, f"report row {row_index}")
    if row["sequence"] != row_index or manifest_source.get("sequence") != row_index:
        raise ReportError(f"report row {row_index} sequence drift")
    for field in ("relative_path", "source_bytes", "source_sha256", "taxonomy"):
        if row[field] != manifest_source.get(field):
            raise ReportError(f"report row {row_index} source identity drift in {field}")
    if not isinstance(row["relative_path"], str) or not row["relative_path"]:
        raise ReportError(f"report row {row_index} path is invalid")
    require_nonnegative_int(row["source_bytes"], f"report row {row_index} source_bytes")
    if not isinstance(row["source_sha256"], str) or SHA256_RE.fullmatch(row["source_sha256"]) is None:
        raise ReportError(f"report row {row_index} source SHA-256 is invalid")
    shape_fields = frozenset(
        {
            "sorts",
            "function_declarations",
            "terms",
            "applications",
            "assertion_roots",
            "boolean_data_roots",
            "source_occurrences",
        }
    )
    shape = require_fields(row["shape"], shape_fields, f"report row {row_index} shape")
    for field in shape_fields:
        require_nonnegative_int(shape[field], f"report row {row_index} shape.{field}")
    theory = require_fields(row["theory"], THEORY_FIELDS, f"report row {row_index} theory")
    for field, value in theory.items():
        require_nonnegative_int(value, f"report row {row_index} theory.{field}")

    projections = require_fields(
        row["projections"], frozenset(ARMS), f"report row {row_index} projections"
    )
    slots = {
        arm: validate_projection(projections[arm], row_index, arm, shape) for arm in ARMS
    }
    b = reduction_ppm(slots[ARMS[0]], slots[ARMS[1]])
    c = reduction_ppm(slots[ARMS[0]], slots[ARMS[2]])
    d = reduction_ppm(slots[ARMS[0]], slots[ARMS[3]])
    increment_b = d - b
    increment_c = d - c
    qualifies = (
        d >= REQUIRED_D_REDUCTION_PPM
        and increment_b >= REQUIRED_INCREMENT_OVER_B_PPM
        and increment_c >= REQUIRED_INCREMENT_OVER_C_PPM
    )
    expected_reductions = {
        "b_reduction_from_a_ppm": b,
        "c_reduction_from_a_ppm": c,
        "d_reduction_from_a_ppm": d,
        "d_increment_over_b_ppm": increment_b,
        "d_increment_over_c_ppm": increment_c,
        "qualifies": qualifies,
    }
    reductions = require_fields(
        row["reductions"], REDUCTION_FIELDS, f"report row {row_index} reductions"
    )
    for field in REDUCTION_FIELDS - {"qualifies"}:
        require_signed_int(reductions[field], f"report row {row_index} reductions.{field}")
    if type(reductions["qualifies"]) is not bool or reductions != expected_reductions:
        raise ReportError(f"report row {row_index} reduction/qualification drift")
    return qualifies


def validate_report(report: Any, manifest: Any, expected_revision: str) -> dict[str, Any]:
    report = require_fields(report, REPORT_FIELDS, "T6 report")
    if report["schema"] != REPORT_SCHEMA:
        raise ReportError("unexpected T6 report schema")
    if report.get("analysis_revision") != expected_revision:
        raise ReportError("T6 report revision mismatch")
    if not isinstance(manifest, dict) or manifest.get("schema") != MANIFEST_SCHEMA:
        raise ReportError("unexpected frozen T6 manifest schema")
    expected_contract = {
        "analysis": "source-only structural projection; no search engine is invoked",
        "parser_mode": "production typed parser with scoped-let auto mode",
        "primary_measure": "literal_slots",
        "result_semantics": (
            "counts are structural opportunity evidence, not timing or novelty evidence"
        ),
    }
    if report["contract"] != expected_contract:
        raise ReportError("T6 report analysis contract drift")
    if (
        manifest.get("population_status") != "accepted"
        or manifest.get("projection_status") != "not_executed"
        or manifest.get("implementation_or_promotion_eligible") is not False
    ):
        raise ReportError("frozen manifest evidence-state drift")
    manifest_sources = manifest.get("sources")
    report_sources = report.get("sources")
    if (
        not isinstance(manifest_sources, list)
        or not isinstance(report_sources, list)
        or len(manifest_sources) != EXPECTED_SOURCES
        or len(report_sources) != EXPECTED_SOURCES
    ):
        raise ReportError("T6 source population is not exactly 12")

    manifest_record = report.get("manifest")
    expected_manifest_record = {
        "file_sha256": MANIFEST_SHA256,
        "canonical_path_list_sha256": PATH_LIST_SHA256,
        "source_records_sha256": SOURCE_RECORDS_SHA256,
        "sources": EXPECTED_SOURCES,
    }
    if manifest_record != expected_manifest_record:
        raise ReportError("T6 report manifest binding drift")
    qualifying = sum(
        validate_source_row(row, manifest_sources[index], index)
        for index, row in enumerate(report_sources)
    )

    expected_decision = "pass" if qualifying >= REQUIRED_QUALIFYING_SOURCES else "reject"
    expected_gate = {
        "scope": "current_p0_qg7_derived_10_of_12",
        "decision": expected_decision,
        "pass_semantics": "source_only_projection_gate_no_implementation_or_promotion",
        "qualifying_sources": qualifying,
        "required_qualifying_sources": REQUIRED_QUALIFYING_SOURCES,
        "required_d_reduction_from_a_ppm": REQUIRED_D_REDUCTION_PPM,
        "required_increment_over_b_ppm": REQUIRED_INCREMENT_OVER_B_PPM,
        "required_increment_over_c_ppm": REQUIRED_INCREMENT_OVER_C_PPM,
    }
    if report.get("gate") != expected_gate:
        raise ReportError("T6 aggregate gate does not match all 12 recomputed rows")
    if (
        report.get("population_status") != "accepted"
        or report.get("projection_status") != "completed"
        or report.get("implementation_or_promotion_eligible") is not False
    ):
        raise ReportError("T6 report evidence-state drift")
    return {"decision": expected_decision, "qualifying_sources": qualifying}


def validate_attestation(attestation: Any) -> dict[str, str]:
    if not isinstance(attestation, dict):
        raise ReportError("toolchain attestation is not an object")
    if (
        attestation.get("schema") != "euf-viper.t6-wmi-toolchain-attestation.v1"
        or attestation.get("state") != "completed"
        or attestation.get("contract_sha256") != TOOLCHAIN_CONTRACT_SHA256
        or attestation.get("toolchain") != "1.96.0"
        or attestation.get("cargo_exit_code") != 0
    ):
        raise ReportError("toolchain attestation is incomplete")
    binaries = attestation.get("binaries")
    binary_names = {"ar", "cargo", "cc", "cxx", "ranlib", "rust_linker", "rustc"}
    if not isinstance(binaries, dict) or frozenset(binaries) != binary_names:
        raise ReportError("toolchain binary attestation is missing")
    for name, record in binaries.items():
        if (
            not isinstance(record, dict)
            or frozenset(record) != {"path", "sha256", "version", "device", "inode"}
            or not Path(str(record.get("path", ""))).is_absolute()
            or SHA256_RE.fullmatch(str(record.get("sha256", ""))) is None
            or not isinstance(record.get("version"), str)
            or type(record.get("device")) is not int
            or type(record.get("inode")) is not int
        ):
            raise ReportError(f"{name} binary attestation field drift")
    cargo = binaries.get("cargo")
    rustc = binaries.get("rustc")
    if (
        not isinstance(cargo, dict)
        or not isinstance(rustc, dict)
        or not str(cargo.get("version", "")).startswith("cargo 1.96.0 (")
        or not str(rustc.get("version", "")).startswith("rustc 1.96.0 (")
        or cargo.get("sha256") == rustc.get("sha256")
        or (cargo.get("device"), cargo.get("inode"))
        == (rustc.get("device"), rustc.get("inode"))
    ):
        raise ReportError("direct cargo/rustc attestation drift")
    verification = attestation.get("independent_verification")
    if (
        not isinstance(verification, dict)
        or verification.get("status") != "independently_verified"
        or not isinstance(verification.get("reviewer"), str)
        or SHA256_RE.fullmatch(str(verification.get("evidence_sha256", ""))) is None
    ):
        raise ReportError("independent toolchain verification attestation drift")
    attempt = attestation.get("attempt")
    if not isinstance(attempt, dict):
        raise ReportError("attempt-private toolchain record is missing")
    environment = attempt.get("environment")
    if not isinstance(environment, dict) or frozenset(environment) != BUILD_ENVIRONMENT_ALLOWLIST:
        raise ReportError("strict Cargo environment allowlist drift")
    expected_fixed_environment = {
        "CARGO_BUILD_JOBS": "1",
        "CARGO_INCREMENTAL": "0",
        "LANG": "C",
        "LC_ALL": "C",
        "OMP_NUM_THREADS": "1",
        "OPENBLAS_NUM_THREADS": "1",
        "RAYON_NUM_THREADS": "1",
        "RUST_MIN_STACK": "134217728",
        "TZ": "UTC",
    }
    if any(environment.get(name) != value for name, value in expected_fixed_environment.items()):
        raise ReportError("fixed Cargo environment value drift")
    required_absent = attempt.get("required_absent_environment")
    if required_absent != REQUIRED_ABSENT_ENVIRONMENT or any(
        name in environment for name in REQUIRED_ABSENT_ENVIRONMENT
    ):
        raise ReportError("required-absent build environment drift")
    if attempt.get("wrappers") != {
        "RUSTC_WRAPPER": None,
        "RUSTC_WORKSPACE_WRAPPER": None,
    }:
        raise ReportError("Cargo wrapper attestation drift")
    linkers = attempt.get("linkers")
    if not isinstance(linkers, dict) or frozenset(linkers) != {
        "ar",
        "cc",
        "cxx",
        "ranlib",
        "rust_linker",
    }:
        raise ReportError("native linker attestation drift")
    if any(linkers[name] != binaries.get(name) for name in linkers):
        raise ReportError("native linker/binary inventory drift")
    if (
        environment["RUSTC"] != rustc.get("path")
        or environment["AR"] != linkers["ar"].get("path")
        or environment["CC"] != linkers["cc"].get("path")
        or environment["CXX"] != linkers["cxx"].get("path")
        or environment["RANLIB"] != linkers["ranlib"].get("path")
    ):
        raise ReportError("tool path/environment attestation drift")
    attempt_root = Path(str(attempt.get("attempt_root", "")))
    if not attempt_root.is_absolute():
        raise ReportError("attempt-private root attestation drift")
    expected_attempt_paths = {
        "CARGO_HOME": attempt_root / "cargo-home",
        "CARGO_TARGET_DIR": attempt_root / "target",
        "HOME": attempt_root / "home",
        "TMPDIR": attempt_root / "tmp",
    }
    if any(Path(environment[name]) != path for name, path in expected_attempt_paths.items()):
        raise ReportError("attempt-private directory binding drift")
    expected_path_entries: list[str] = []
    for name in ("ar", "cargo", "cc", "cxx", "ranlib", "rust_linker", "rustc"):
        parent = str(Path(binaries[name]["path"]).parent)
        if parent not in expected_path_entries:
            expected_path_entries.append(parent)
    expected_path_entries.extend(
        path for path in ("/usr/bin", "/bin") if path not in expected_path_entries
    )
    if environment["PATH"] != ":".join(expected_path_entries):
        raise ReportError("Cargo PATH attestation drift")
    config = attempt.get("cargo_config")
    target = attestation.get("target")
    expected_config = (
        "[build]\n"
        f"rustc = {json.dumps(rustc.get('path'), ensure_ascii=True)}\n\n"
        f"[target.{target}]\n"
        f"linker = {json.dumps(linkers['rust_linker'].get('path'), ensure_ascii=True)}\n"
        f"ar = {json.dumps(linkers['ar'].get('path'), ensure_ascii=True)}\n"
    )
    if (
        not isinstance(config, dict)
        or config.get("path") != str(Path(environment["CARGO_HOME"]) / "config.toml")
        or config.get("content") != expected_config
        or sha256_bytes(expected_config.encode("ascii")) != config.get("sha256")
    ):
        raise ReportError("attempt-private Cargo config digest drift")
    command = attestation.get("command")
    expected_command = [
        cargo.get("path"),
        "test",
        "--release",
        "--locked",
        "--all-features",
        "t6_bool_dag_census::tests::p0_qg12_census_from_env",
        "--",
        "--ignored",
        "--exact",
        "--nocapture",
    ]
    if command != expected_command:
        raise ReportError("direct Cargo command attestation drift")
    return environment


def validate_runtime_bindings(
    environment: dict[str, str],
    revision: str,
    corpus_root: Path,
    manifest: Path,
    report: Path,
) -> None:
    expected = {
        "EUF_VIPER_EXPECTED_REVISION": revision,
        "EUF_VIPER_T6_CORPUS_ROOT": str(corpus_root),
        "EUF_VIPER_T6_MANIFEST": str(manifest),
        "EUF_VIPER_T6_OUTPUT": str(report),
    }
    if any(environment.get(name) != value for name, value in expected.items()):
        raise ReportError("Cargo runtime evidence-path binding drift")


def validate_disposition(path: Path) -> dict[str, Any]:
    disposition, data = strict_load(path)
    if sha256_bytes(data) != HISTORICAL_JOB_DISPOSITION_SHA256:
        raise ReportError("historical job disposition artifact hash mismatch")
    expected = {
        "artifact": {
            "path": "campaigns/t6-theory-dag-hard10-v1.json",
            "sha256": "198b0824c8847f249cc0c4405dcdea4e9b3101979c0b437cdeebd26165892476",
        },
        "automatic_cancellation_allowed": False,
        "classification": "historical_hard10",
        "current_state": "not_queried",
        "job_id": HISTORICAL_HARD10_JOB_ID,
        "replacement_evidence": (
            "none; the accepted v2 population artifact is diagnostic and its projection remains unexecuted"
        ),
        "schema": "euf-viper.t6-wmi-job-disposition.v1",
    }
    if disposition != expected:
        raise ReportError("historical job 146075 disposition drift")
    return disposition


def atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = (
        json.dumps(payload, allow_nan=False, ensure_ascii=True, indent=2, sort_keys=True)
        + "\n"
    )
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(data, encoding="ascii", newline="\n")
    temporary.replace(path)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--corpus-root", required=True, type=Path)
    parser.add_argument("--metadata", required=True, type=Path)
    parser.add_argument("--run-log", required=True, type=Path)
    parser.add_argument("--toolchain-attestation", required=True, type=Path)
    parser.add_argument("--historical-job-disposition", required=True, type=Path)
    parser.add_argument("--expected-revision", required=True)
    parser.add_argument("--job-id", required=True, type=int)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.job_id == HISTORICAL_HARD10_JOB_ID:
        raise ReportError("historical hard10 job 146075 cannot be reclassified as a v2 census")
    manifest, manifest_bytes = strict_load(args.manifest)
    if sha256_bytes(manifest_bytes) != MANIFEST_SHA256:
        raise ReportError("frozen T6 manifest artifact hash mismatch")
    report, _ = strict_load(args.report)
    gate = validate_report(report, manifest, args.expected_revision)
    toolchain, _ = strict_load(args.toolchain_attestation)
    environment = validate_attestation(toolchain)
    validate_runtime_bindings(
        environment,
        args.expected_revision,
        args.corpus_root,
        args.manifest,
        args.report,
    )
    disposition = validate_disposition(args.historical_job_disposition)
    artifacts = {
        "historical_job_disposition": args.historical_job_disposition,
        "manifest": args.manifest,
        "report": args.report,
        "run": args.run_log,
        "toolchain_attestation": args.toolchain_attestation,
    }
    payload = {
        "schema": "euf-viper.t6-theory-dag-wmi-run.v3",
        "state": "completed",
        "analysis_kind": "source_only_structural_projection",
        "revision": args.expected_revision,
        "job_id": args.job_id,
        "hostname": platform.node(),
        "gate": {
            **gate,
            "scope": "current_p0_qg7_derived_10_of_12",
            "required_qualifying_sources": REQUIRED_QUALIFYING_SOURCES,
            "implementation_or_promotion_eligible": False,
        },
        "population_status": "accepted",
        "projection_status": "completed",
        "implementation_or_promotion_eligible": False,
        "historical_job_146075": disposition,
        "validation": {
            "expected_sources": EXPECTED_SOURCES,
            "observed_sources": len(report["sources"]),
            "rows_recomputed": EXPECTED_SOURCES,
        },
        "artifacts": {
            name: {"path": str(path.resolve()), "sha256": sha256_file(path)}
            for name, path in artifacts.items()
        },
    }
    atomic_write_json(args.metadata, payload)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ReportError as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(2) from error
