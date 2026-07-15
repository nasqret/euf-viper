#!/usr/bin/env python3
"""Run the real Linux release production-evidence contract end to end."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import subprocess
import sys
import tempfile
from pathlib import Path


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def run(
    arguments: list[str | Path],
    *,
    cwd: Path,
    environment: dict[str, str] | None = None,
    allowed: set[int] = {0},
) -> subprocess.CompletedProcess[bytes]:
    completed = subprocess.run(
        [str(value) for value in arguments],
        cwd=cwd,
        capture_output=True,
        check=False,
        env=environment,
    )
    if completed.returncode not in allowed:
        raise SystemExit(
            f"command failed ({completed.returncode}): {arguments!r}\n"
            f"stdout={completed.stdout!r}\nstderr={completed.stderr!r}"
        )
    return completed


def solver_environment(
    binary_hash: str, nonce: str, receipt: Path, receipt_sha256: str
) -> dict[str, str]:
    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("EUF_VIPER_")
    }
    environment.update(
        {
            "EUF_VIPER_RUN_NONCE": nonce,
            "EUF_VIPER_TRUSTED_EXECUTABLE_SHA256": binary_hash,
            "EUF_VIPER_SEALED_BUILD_RECEIPT": str(receipt),
            "EUF_VIPER_SEALED_BUILD_RECEIPT_SHA256": receipt_sha256,
            "LANG": "C",
            "LC_ALL": "C",
        }
    )
    return environment


def solve_with_evidence(
    binary: Path,
    source: Path,
    output: Path,
    binary_hash: str,
    receipt: Path,
    receipt_sha256: str,
    *,
    nonce: str | None = None,
) -> tuple[subprocess.CompletedProcess[bytes], str]:
    nonce = nonce or secrets.token_hex(32)
    completed = run(
        [binary, "solve", source, "--evidence-out", output],
        cwd=source.parent,
        environment=solver_environment(binary_hash, nonce, receipt, receipt_sha256),
        allowed={0, 2, 3},
    )
    return completed, nonce


def check_sidecar(
    python: Path,
    checker: Path,
    source: Path,
    evidence: Path,
    binary_hash: str,
    nonce: str,
    status: str,
    repository: Path,
    receipt_sha256: str,
) -> None:
    run(
        [
            python,
            checker,
            evidence,
            "--source",
            source,
            "--status",
            status,
            "--executable-sha256",
            binary_hash,
            "--evidence-sha256",
            sha256(evidence),
            "--run-nonce",
            nonce,
            "--sealed-build-receipt-sha256",
            receipt_sha256,
        ],
        cwd=repository,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--feature-report", type=Path, required=True)
    parser.add_argument("--sealed-build-manifest", type=Path, required=True)
    parser.add_argument("--sealed-build-receipt", type=Path, required=True)
    parser.add_argument("--baseline-binary", type=Path, required=True)
    parser.add_argument("--baseline-receipt", type=Path, required=True)
    parser.add_argument("--z3", type=Path, required=True)
    parser.add_argument("--cvc5", type=Path, required=True)
    parser.add_argument("--yices2", type=Path, required=True)
    parser.add_argument("--opensmt", type=Path, required=True)
    args = parser.parse_args()

    repository = args.repository.resolve(strict=True)
    binary = args.binary.resolve(strict=True)
    feature_report = args.feature_report.resolve(strict=True)
    comparators = {
        "z3": args.z3.resolve(strict=True),
        "cvc5": args.cvc5.resolve(strict=True),
        "yices2": args.yices2.resolve(strict=True),
        "opensmt": args.opensmt.resolve(strict=True),
    }
    python = Path(sys.executable).resolve(strict=True)
    checker = repository / "scripts/cert/check_production_evidence.py"
    binary_hash = sha256(binary)
    sealed_build = json.loads(args.sealed_build_manifest.read_bytes())
    sealed_receipt = args.sealed_build_receipt.resolve(strict=True)
    sealed_receipt_sha256 = sha256(sealed_receipt)
    if (
        sealed_build.get("schema") != "euf-viper.sealed-linux-build.v2"
        or sealed_build.get("status") != "built"
    ):
        raise SystemExit("release smoke received an invalid sealed build manifest")

    report = run([feature_report], cwd=repository).stdout.decode("ascii").strip()
    features = report.split(",") if report else []
    if len(features) != len(set(features)) or not {
        "certificates",
        "production-evidence",
    } <= set(features):
        raise SystemExit(f"release feature report is incomplete or malformed: {report!r}")

    run(
        [
            python,
            repository / "scripts/ci/check_ordinary_cli_contract.py",
            "--binary",
            binary,
            "--repository",
            repository,
            "--baseline-binary",
            args.baseline_binary.resolve(strict=True),
            "--baseline-receipt",
            args.baseline_receipt.resolve(strict=True),
        ],
        cwd=repository,
    )

    with tempfile.TemporaryDirectory(prefix="euf-viper-release-smoke-") as raw_directory:
        root = Path(raw_directory)
        sat_source = root / "sat.smt2"
        sat_source.write_text(
            "(set-logic QF_UF)\n"
            "(set-info :status sat)\n"
            "(declare-fun p () Bool)\n"
            "(assert p)\n"
            "(check-sat)\n",
            encoding="ascii",
        )
        sat_evidence = root / "sat.evidence.json"
        completed, sat_nonce = solve_with_evidence(
            binary,
            sat_source,
            sat_evidence,
            binary_hash,
            sealed_receipt,
            sealed_receipt_sha256,
        )
        if (completed.returncode, completed.stdout) != (0, b"sat\n"):
            raise SystemExit(
                f"release SAT evidence solve was not decisive: "
                f"{completed.returncode}, {completed.stdout!r}, {completed.stderr!r}"
            )
        check_sidecar(
            python,
            checker,
            sat_source,
            sat_evidence,
            binary_hash,
            sat_nonce,
            "sat",
            repository,
            sealed_receipt_sha256,
        )
        sat_payload = json.loads(sat_evidence.read_bytes())
        build = sat_payload.get("solver", {}).get("build", {})
        if (
            build.get("sealed_source_manifest_sha256")
            != sealed_build.get("source_snapshot_manifest_sha256")
            or build.get("execution_closure_sha256")
            != sealed_build.get("build_execution_closure_sha256")
        ):
            raise SystemExit("release sidecar does not bind the exact sealed build manifests")

        unsat_source = root / "unsat.smt2"
        unsat_source.write_text(
            "(set-logic QF_UF)\n"
            "(set-info :status unsat)\n"
            "(declare-fun p () Bool)\n"
            "(assert p)\n"
            "(assert (not p))\n"
            "(check-sat)\n",
            encoding="ascii",
        )
        unsat_evidence = root / "unsat.evidence.json"
        completed, unsat_nonce = solve_with_evidence(
            binary,
            unsat_source,
            unsat_evidence,
            binary_hash,
            sealed_receipt,
            sealed_receipt_sha256,
        )
        if (completed.returncode, completed.stdout) != (3, b"unsupported\n"):
            raise SystemExit(
                f"release UNSAT did not fail closed: "
                f"{completed.returncode}, {completed.stdout!r}, {completed.stderr!r}"
            )
        unsat_payload = json.loads(unsat_evidence.read_bytes())
        if (unsat_payload.get("status"), unsat_payload.get("backend_status")) != (
            "unsupported",
            "unsat",
        ):
            raise SystemExit("UNSAT sidecar has a decisive or incoherent status")
        check_sidecar(
            python,
            checker,
            unsat_source,
            unsat_evidence,
            binary_hash,
            unsat_nonce,
            "unsupported",
            repository,
            sealed_receipt_sha256,
        )
        rejected = run(
            [
                python,
                checker,
                unsat_evidence,
                "--source",
                unsat_source,
                "--status",
                "sat",
                "--executable-sha256",
                binary_hash,
                "--sealed-build-receipt-sha256",
                sealed_receipt_sha256,
            ],
            cwd=repository,
            allowed={1},
        )
        expected_rejection = (
            b"evidence status mismatch: expected 'sat', got 'unsupported'"
        )
        if expected_rejection not in rejected.stderr:
            raise SystemExit(
                "checker rejected UNSAT-as-SAT without the required status diagnostic"
            )

        existing = root / "existing.json"
        existing.write_bytes(b"do-not-replace\n")
        completed, _ = solve_with_evidence(
            binary,
            sat_source,
            existing,
            binary_hash,
            sealed_receipt,
            sealed_receipt_sha256,
        )
        if completed.returncode != 2 or completed.stdout or existing.read_bytes() != b"do-not-replace\n":
            raise SystemExit("existing evidence target was replaced or yielded a result")

        victim = root / "victim.json"
        victim.write_bytes(b"victim\n")
        output_link = root / "output-link.json"
        output_link.symlink_to(victim)
        completed, _ = solve_with_evidence(
            binary,
            sat_source,
            output_link,
            binary_hash,
            sealed_receipt,
            sealed_receipt_sha256,
        )
        if completed.returncode != 2 or completed.stdout or victim.read_bytes() != b"victim\n":
            raise SystemExit("symlinked evidence output escaped no-follow publication")

        source_link = root / "source-link.smt2"
        source_link.symlink_to(sat_source)
        completed, _ = solve_with_evidence(
            binary,
            source_link,
            root / "source-link.json",
            binary_hash,
            sealed_receipt,
            sealed_receipt_sha256,
        )
        if completed.returncode != 2 or completed.stdout:
            raise SystemExit("symlinked source was accepted in evidence mode")

        raced = root / "raced.json"
        processes: list[tuple[subprocess.Popen[bytes], str]] = []
        for _ in range(2):
            nonce = secrets.token_hex(32)
            process = subprocess.Popen(
                [str(binary), "solve", str(sat_source), "--evidence-out", str(raced)],
                cwd=root,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=solver_environment(
                    binary_hash, nonce, sealed_receipt, sealed_receipt_sha256
                ),
            )
            processes.append((process, nonce))
        results = [(process.wait(), *process.communicate(), nonce) for process, nonce in processes]
        winners = [record for record in results if record[0] == 0 and record[1] == b"sat\n"]
        losers = [record for record in results if record[0] == 2 and record[1] == b""]
        if len(winners) != 1 or len(losers) != 1:
            raise SystemExit(f"evidence publication race did not have one winner: {results!r}")
        winning_nonce = json.loads(raced.read_bytes())["run_nonce"]
        if winning_nonce != winners[0][3]:
            raise SystemExit("published race sidecar does not belong to the decisive process")

        solver_config = root / "solver-config.json"
        run(
            [
                python,
                repository / "scripts/bench/record_solver_config.py",
                "--campaign",
                repository / "campaigns/best-overall-qf-uf-2026-07.json",
                "--viper",
                binary,
                "--viper-feature-report",
                feature_report,
                "--viper-sealed-build-receipt",
                sealed_receipt,
                "--viper-version",
                "release-evidence-smoke",
                "--z3",
                comparators["z3"],
                "--cvc5",
                comparators["cvc5"],
                "--yices2",
                comparators["yices2"],
                "--opensmt",
                comparators["opensmt"],
                "--smoke-instance",
                sat_source,
                "--smoke-expected",
                "sat",
                "--out",
                solver_config,
            ],
            cwd=repository,
        )
        config = json.loads(solver_config.read_bytes())
        candidate = next(record for record in config["solvers"] if record["id"] == "euf-viper")
        if candidate.get("binary") != str(binary) or candidate.get("evidence", {}).get(
            "accepted_decisive_statuses"
        ) != ["sat"]:
            raise SystemExit("real recorder did not bind the compiled evidence solver")

        corpus = root / "corpus"
        instance = corpus / "family" / "sat.smt2"
        instance.parent.mkdir(parents=True)
        instance.write_bytes(sat_source.read_bytes())
        manifest = root / "manifest.jsonl"
        manifest.write_bytes(
            canonical(
                {
                    "bytes": instance.stat().st_size,
                    "id": 0,
                    "path": str(instance),
                    "relative_path": "family/sat.smt2",
                    "sha256": sha256(instance),
                    "status": "sat",
                }
            )
        )
        taxonomy = root / "taxonomy.jsonl"
        taxonomy.write_bytes(
            canonical(
                {
                    "family": "release-smoke",
                    "lineage": "ci/release-smoke",
                    "normalized_sha256": sha256(instance),
                    "relative_path": "family/sat.smt2",
                    "split": "development",
                }
            )
        )
        lock = root / "locked.json"
        output_root = root / "campaign-output"
        run(
            [
                python,
                repository / "scripts/bench/freeze_campaign.py",
                repository / "campaigns/best-overall-qf-uf-2026-07.json",
                "--manifest",
                manifest,
                "--taxonomy",
                taxonomy,
                "--solver-config",
                solver_config,
                "--repository",
                repository,
                "--corpus-root",
                corpus,
                "--cpu-id",
                "0",
                "--memory-bytes",
                str(2 * 1024**3),
                "--order",
                "balanced_latin_square",
                "--budget",
                "2",
                "--output-directory",
                output_root,
                "--out",
                lock,
            ],
            cwd=repository,
        )
        run(
            [python, repository / "scripts/bench/run_locked_campaign.py", lock],
            cwd=repository,
        )
        raw = output_root / "raw.jsonl"
        if not raw.is_file():
            raise SystemExit("miniature locked runner omitted raw.jsonl")
        analysis = root / "analysis.json"
        run(
            [
                python,
                repository / "scripts/bench/analyze_campaign.py",
                raw,
                "--lock",
                lock,
                "--baseline",
                "z3-default",
                "--bootstrap-replicates",
                "64",
                "--out",
                analysis,
            ],
            cwd=repository,
            allowed={0, 1},
        )
        report_payload = json.loads(analysis.read_bytes())
        if report_payload.get("inputs", {}).get("instances") != 1:
            raise SystemExit("miniature locked analyzer did not validate exactly one instance")

    print("real release evidence and locked-campaign smoke passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
