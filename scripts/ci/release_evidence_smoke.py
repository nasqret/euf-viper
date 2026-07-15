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


def artifact_record(path: Path) -> dict[str, object]:
    resolved = path.resolve(strict=True)
    return {"path": str(resolved), "sha256": sha256(resolved)}


def executable_record(path: Path) -> dict[str, object]:
    resolved = path.resolve(strict=True)
    metadata = resolved.stat()
    if not resolved.is_file() or not os.access(resolved, os.X_OK):
        raise SystemExit(f"receipt executable is not runnable: {resolved}")
    return {
        "path": str(path.absolute()),
        "realpath": str(resolved),
        "sha256": sha256(resolved),
        "bytes": metadata.st_size,
    }


def write_corpus_view(
    kind: str,
    sources: list[Path],
    manifest: Path,
    taxonomy: Path,
    split: Path,
) -> None:
    manifest.parent.mkdir(parents=True, exist_ok=True)
    taxonomy.parent.mkdir(parents=True, exist_ok=True)
    split.parent.mkdir(parents=True, exist_ok=True)
    manifest.write_bytes(
        b"".join(
            canonical(
                {
                    "bytes": source.stat().st_size,
                    "id": index,
                    "path": str(source),
                    "relative_path": f"family/sat-{index}.smt2",
                    "sha256": sha256(source),
                    "status": "sat",
                }
            )
            for index, source in enumerate(sources)
        )
    )
    taxonomy.write_bytes(
        b"".join(
            canonical(
                {
                    "family": "release-smoke",
                    "lineage": "ci/release-smoke",
                    "normalized_sha256": sha256(source),
                    "relative_path": f"family/sat-{index}.smt2",
                    "split": "development",
                }
            )
            for index, source in enumerate(sources)
        )
    )
    split.write_bytes(
        canonical(
            {
                "kind": kind,
                "manifest_sha256": sha256(manifest),
                "relative_paths": [
                    f"family/sat-{index}.smt2" for index in range(len(sources))
                ],
                "taxonomy_sha256": sha256(taxonomy),
            }
        )
    )


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
    parser.add_argument("--baseline-oracle", type=Path, required=True)
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
        sealed_build.get("schema") != "euf-viper.sealed-linux-build.v3"
        or sealed_build.get("status") != "built"
    ):
        raise SystemExit("release smoke received an invalid sealed build manifest")

    report = run([feature_report], cwd=repository).stdout.decode("ascii").strip()
    features = report.split(",") if report else []
    expected_features = [
        "certificates",
        "default",
        "finite-symmetry",
        "production-evidence",
    ]
    if features != expected_features:
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
            "--oracle",
            args.baseline_oracle.resolve(strict=True),
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

        run_root = root / "locked-audit"
        (run_root / "locks").mkdir(parents=True)
        solver_config = run_root / "solver-config.json"
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
        instance = corpus / "family" / "sat-0.smt2"
        second_instance = corpus / "family" / "sat-1.smt2"
        instance.parent.mkdir(parents=True)
        instance.write_bytes(sat_source.read_bytes())
        second_instance.write_text(
            "(set-logic QF_UF)\n"
            "(set-info :status sat)\n"
            "(declare-fun q () Bool)\n"
            "(assert q)\n"
            "(check-sat)\n",
            encoding="ascii",
        )
        manifests = {
            kind: run_root / "manifests" / f"{kind}.jsonl"
            for kind in ("full", "official")
        }
        taxonomies = {
            kind: run_root / "taxonomy" / f"{kind}.jsonl"
            for kind in ("full", "official")
        }
        taxonomy_splits = {
            kind: run_root / "taxonomy" / f"{kind}-split.json"
            for kind in ("full", "official")
        }
        write_corpus_view(
            "full",
            [instance, second_instance],
            manifests["full"],
            taxonomies["full"],
            taxonomy_splits["full"],
        )
        write_corpus_view(
            "official",
            [instance],
            manifests["official"],
            taxonomies["official"],
            taxonomy_splits["official"],
        )
        if (
            manifests["full"] == manifests["official"]
            or sha256(manifests["full"]) == sha256(manifests["official"])
            or taxonomies["full"] == taxonomies["official"]
            or sha256(taxonomies["full"]) == sha256(taxonomies["official"])
        ):
            raise SystemExit("full and official smoke corpus identities are not distinct")
        analysis_payloads: dict[str, dict[str, object]] = {}
        validation_payloads: dict[str, dict[str, object]] = {}
        for kind in ("full", "official"):
            parent_lock = run_root / "locks" / f"{kind}-parent.json"
            output_root = run_root / f"{kind}-2s"
            run(
                [
                    python,
                    repository / "scripts/bench/freeze_campaign.py",
                    repository / "campaigns/best-overall-qf-uf-2026-07.json",
                    "--manifest",
                    manifests[kind],
                    "--taxonomy",
                    taxonomies[kind],
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
                    parent_lock,
                ],
                cwd=repository,
            )
            prepared_locks = run_root / "locks" / f"{kind}-prepared"
            bound_locks = run_root / "locks" / kind
            run(
                [
                    python,
                    repository / "scripts/bench/shard_campaign_lock.py",
                    parent_lock,
                    "--count",
                    "2",
                    "--out-dir",
                    prepared_locks,
                ],
                cwd=repository,
            )
            for index in range(2):
                prepared = prepared_locks / f"lock-{index:04d}.json"
                bound = bound_locks / f"bound-{index:04d}.json"
                run(
                    [
                        python,
                        repository / "scripts/bench/bind_campaign_cpu.py",
                        prepared,
                        "--out",
                        bound,
                    ],
                    cwd=repository,
                )
                run(
                    [
                        python,
                        repository / "scripts/bench/run_locked_campaign.py",
                        bound,
                    ],
                    cwd=repository,
                )
                raw = output_root / f"shard-{index:04d}" / "raw.jsonl"
                if not raw.is_file():
                    raise SystemExit(
                        f"miniature locked runner omitted {kind} shard {index} raw"
                    )

            analysis = run_root / "audit" / kind / "global.json"
            analysis.parent.mkdir(parents=True, exist_ok=True)
            completed = run(
                [
                    python,
                    repository / "scripts/bench/analyze_campaign.py",
                    "--parent-lock",
                    parent_lock,
                    "--shard-lock-dir",
                    bound_locks,
                    "--shard-results-root",
                    output_root,
                    "--bootstrap-replicates",
                    "64",
                    "--out",
                    analysis,
                ],
                cwd=repository,
                allowed={0, 1},
            )
            report_payload = json.loads(analysis.read_bytes())
            expected_instances = 2 if kind == "full" else 1
            if (
                report_payload.get("inputs", {}).get("instances")
                != expected_instances
                or len(report_payload.get("inputs", {}).get("shards", [])) != 2
            ):
                raise SystemExit(
                    f"miniature {kind} analyzer did not validate two exact shards"
                )
            expected_exit = 0 if report_payload.get("promoted") is True else 1
            if completed.returncode != expected_exit:
                raise SystemExit(
                    f"miniature {kind} analyzer report contradicts its exit status"
                )
            validation = run(
                [
                    python,
                    repository / "scripts/wmi/finalize_locked_audit.py",
                    "--run-root",
                    run_root,
                    "--shards",
                    "2",
                    "--validate-analysis",
                    kind,
                    "--expected-analysis-exit",
                    str(expected_exit),
                ],
                cwd=repository,
            )
            validation_payload = json.loads(validation.stdout)
            if (
                validation_payload.get("kind") != kind
                or validation_payload.get("expected_analysis_exit") != expected_exit
                or validation_payload.get("analysis_sha256") != sha256(analysis)
            ):
                raise SystemExit(
                    f"miniature {kind} validation receipt does not bind analysis bytes"
                )
            analysis_payloads[kind] = report_payload
            validation_payloads[kind] = validation_payload

        audit_index = run_root / "audit" / "index.json"
        parent_payloads = {
            kind: json.loads(
                (run_root / "locks" / f"{kind}-parent.json").read_bytes()
            )
            for kind in ("full", "official")
        }
        revisions = {
            payload.get("repository", {}).get("commit")
            for payload in parent_payloads.values()
        }
        if revisions != {sealed_build.get("revision")}:
            raise SystemExit(
                "smoke parent locks do not bind the sealed repository revision"
            )
        source_snapshot = sealed_build.get("source_snapshot")
        if not isinstance(source_snapshot, dict) or not isinstance(
            source_snapshot.get("files"), list
        ):
            raise SystemExit("sealed build source snapshot is malformed")
        provenance = {
            "attempt": {
                "checkout": str(repository),
                "id": "linux-release-smoke",
            },
            "environment": {
                "kind": "hosted-linux-ci",
                "platform": sys.platform,
            },
            "execution_environment": {
                name: os.environ.get(name, "")
                for name in ("HOME", "PATH", "RUNNER_OS", "RUNNER_ARCH")
            },
            "manifest_sha256": sha256(args.sealed_build_manifest),
            "revision": sealed_build["revision"],
            "runtime_tools": {"python": executable_record(python)},
            "source_blob_count": len(source_snapshot["files"]),
            "source_blobs_sha256": hashlib.sha256(
                canonical(source_snapshot["files"])
            ).hexdigest(),
            "source_tree": sealed_build["source_tree"],
        }
        execution_closure = run_root / "execution-closure.json"
        execution_closure.write_bytes(
            canonical(sealed_build["build_execution_closure"])
        )
        sealed_attestation = (
            args.sealed_build_manifest.resolve(strict=True).parent
            / "sealed-build-attestation.json"
        ).resolve(strict=True)
        preparation_receipt = run_root / "prepare.json"
        preparation_artifacts = {
            name: artifact_record(run_root / name)
            for name in (
                "solver-config.json",
                "taxonomy/full.jsonl",
                "taxonomy/full-split.json",
                "taxonomy/official.jsonl",
                "taxonomy/official-split.json",
                "locks/full-parent.json",
                "locks/official-parent.json",
            )
        }
        preparation = {
            "schema": "euf-viper.locked-p0-preparation.v3",
            "status": "prepared",
            "attempt": provenance["attempt"],
            "artifacts": preparation_artifacts,
            "build_features": features,
            "corpus": {
                "full_manifest": artifact_record(manifests["full"]),
                "official_manifest": artifact_record(manifests["official"]),
                "root": str(corpus.resolve(strict=True)),
            },
            "environment": provenance["environment"],
            "execution_environment": provenance["execution_environment"],
            "feature_report": executable_record(feature_report),
            "hostname": os.uname().nodename,
            "job": {"id": 1, "submit_directory": str(repository)},
            "paths": {
                "checkout": str(repository),
                "run_root": str(run_root.resolve(strict=True)),
                "submission_manifest": str(
                    args.sealed_build_manifest.resolve(strict=True)
                ),
            },
            "revision": provenance["revision"],
            "runtime_tools": provenance["runtime_tools"],
            "shards": 2,
            "solver_executables": {
                record["id"]: executable_record(Path(record["binary"]))
                for record in config["solvers"]
            },
            "sealed_build": {
                "path": str(args.sealed_build_manifest.resolve(strict=True)),
                "sha256": sha256(args.sealed_build_manifest),
                "source_snapshot_manifest_sha256": sealed_build[
                    "source_snapshot_manifest_sha256"
                ],
                "build_execution_closure_sha256": sealed_build[
                    "build_execution_closure_sha256"
                ],
                "attestation_path": str(sealed_attestation),
                "attestation_sha256": sha256(sealed_attestation),
                "receipt_path": str(sealed_receipt),
                "receipt_sha256": sealed_receipt_sha256,
            },
            "execution_closure": artifact_record(execution_closure),
            "source": {
                "blob_count": provenance["source_blob_count"],
                "blobs_sha256": provenance["source_blobs_sha256"],
                "tree": provenance["source_tree"],
                "snapshot_manifest_sha256": sealed_build[
                    "source_snapshot_manifest_sha256"
                ],
                "build_execution_closure_sha256": sealed_build[
                    "build_execution_closure_sha256"
                ],
            },
            "submission_manifest_sha256": provenance["manifest_sha256"],
            "viper": executable_record(binary),
        }
        preparation_receipt.write_bytes(canonical(preparation))
        preparation_receipt.chmod(0o400)
        preparation_sha256 = sha256(preparation_receipt)
        analysis_binding_arguments: list[str | Path] = []
        for kind in ("full", "official"):
            analysis_binding_arguments.extend(
                [
                    f"--{kind}-analysis-sha256",
                    str(validation_payloads[kind]["analysis_sha256"]),
                    f"--{kind}-analysis-exit",
                    str(validation_payloads[kind]["expected_analysis_exit"]),
                ]
            )
        provenance_argument = json.dumps(
            provenance, sort_keys=True, separators=(",", ":")
        )
        scheduler_receipt = run_root / "audit" / "scheduler.json"
        scheduler_result = run(
            [
                python,
                repository / "scripts/wmi/finalize_locked_audit.py",
                "--out",
                scheduler_receipt,
                "--provenance",
                provenance_argument,
                "--run-root",
                run_root,
                "--prepare-job",
                "1",
                "--shards",
                "2",
                "--audit-job",
                "2",
                "--preparation-receipt",
                preparation_receipt,
                "--preparation-receipt-sha256",
                preparation_sha256,
                "--write-scheduler-receipt",
                *analysis_binding_arguments,
            ],
            cwd=repository,
        )
        scheduler_payload = json.loads(scheduler_result.stdout)
        if (
            scheduler_payload.get("jobs") != {"prepare": 1, "audit": 2}
            or scheduler_payload.get("preparation_receipt", {}).get("sha256")
            != preparation_sha256
            or any(
                scheduler_payload.get("analyses", {}).get(kind, {}).get("sha256")
                != validation_payloads[kind]["analysis_sha256"]
                for kind in ("full", "official")
            )
        ):
            raise SystemExit("scheduler receipt did not preserve validated bindings")
        scheduler_sha256 = sha256(scheduler_receipt)
        run(
            [
                python,
                repository / "scripts/wmi/finalize_locked_audit.py",
                "--out",
                audit_index,
                "--provenance",
                json.dumps(provenance, sort_keys=True, separators=(",", ":")),
                "--run-root",
                run_root,
                "--prepare-job",
                "1",
                "--shards",
                "2",
                "--audit-job",
                "2",
                "--preparation-receipt",
                preparation_receipt,
                "--preparation-receipt-sha256",
                preparation_sha256,
                "--scheduler-receipt",
                scheduler_receipt,
                "--scheduler-receipt-sha256",
                scheduler_sha256,
                *analysis_binding_arguments,
            ],
            cwd=repository,
        )
        index_payload = json.loads(audit_index.read_bytes())
        for kind, report_payload in analysis_payloads.items():
            indexed = index_payload.get("analyses", {}).get(kind, {})
            if (
                indexed.get("sha256") != sha256(run_root / "audit" / kind / "global.json")
                or indexed.get("shards") != 2
                or indexed.get("promoted") != report_payload.get("promoted")
                or indexed.get("validated_process_exit")
                != validation_payloads[kind]["expected_analysis_exit"]
            ):
                raise SystemExit(f"final audit index did not bind {kind} analysis")
        if (
            index_payload.get("preparation_receipt", {}).get("sha256")
            != preparation_sha256
            or index_payload.get("scheduler_receipt", {}).get("sha256")
            != scheduler_sha256
        ):
            raise SystemExit("final audit index omitted receipt consistency bindings")

    print("real release evidence and locked-campaign smoke passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
