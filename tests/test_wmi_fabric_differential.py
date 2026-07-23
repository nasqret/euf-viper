from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SBATCH = ROOT / "scripts" / "wmi" / "euf_viper_fabric_differential.sbatch"
SUBMIT = ROOT / "scripts" / "wmi" / "submit_fabric_differential.sh"
SCRIPTS = (SBATCH, SUBMIT)

TARGET_REVISION = "a" * 40
GENERATOR_VERSION = 1
SEED = 7640891576956012809
FIRST_CASE = 0
CASE_COUNT = 1_000_000
LAST_CASE = 999_999
SMOKE_REVISION = "51fc7d31a0e499fc9ffc4c30bf9227e6b8c0fdcc"
SMOKE_MANIFEST_SHA256 = (
    "84364115fb1b169f96d3e78885ecbf4609e0d935f5aff21aa1b89cddb5d3e291"
)
SMOKE_ROWS = 2
SMOKE_JOB_ID = 169653


def embedded_python(path: Path, marker: str) -> str:
    text = path.read_text(encoding="ascii")
    match = re.search(
        rf"<<'{re.escape(marker)}'\n(?P<body>.*?)\n{re.escape(marker)}$",
        text,
        re.MULTILINE | re.DOTALL,
    )
    if match is None:
        raise AssertionError(f"missing embedded Python block {marker} in {path}")
    return match.group("body")


AUTHORIZATION_VALIDATOR = embedded_python(SUBMIT, "PY_AUTHORIZATION")
BATCH_AUTHORIZATION_VALIDATOR = embedded_python(SBATCH, "PY_VALIDATE_AUTHORIZATION")
OUTPUT_VALIDATOR = embedded_python(SBATCH, "PY_VALIDATE_OUTPUT")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def encoded_json(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=True, allow_nan=False, indent=2, sort_keys=True)
        + "\n"
    ).encode("ascii")


class AuthorizationFixture:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.audit_path = root / "smoke-audit.json"
        self.authorization_path = root / "authorization.json"
        self.audit = self.make_audit()
        self.authorization = self.make_authorization()
        self.write()

    def make_audit(self) -> dict[str, object]:
        artifact_names = (
            "fabric-shadow.jsonl",
            "summary.json",
            "slurm.json",
            "euf-viper",
            "stdout.log",
            "stderr.log",
        )
        return {
            "schema": "euf-viper.fabric-shadow-offline-audit.v1",
            "status": "verified",
            "scope": {
                "stage": "F0",
                "mode": "semantic_substrate_shadow_census",
                "default_behavior_change": False,
                "solver_result_claim": False,
                "performance_claim": False,
                "promotion_claim": False,
                "solver_result_claims_allowed": 0,
                "verification": "complete_bound_shadow_census_artifact",
                "verified": True,
            },
            "revision": SMOKE_REVISION,
            "corpus_mode": "smoke",
            "job_id": SMOKE_JOB_ID,
            "operator_expectations": {
                "revision": SMOKE_REVISION,
                "manifest_sha256": SMOKE_MANIFEST_SHA256,
                "corpus_mode": "smoke",
                "row_count": SMOKE_ROWS,
                "slurm_job_id": SMOKE_JOB_ID,
                "source": "independent_operator_input",
            },
            "manifest": {
                "sha256": SMOKE_MANIFEST_SHA256,
                "rows": SMOKE_ROWS,
                "corpus_root": "/home/test/read-only-corpus",
            },
            "bindings": {
                "input_binding_sha256": "1" * 64,
                "solver_sha256": "2" * 64,
                "runner_sha256": "3" * 64,
                "cargo_sha256": "4" * 64,
                "rustc_sha256": "5" * 64,
                "python_sha256": "6" * 64,
            },
            "counts": {
                "manifest_rows": SMOKE_ROWS,
                "completed_rows": SMOKE_ROWS,
                "error_rows": 0,
                "missing_rows": 0,
                "duplicate_rows": 0,
                "solver_result_claims": 0,
            },
            "inputs": {
                "artifact_directory": "/tmp/fetched-fabric-smoke/artifacts",
                "submission_receipt": {
                    "path": "/tmp/fetched-fabric-smoke/submission.json",
                    "sha256": "7" * 64,
                    "bytes": 1024,
                },
                "artifacts": {
                    name: {
                        "path": f"/tmp/fetched-fabric-smoke/artifacts/{name}",
                        "sha256": hashlib.sha256(name.encode("ascii")).hexdigest(),
                        "bytes": index,
                    }
                    for index, name in enumerate(artifact_names)
                },
            },
            "audited_at": "2026-07-22T12:34:56Z",
        }

    def make_authorization(self) -> dict[str, object]:
        audit_hash = sha256_bytes(encoded_json(self.audit))
        return {
            "schema": "euf-viper.fabric-differential-authorization.v1",
            "status": "authorized",
            "decision": "submit_one_wmi_fabric_differential",
            "authorization_id": "fabric-diff-review-20260722",
            "authorized_by": "independent-reviewer",
            "authorized_at": "2026-07-22T13:00:00Z",
            "target": {
                "revision": TARGET_REVISION,
                "generator_version": GENERATOR_VERSION,
                "seed": SEED,
                "first_case": FIRST_CASE,
                "case_count": CASE_COUNT,
                "last_case": LAST_CASE,
                "cpus_per_task": 1,
                "command": [
                    "euf-viper",
                    "fabric-differential",
                    "--cases",
                    str(CASE_COUNT),
                    "--first",
                    str(FIRST_CASE),
                    "--seed",
                    str(SEED),
                ],
            },
            "audited_smoke": {
                "receipt_path": str(self.audit_path),
                "receipt_sha256": audit_hash,
                "revision": SMOKE_REVISION,
                "manifest_sha256": SMOKE_MANIFEST_SHA256,
                "rows": SMOKE_ROWS,
                "job_id": SMOKE_JOB_ID,
            },
        }

    def write(
        self,
        *,
        authorization: dict[str, object] | None = None,
        audit: dict[str, object] | None = None,
        refresh_audit_binding: bool = True,
    ) -> tuple[dict[str, object], dict[str, object]]:
        audit_value = copy.deepcopy(self.audit if audit is None else audit)
        authorization_value = copy.deepcopy(
            self.authorization if authorization is None else authorization
        )
        audit_bytes = encoded_json(audit_value)
        self.audit_path.write_bytes(audit_bytes)
        if refresh_audit_binding:
            authorization_value["audited_smoke"]["receipt_path"] = str(  # type: ignore[index]
                self.audit_path
            )
            authorization_value["audited_smoke"]["receipt_sha256"] = (  # type: ignore[index]
                sha256_bytes(audit_bytes)
            )
        self.authorization_path.write_bytes(encoded_json(authorization_value))
        return authorization_value, audit_value


class WmiFabricDifferentialTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.work = Path(self.temporary.name).resolve()
        self.fixture = AuthorizationFixture(self.work)
        self.validation_index = 0

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def text(self, path: Path) -> str:
        return path.read_text(encoding="ascii")

    def validator_arguments(self, snapshot_root: Path) -> list[str]:
        return [
            str(self.fixture.authorization_path),
            str(snapshot_root),
            TARGET_REVISION,
            str(GENERATOR_VERSION),
            str(SEED),
            str(FIRST_CASE),
            str(CASE_COUNT),
            str(LAST_CASE),
            SMOKE_REVISION,
            SMOKE_MANIFEST_SHA256,
            str(SMOKE_ROWS),
            str(SMOKE_JOB_ID),
        ]

    def run_authorization_validator(self) -> subprocess.CompletedProcess[str]:
        self.validation_index += 1
        snapshot_root = self.work / f"snapshots-{self.validation_index}"
        snapshot_root.mkdir()
        return subprocess.run(
            [sys.executable, "-", *self.validator_arguments(snapshot_root)],
            input=AUTHORIZATION_VALIDATOR,
            text=True,
            capture_output=True,
            check=False,
        )

    def run_batch_authorization_validator(self) -> subprocess.CompletedProcess[str]:
        authorization_hash = sha256_bytes(self.fixture.authorization_path.read_bytes())
        audit_hash = sha256_bytes(self.fixture.audit_path.read_bytes())
        arguments = [
            str(self.fixture.authorization_path),
            str(self.fixture.audit_path),
            authorization_hash,
            audit_hash,
            TARGET_REVISION,
            str(SEED),
            str(FIRST_CASE),
            str(CASE_COUNT),
            str(LAST_CASE),
            SMOKE_REVISION,
            SMOKE_MANIFEST_SHA256,
            str(SMOKE_ROWS),
            str(SMOKE_JOB_ID),
        ]
        return subprocess.run(
            [sys.executable, "-", *arguments],
            input=BATCH_AUTHORIZATION_VALIDATOR,
            text=True,
            capture_output=True,
            check=False,
        )

    def valid_output(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "status": "complete",
            "generator_version": GENERATOR_VERSION,
            "seed": SEED,
            "first_case": FIRST_CASE,
            "cases_run": CASE_COUNT,
            "sat_cases": 600_000,
            "unsat_cases": 400_000,
            "abstained_cases": 0,
            "oracle_cases": CASE_COUNT,
            "oracle_skipped": 0,
            "total_terms": 4_000_000,
            "total_atoms": 3_000_000,
            "total_expression_nodes": 8_000_000,
            "campaign_fingerprint": 123456789,
            "elapsed_ns": 987654321,
        }

    def run_output_validator(
        self,
        payload: dict[str, object] | None = None,
        *,
        raw: bytes | None = None,
        arguments: list[str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        output = self.work / f"stdout-{self.validation_index}.json"
        self.validation_index += 1
        output.write_bytes(
            raw
            if raw is not None
            else (
                json.dumps(
                    self.valid_output() if payload is None else payload,
                    ensure_ascii=True,
                    allow_nan=False,
                    separators=(",", ":"),
                )
                + "\n"
            ).encode("ascii")
        )
        validator_arguments = arguments or [
            str(GENERATOR_VERSION),
            str(SEED),
            str(FIRST_CASE),
            str(CASE_COUNT),
            str(LAST_CASE),
        ]
        return subprocess.run(
            [sys.executable, "-", str(output), *validator_arguments],
            input=OUTPUT_VALIDATOR,
            text=True,
            capture_output=True,
            check=False,
        )

    def test_shell_syntax_and_embedded_python(self) -> None:
        completed = subprocess.run(
            ["bash", "-n", *(str(path) for path in SCRIPTS)],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        markers = {
            SBATCH: (
                "PY_VALIDATE_AUTHORIZATION",
                "PY_VALIDATE_OUTPUT",
                "PY_METADATA",
                "PY_FSYNC",
                "PY_FSYNC_PARENT",
            ),
            SUBMIT: ("PY_AUTHORIZATION", "PY_SUBMISSION_RECEIPT"),
        }
        for path, expected_markers in markers.items():
            for marker in expected_markers:
                with self.subTest(path=path.name, marker=marker):
                    compile(embedded_python(path, marker), f"{path}:{marker}", "exec")
        for path in SCRIPTS:
            self.assertTrue(os.access(path, os.X_OK), f"{path} is not executable")

    def test_submission_is_unreachable_without_explicit_receipt(self) -> None:
        fake_bin = self.work / "fake-bin"
        fake_bin.mkdir()
        marker = self.work / "ssh-was-called"
        fake_ssh = fake_bin / "ssh"
        fake_ssh.write_text(
            f"#!/bin/sh\ntouch {marker!s}\nexit 99\n", encoding="ascii"
        )
        fake_ssh.chmod(0o755)
        environment = dict(os.environ)
        environment["PATH"] = f"{fake_bin}:{environment['PATH']}"
        environment["EUF_VIPER_FABRIC_DIFF_ENABLE"] = "1"
        environment["EUF_VIPER_FABRIC_DIFF_WORK_ROOT"] = "/work/test/fabric"
        completed = subprocess.run(
            ["bash", str(SUBMIT)],
            cwd=ROOT,
            env=environment,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 2)
        self.assertIn("--authorization-receipt is required", completed.stderr)
        self.assertFalse(marker.exists())

    def test_batch_is_default_off_without_bound_environment(self) -> None:
        completed = subprocess.run(
            ["bash", str(SBATCH)],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 2)
        self.assertIn("default-off", completed.stderr)

    def test_exact_one_core_campaign_is_frozen_in_both_scripts(self) -> None:
        for path in SCRIPTS:
            text = self.text(path)
            with self.subTest(path=path.name):
                self.assertIn("CAMPAIGN_SEED=7640891576956012809", text)
                self.assertIn("FIRST_CASE=0", text)
                self.assertIn("CASE_COUNT=1000000", text)
                self.assertIn("LAST_CASE=999999", text)
        batch = self.text(SBATCH)
        submit = self.text(SUBMIT)
        for directive in (
            "#SBATCH --nodes=1",
            "#SBATCH --ntasks=1",
            "#SBATCH --cpus-per-task=1",
        ):
            self.assertIn(directive, batch)
        self.assertIn('SLURM_CPUS_PER_TASK:-}" = 1', batch)
        self.assertIn('SLURM_ARRAY_TASK_ID:-}', batch)
        self.assertIn("CARGO_BUILD_JOBS=1", batch)
        self.assertIn("RAYON_NUM_THREADS=1", batch)
        self.assertIn('"$PERSISTED_BINARY" fabric-differential', batch)
        self.assertIn('--cases "$CASE_COUNT"', batch)
        self.assertIn('--first "$FIRST_CASE"', batch)
        self.assertIn('--seed "$CAMPAIGN_SEED"', batch)
        self.assertIn("--nodes=1 --ntasks=1 --cpus-per-task=1", submit)
        self.assertNotIn("--array", submit)

    def test_clean_published_exact_revision_and_no_ambient_source(self) -> None:
        batch = self.text(SBATCH)
        submit = self.text(SUBMIT)
        self.assertIn("git ls-remote --exit-code", submit)
        self.assertIn("refs/heads/perf-viper-fabric-next", submit)
        self.assertIn("HEAD $REVISION is not the published", submit)
        self.assertGreaterEqual(
            submit.count("git status --porcelain=v1 --untracked-files=all"), 2
        )
        self.assertGreaterEqual(
            batch.count("git status --porcelain=v1 --untracked-files=all"), 2
        )
        self.assertIn("checkouts/$REVISION", submit)
        self.assertIn('"$WORK_ROOT"/checkouts/"$EXPECTED_REVISION"', batch)
        self.assertIn("reject_ambient_cargo_configuration", batch)
        self.assertIn("env -i", batch)
        self.assertIn("env -i", submit)
        self.assertNotIn("rsync", submit)
        self.assertNotIn("git reset", submit)
        self.assertNotIn("git clean", submit)
        self.assertNotIn("--export=ALL", submit)

    def test_all_remote_artifacts_homes_and_build_cache_are_under_work(self) -> None:
        batch = self.text(SBATCH)
        submit = self.text(SUBMIT)
        self.assertIn("must be below absolute /work", batch)
        self.assertIn("must be below absolute /work", submit)
        self.assertIn('REMOTE_CARGO_HOME="$REMOTE_WORK_ROOT/cargo-home"', submit)
        self.assertIn('BUILD_ROOT="$RUN_ROOT/.build.$JOB_ID.partial"', batch)
        self.assertIn('RUNTIME_HOME="$RUN_ROOT/.runtime-home.$JOB_ID"', batch)
        self.assertIn('HOME="$BUILD_ROOT/home"', batch)
        self.assertIn('HOME="$RUNTIME_HOME"', batch)
        self.assertIn('TMPDIR="$BUILD_ROOT/tmp"', batch)
        self.assertIn("artifacts and build cache must stay outside remote HOME", batch)
        self.assertIn("work root must be outside remote HOME", submit)
        self.assertNotIn("SLURM_TMPDIR", batch + submit)
        self.assertNotIn("/home/bnaskrecki", batch + submit)

    def test_toolchain_source_binary_and_receipt_hashes_are_bound_twice(self) -> None:
        batch = self.text(SBATCH)
        submit = self.text(SUBMIT)
        for token in (
            "CARGO_SHA256",
            "RUSTC_SHA256",
            "PYTHON_SHA256",
            "EXPECTED_BINARY_SHA256",
            "AUTHORIZATION_SHA256",
            "SMOKE_AUDIT_SHA256",
            "JOB_SCRIPT_SHA256",
            "CARGO_TOML_SHA256",
            "CARGO_LOCK_SHA256",
            "RUST_TOOLCHAIN_SHA256",
        ):
            with self.subTest(token=token):
                self.assertIn(token, batch)
                self.assertIn(token, submit)
        self.assertIn('"$CARGO" build --release --locked --features fabric', batch)
        self.assertIn("'$REMOTE_CARGO' build --release --locked --features fabric", submit)
        self.assertIn("rebuilt binary differs from the submit-time preflight binary", batch)
        self.assertIn("cargo 1.93.0", batch)
        self.assertIn("rustc 1.93.0", batch)
        for drift in (
            "local revision drifted after authorization validation",
            "published target changed after authorization validation",
            "remote revision drifted after preflight build",
            "remote cargo target drifted before submission",
            "remote rustc target drifted before submission",
            "remote python target drifted before submission",
            "remote preflight binary drifted before submission",
            "remote authorization receipt drifted before submission",
            "remote smoke audit receipt drifted before submission",
            "remote job script drifted before submission",
        ):
            with self.subTest(drift=drift):
                self.assertIn(drift, submit)

    def test_authorization_gate_precedes_every_ssh_and_sbatch(self) -> None:
        text = self.text(SUBMIT)
        validation = text.index('AUTHORIZATION_BINDING="$(python3 -')
        first_ssh = text.index('REMOTE_HOME="$(ssh')
        sbatch = text.index("sbatch --parsable")
        self.assertLess(validation, first_ssh)
        self.assertLess(first_ssh, sbatch)
        self.assertEqual(text.count("sbatch --parsable"), 1)
        self.assertIn("--kill-on-invalid-dep=yes", text)
        self.assertIn("write_receipt submission_intent", text)
        self.assertIn("write_receipt submitted", text)

    def test_atomic_artifact_bundle_contains_json_metadata_hashes_and_receipts(self) -> None:
        text = self.text(SBATCH)
        self.assertIn('STAGING_ROOT="$RUN_ROOT/.artifacts.$JOB_ID.partial"', text)
        self.assertIn('FINAL_ROOT="$RUN_ROOT/artifacts"', text)
        self.assertIn('mv "$STAGING_ROOT" "$FINAL_ROOT"', text)
        self.assertIn("sha256sum -c SHA256SUMS", text)
        self.assertIn("os.fsync", text)
        for artifact in (
            "stdout.json",
            "stderr.log",
            "metadata.json",
            "SHA256SUMS",
            "euf-viper",
            "authorization.json",
            "audited-smoke.json",
        ):
            self.assertIn(artifact, text)
        self.assertLess(text.index("PY_VALIDATE_OUTPUT"), text.index('mv "$STDOUT_CANDIDATE"'))
        self.assertLess(text.index("sha256sum -c SHA256SUMS"), text.index('mv "$STAGING_ROOT"'))

    def test_valid_authorization_chain_is_snapshotted_and_revalidated(self) -> None:
        completed = self.run_authorization_validator()
        self.assertEqual(completed.returncode, 0, completed.stderr)
        authorization_hash, audit_hash = completed.stdout.strip().split("\t")
        self.assertEqual(
            authorization_hash,
            sha256_bytes(self.fixture.authorization_path.read_bytes()),
        )
        self.assertEqual(audit_hash, sha256_bytes(self.fixture.audit_path.read_bytes()))
        snapshot_root = self.work / "snapshots-1"
        self.assertEqual(
            (snapshot_root / "authorization.json").read_bytes(),
            self.fixture.authorization_path.read_bytes(),
        )
        self.assertEqual(
            (snapshot_root / "audited-smoke.json").read_bytes(),
            self.fixture.audit_path.read_bytes(),
        )
        batch_completed = self.run_batch_authorization_validator()
        self.assertEqual(batch_completed.returncode, 0, batch_completed.stderr)

    def test_batch_revalidation_rejects_target_and_smoke_tampering(self) -> None:
        authorization = copy.deepcopy(self.fixture.authorization)
        authorization["target"]["seed"] = SEED + 1  # type: ignore[index]
        self.fixture.write(authorization=authorization)
        completed = self.run_batch_authorization_validator()
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("authorized seed", completed.stderr)

        audit = copy.deepcopy(self.fixture.audit)
        audit["counts"]["error_rows"] = 1  # type: ignore[index]
        self.fixture.write(audit=audit)
        completed = self.run_batch_authorization_validator()
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("smoke error_rows", completed.stderr)

    def test_authorization_rejects_target_identity_and_command_drift(self) -> None:
        cases = (
            ("status", "denied", "authorization status"),
            ("decision", "review_only", "authorization decision"),
            ("target.revision", "b" * 40, "authorized target revision"),
            ("target.generator_version", 2, "authorized generator version"),
            ("target.seed", SEED + 1, "authorized seed"),
            ("target.first_case", 1, "authorized first case"),
            ("target.case_count", CASE_COUNT - 1, "authorized case count"),
            ("target.last_case", LAST_CASE - 1, "authorized last case"),
            ("target.cpus_per_task", 2, "authorized CPU count"),
            ("target.command", ["euf-viper", "fabric-differential"], "authorized command"),
        )
        baseline = copy.deepcopy(self.fixture.authorization)
        for name, value, fragment in cases:
            authorization = copy.deepcopy(baseline)
            if name.startswith("target."):
                authorization["target"][name.split(".", 1)[1]] = value  # type: ignore[index]
            else:
                authorization[name] = value
            self.fixture.write(authorization=authorization)
            completed = self.run_authorization_validator()
            with self.subTest(field=name):
                self.assertNotEqual(completed.returncode, 0)
                self.assertIn(fragment, completed.stderr)
        self.fixture.write(authorization=baseline)

    def test_authorization_rejects_any_unverified_or_mismatched_smoke(self) -> None:
        cases = (
            ("status", "failed", "smoke audit status"),
            ("revision", "b" * 40, "smoke audit revision"),
            ("corpus_mode", "full", "smoke audit corpus mode"),
            ("job_id", SMOKE_JOB_ID + 1, "smoke audit job"),
            ("manifest.sha256", "8" * 64, "smoke manifest hash"),
            ("counts.completed_rows", 1, "smoke completed count"),
            ("counts.error_rows", 1, "smoke error_rows"),
            ("counts.missing_rows", 1, "smoke missing_rows"),
            ("counts.duplicate_rows", 1, "smoke duplicate_rows"),
            ("counts.solver_result_claims", 1, "smoke solver_result_claims"),
            ("scope.verified", False, "smoke audit scope"),
            ("scope.solver_result_claim", True, "smoke audit scope"),
        )
        baseline = copy.deepcopy(self.fixture.audit)
        for name, value, fragment in cases:
            audit = copy.deepcopy(baseline)
            parts = name.split(".")
            target = audit
            for part in parts[:-1]:
                target = target[part]  # type: ignore[assignment,index]
            target[parts[-1]] = value  # type: ignore[index]
            self.fixture.write(audit=audit)
            completed = self.run_authorization_validator()
            with self.subTest(field=name):
                self.assertNotEqual(completed.returncode, 0)
                self.assertIn(fragment, completed.stderr)
        self.fixture.write(audit=baseline)

    def test_authorization_rejects_hash_tampering_extra_fields_and_hostile_json(self) -> None:
        authorization = copy.deepcopy(self.fixture.authorization)
        authorization["audited_smoke"]["receipt_sha256"] = "0" * 64  # type: ignore[index]
        self.fixture.write(
            authorization=authorization,
            refresh_audit_binding=False,
        )
        completed = self.run_authorization_validator()
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("authorized smoke receipt hash", completed.stderr)

        authorization = copy.deepcopy(self.fixture.authorization)
        authorization["unexpected"] = True
        self.fixture.write(authorization=authorization)
        completed = self.run_authorization_validator()
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("extra=['unexpected']", completed.stderr)

        self.fixture.write()
        raw = self.fixture.authorization_path.read_text(encoding="ascii")
        self.fixture.authorization_path.write_text(
            raw.replace(
                '  "status": "authorized",',
                '  "status": "authorized",\n  "status": "authorized",',
                1,
            ),
            encoding="ascii",
        )
        completed = self.run_authorization_validator()
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("duplicate JSON key", completed.stderr)

        self.fixture.write()
        raw_audit = self.fixture.audit_path.read_text(encoding="ascii").replace(
            '  "job_id": 169653,', '  "job_id": NaN,', 1
        )
        self.fixture.audit_path.write_text(raw_audit, encoding="ascii")
        authorization = copy.deepcopy(self.fixture.authorization)
        authorization["audited_smoke"]["receipt_sha256"] = sha256_bytes(  # type: ignore[index]
            raw_audit.encode("ascii")
        )
        self.fixture.authorization_path.write_bytes(encoded_json(authorization))
        completed = self.run_authorization_validator()
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("non-finite JSON constant", completed.stderr)

    def test_authorization_rejects_symlinked_receipts(self) -> None:
        original_authorization = self.fixture.authorization_path
        target = self.work / "authorization-target.json"
        target.write_bytes(original_authorization.read_bytes())
        original_authorization.unlink()
        original_authorization.symlink_to(target)
        completed = self.run_authorization_validator()
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("canonical non-symlink path", completed.stderr)

    def test_valid_complete_output_is_accepted(self) -> None:
        completed = self.run_output_validator()
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_output_rejects_disagreement_identity_and_count_drift(self) -> None:
        cases = (
            ("status", "disagreement", "reported disagreement"),
            ("schema_version", 2, "schema version mismatch"),
            ("generator_version", 2, "generator version mismatch"),
            ("seed", SEED + 1, "seed mismatch"),
            ("first_case", 1, "first case mismatch"),
            ("cases_run", CASE_COUNT - 1, "case count mismatch"),
            ("sat_cases", 599_999, "SAT/UNSAT counts"),
            ("abstained_cases", 1, "unchecked abstentions"),
            ("oracle_cases", CASE_COUNT - 1, "finite-oracle counts"),
            ("oracle_skipped", 1, "finite-oracle counts"),
            ("elapsed_ns", 0, "elapsed_ns must be positive"),
        )
        baseline = self.valid_output()
        for name, value, fragment in cases:
            payload = dict(baseline)
            payload[name] = value
            completed = self.run_output_validator(payload)
            with self.subTest(field=name):
                self.assertNotEqual(completed.returncode, 0)
                self.assertIn(fragment, completed.stderr)

    def test_output_rejects_type_confusion_extra_fields_and_noncanonical_json(self) -> None:
        payload = self.valid_output()
        payload["cases_run"] = True
        completed = self.run_output_validator(payload)
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("nonnegative JSON integer", completed.stderr)

        payload = self.valid_output()
        payload["witness"] = "unexpected"
        completed = self.run_output_validator(payload)
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("extra=['witness']", completed.stderr)

        payload = self.valid_output()
        pretty = encoded_json(payload)
        completed = self.run_output_validator(raw=pretty)
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("exactly one newline-terminated JSON line", completed.stderr)

        compact = json.dumps(payload, separators=(",", ":")).encode("ascii")
        completed = self.run_output_validator(raw=compact)
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("newline-terminated", completed.stderr)

    def test_output_rejects_duplicate_keys_nonfinite_values_and_range_mismatch(self) -> None:
        payload = self.valid_output()
        raw = (json.dumps(payload, separators=(",", ":")) + "\n").encode("ascii")
        duplicate = raw.replace(
            b'"status":"complete",',
            b'"status":"complete","status":"complete",',
            1,
        )
        completed = self.run_output_validator(raw=duplicate)
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("duplicate JSON key", completed.stderr)

        nonfinite = raw.replace(b'"elapsed_ns":987654321', b'"elapsed_ns":NaN', 1)
        completed = self.run_output_validator(raw=nonfinite)
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("non-finite JSON constant", completed.stderr)

        arguments = [
            str(GENERATOR_VERSION),
            str(SEED),
            str(FIRST_CASE),
            str(CASE_COUNT),
            str(LAST_CASE + 1),
        ]
        completed = self.run_output_validator(arguments=arguments)
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("case range is inconsistent", completed.stderr)

    def test_nonzero_exit_is_rejected_before_output_publication(self) -> None:
        text = self.text(SBATCH)
        status_capture = text.index("COMMAND_STATUS=$?")
        status_gate = text.index('"Fabric differential command returned nonzero status')
        validator = text.index("<<'PY_VALIDATE_OUTPUT'")
        publication = text.index('mv "$STDOUT_CANDIDATE"')
        self.assertLess(status_capture, status_gate)
        self.assertLess(status_gate, validator)
        self.assertLess(validator, publication)


if __name__ == "__main__":
    unittest.main()
