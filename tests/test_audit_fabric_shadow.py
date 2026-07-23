from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "bench" / "audit_fabric_shadow.py"
SPEC = importlib.util.spec_from_file_location("audit_fabric_shadow", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
AUDIT = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = AUDIT
SPEC.loader.exec_module(AUDIT)


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def canonical_line(value: object) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("ascii")


def pretty_json(path: Path, value: object) -> None:
    path.write_bytes(
        (
            json.dumps(
                value,
                ensure_ascii=True,
                allow_nan=False,
                indent=2,
                sort_keys=True,
            )
            + "\n"
        ).encode("ascii")
    )


def quantiles(values: list[int]) -> dict[str, int]:
    ordered = sorted(values)

    def rank(percentile: int) -> int:
        numerator = percentile * len(ordered)
        index = max(0, (numerator + 99) // 100 - 1)
        return ordered[index]

    return {
        "count": len(ordered),
        "total": sum(ordered),
        "min": ordered[0],
        "p50": rank(50),
        "p90": rank(90),
        "p95": rank(95),
        "p99": rank(99),
        "max": ordered[-1],
    }


class FabricArtifactFixture:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.artifacts = root / "fetched" / "artifacts"
        self.artifacts.mkdir(parents=True)
        self.submission_path = root / "submission.json"
        self.audit_path = root / "audit.json"

        self.revision = "a" * 40
        self.manifest_hash = "b" * 64
        self.runner_hash = "c" * 64
        self.cargo_hash = "d" * 64
        self.rustc_hash = "e" * 64
        self.python_hash = "f" * 64
        self.work_root = "/work/test/euf-viper"
        self.remote_worktree = f"{self.work_root}/checkouts/{self.revision[:12]}"
        self.run_root = f"{self.work_root}/runs/fabric-shadow-smoke-1"
        self.final_root = f"{self.run_root}/artifacts"
        self.staging_root = f"{self.run_root}/.artifacts.partial"
        self.manifest_path = "/home/test/benchmarks/qf_uf_smoke.jsonl"
        self.corpus_root = "/home/test/benchmarks/smtlib-2025/QF_UF"
        self.timeout = 60.0
        self.job_id = 12345

        self.tools = {
            "runner": {"sha256": self.runner_hash},
            "cargo": {
                "path": "/home/test/.rustup/toolchains/1.93.0/bin/cargo",
                "sha256": self.cargo_hash,
                "version": "cargo 1.93.0 (083ac5135 2026-01-07)",
            },
            "rustc": {
                "path": "/home/test/.rustup/toolchains/1.93.0/bin/rustc",
                "sha256": self.rustc_hash,
                "version": "rustc 1.93.0 (254b59607 2026-01-19)",
            },
            "python": {
                "path": "/usr/bin/python3",
                "sha256": self.python_hash,
                "version": "Python 3.10.12",
            },
        }
        self.records = self._make_records()
        self._write_records()
        self._write_solver_and_logs()
        self.summary = self._make_summary()
        pretty_json(self.artifacts / "summary.json", self.summary)
        self.slurm = self._make_slurm()
        pretty_json(self.artifacts / "slurm.json", self.slurm)
        self.submission = self._make_submission()
        pretty_json(self.submission_path, self.submission)

    def _make_records(self) -> list[dict]:
        records: list[dict] = []
        for index in range(2):
            relative = f"QF_UF/family/case-{index}.smt2"
            records.append(
                {
                    "record_type": "fabric_shadow_receipt",
                    "manifest_index": index,
                    "manifest_line": index + 1,
                    "id": index,
                    "path": f"benchmarks/smtlib-2025/QF_UF/{relative}",
                    "relative_path": relative,
                    "resolved_path": f"{self.corpus_root}/{relative}",
                    "resolution_rule": "corpus_root_relative_path",
                    "expected_status": "sat" if index == 0 else "unsat",
                    "manifest_sha256": self.manifest_hash,
                    "input_binding_sha256": "0" * 64,
                    "input_sha256": str(index + 1) * 64,
                    "solver_path": f"{self.staging_root}/euf-viper",
                    "solver_sha256": "0" * 64,
                    "timeout_s": self.timeout,
                    "wall_time_ns": 100 + index,
                    "schema_version": 1,
                    "mode": "fabric_shadow",
                    "solver_result_emitted": False,
                    "source_bytes": 10 + index,
                    "parse_ns": 20 + index,
                    "projection_ns": 30 + index,
                    "terms": 2 + index,
                    "applications": 1 + index,
                    "atoms": 3 + index,
                    "assertions": 1,
                    "root_literals": 1 + index,
                    "components": 1,
                    "max_component_terms": 2 + index,
                    "cross_component_boolean_nodes": index,
                    "unsupported_fragments": 0,
                    "contradiction": index == 1,
                }
            )
        binding = hashlib.sha256()
        fields = (
            "manifest_index",
            "manifest_line",
            "id",
            "path",
            "relative_path",
            "resolved_path",
            "resolution_rule",
            "expected_status",
            "input_sha256",
            "source_bytes",
        )
        for record in records:
            binding.update(canonical_line({field: record[field] for field in fields}))
        binding_hash = binding.hexdigest()
        for record in records:
            record["input_binding_sha256"] = binding_hash
        return records

    def _write_records(self) -> None:
        path = self.artifacts / "fabric-shadow.jsonl"
        path.write_bytes(b"".join(canonical_line(record) for record in self.records))

    def _write_solver_and_logs(self) -> None:
        solver = self.artifacts / "euf-viper"
        solver.write_bytes(b"ELF-test-solver\x00\x01")
        solver.chmod(0o555)
        solver_hash = sha256(solver)
        for record in self.records:
            record["solver_sha256"] = solver_hash
        self._write_records()
        (self.artifacts / "stdout.log").write_bytes(
            b"status=complete manifest_rows=2 completed_rows=2 remaining_rows=0\n"
        )
        (self.artifacts / "stderr.log").write_bytes(b"Finished release build\n")

    def _make_summary(self) -> dict:
        totals = {
            field: sum(record[field] for record in self.records)
            for field in (
                "source_bytes",
                "terms",
                "applications",
                "atoms",
                "assertions",
                "root_literals",
                "components",
                "cross_component_boolean_nodes",
                "unsupported_fragments",
            )
        }
        totals["max_component_terms"] = max(
            record["max_component_terms"] for record in self.records
        )
        totals["contradiction_instances"] = sum(
            int(record["contradiction"]) for record in self.records
        )
        return {
            "schema_version": 1,
            "mode": "fabric_shadow",
            "status": "complete",
            "manifest_path": self.manifest_path,
            "manifest_sha256": self.manifest_hash,
            "input_binding_sha256": self.records[0]["input_binding_sha256"],
            "input_bytes": sum(record["source_bytes"] for record in self.records),
            "solver_path": f"{self.staging_root}/euf-viper",
            "solver_sha256": self.records[0]["solver_sha256"],
            "out_jsonl_path": f"{self.staging_root}/fabric-shadow.jsonl",
            "out_jsonl_sha256": sha256(self.artifacts / "fabric-shadow.jsonl"),
            "resolution": {
                "rule": "corpus_root_plus_relative_path_and_repository_layout_when_repo_root",
                "corpus_root": self.corpus_root,
                "invocation_cwd": None,
                "declared_paths": "preserved_but_ignored",
                "repository_root": self.remote_worktree,
                "repository_layout": "benchmarks/smtlib-2025/QF_UF",
                "repository_layout_enabled": False,
                "resolved_by_rule": {"corpus_root_relative_path": 2},
                "ambiguity_policy": "reject",
                "traversal_policy": "normalized_relative_and_resolved_containment",
            },
            "parameters": {"jobs": 1, "timeout_s": self.timeout, "resume": False},
            "counts": {
                "manifest_rows": 2,
                "preexisting_rows": 0,
                "selected_rows": 2,
                "attempted_rows": 2,
                "completed_rows": 2,
                "error_rows": 0,
                "remaining_rows": 0,
            },
            "aggregate_component_metrics": totals,
            "timing_quantiles_ns": {
                field: quantiles([record[field] for record in self.records])
                for field in ("wall_time_ns", "parse_ns", "projection_ns")
            },
            "error": None,
        }

    def _artifact_entry(self, filename: str) -> dict:
        path = self.artifacts / filename
        return {
            "path": f"{self.final_root}/{filename}",
            "sha256": sha256(path),
            "bytes": path.stat().st_size,
        }

    def _make_slurm(self) -> dict:
        return {
            "schema": "euf-viper.fabric-shadow-wmi-run.v1",
            "status": "artifact_complete",
            "scope": dict(AUDIT.NON_CLAIM_SCOPE),
            "revision": self.revision,
            "corpus_mode": "smoke",
            "resume": False,
            "single_core": True,
            "jobs": 1,
            "instance_timeout_s": self.timeout,
            "manifest": {
                "path": self.manifest_path,
                "corpus_root": self.corpus_root,
                "corpus_access": "read_only",
                "sha256": self.manifest_hash,
                "expected_sources": 2,
                "observed_records": 2,
            },
            "slurm": {
                "job_id": str(self.job_id),
                "job_name": "euf-fabric-shadow",
                "cluster": "wmi",
                "partition": "cpu_idle",
                "account": "test-account",
                "node_list": "wn001",
                "cpus_per_task": 1,
                "submit_dir": self.remote_worktree,
            },
            "tools": {
                "runner": {
                    "path": f"{self.remote_worktree}/scripts/bench/run_fabric_shadow.py",
                    "sha256": self.runner_hash,
                },
                "cargo": dict(self.tools["cargo"]),
                "rustc": dict(self.tools["rustc"]),
                "python": dict(self.tools["python"]),
            },
            "artifacts": {
                key: self._artifact_entry(filename)
                for key, filename in AUDIT.SLURM_ARTIFACT_FILES.items()
            },
            "completed_at": "2026-07-22T12:34:56.123456Z",
        }

    def _make_submission(self) -> dict:
        return {
            "schema": "euf-viper.fabric-shadow-wmi-submission.v1",
            "status": "submitted",
            "run_id": "smoke-1",
            "scope": dict(AUDIT.NON_CLAIM_SCOPE),
            "revision": self.revision,
            "published_ref": "refs/heads/perf-viper-fabric",
            "corpus_mode": "smoke",
            "remote_host": "test@10.0.0.1",
            "work_root": self.work_root,
            "remote_worktree": self.remote_worktree,
            "run_root": self.run_root,
            "manifest": {
                "path": self.manifest_path,
                "sha256": self.manifest_hash,
                "expected_sources": 2,
                "corpus_root": self.corpus_root,
                "corpus_access": "read_only",
            },
            "tools": self.tools,
            "slurm": {
                "job_id": self.job_id,
                "cluster": "wmi",
                "partition": "cpu_idle",
                "wall_time": "00:15:00",
                "dependency": None,
                "cpus_per_task": 1,
                "runner_jobs": 1,
                "instance_timeout_s": self.timeout,
                "raw_submission": f"{self.job_id};wmi",
            },
            "resume": False,
            "submission_state_may_be_incomplete": False,
            "artifacts": {
                "root": self.final_root,
                "rows": f"{self.final_root}/fabric-shadow.jsonl",
                "summary": f"{self.final_root}/summary.json",
                "slurm": f"{self.final_root}/slurm.json",
                "stdout": f"{self.final_root}/stdout.log",
                "stderr": f"{self.final_root}/stderr.log",
            },
        }

    def refresh_slurm_artifact(self, key: str) -> None:
        filename = AUDIT.SLURM_ARTIFACT_FILES[key]
        self.slurm["artifacts"][key] = self._artifact_entry(filename)
        pretty_json(self.artifacts / "slurm.json", self.slurm)

    def rewrite_summary(self) -> None:
        pretty_json(self.artifacts / "summary.json", self.summary)
        self.refresh_slurm_artifact("summary")

    def rewrite_records(self) -> None:
        self._write_records()
        self.summary["out_jsonl_sha256"] = sha256(
            self.artifacts / "fabric-shadow.jsonl"
        )
        pretty_json(self.artifacts / "summary.json", self.summary)
        self.slurm["artifacts"]["records"] = self._artifact_entry(
            "fabric-shadow.jsonl"
        )
        self.slurm["artifacts"]["summary"] = self._artifact_entry("summary.json")
        pretty_json(self.artifacts / "slurm.json", self.slurm)

    def operator_expectations(self) -> dict[str, object]:
        return {
            "expected_revision": self.revision,
            "expected_manifest_sha256": self.manifest_hash,
            "expected_corpus_mode": "smoke",
            "expected_row_count": 2,
            "expected_slurm_job_id": self.job_id,
        }

    def operator_cli_arguments(self) -> list[str]:
        return [
            "--expected-revision",
            self.revision,
            "--expected-manifest-sha256",
            self.manifest_hash,
            "--expected-corpus-mode",
            "smoke",
            "--expected-row-count",
            "2",
            "--expected-slurm-job-id",
            str(self.job_id),
        ]


class AuditFabricShadowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.work = Path(self.temporary.name)
        self.fixture = FabricArtifactFixture(self.work)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def assert_audit_fails(self, fragment: str) -> None:
        with self.assertRaises(AUDIT.AuditError) as captured:
            AUDIT.audit_fabric_shadow(
                self.fixture.artifacts,
                self.fixture.submission_path,
                **self.fixture.operator_expectations(),
            )
        self.assertIn(fragment, str(captured.exception))

    def test_success_emits_atomic_ascii_non_claim_receipt(self) -> None:
        completed = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                str(self.fixture.artifacts),
                str(self.fixture.submission_path),
                *self.fixture.operator_cli_arguments(),
                "--out",
                str(self.fixture.audit_path),
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertTrue(completed.stdout.startswith("verified receipt="))
        raw = self.fixture.audit_path.read_bytes()
        raw.decode("ascii", errors="strict")
        receipt = json.loads(raw)
        self.assertEqual(receipt["status"], "verified")
        self.assertIs(receipt["scope"]["verified"], True)
        self.assertIs(receipt["scope"]["solver_result_claim"], False)
        self.assertIs(receipt["scope"]["performance_claim"], False)
        self.assertIs(receipt["scope"]["promotion_claim"], False)
        self.assertEqual(
            receipt["operator_expectations"],
            {
                "revision": self.fixture.revision,
                "manifest_sha256": self.fixture.manifest_hash,
                "corpus_mode": "smoke",
                "row_count": 2,
                "slurm_job_id": self.fixture.job_id,
                "source": "independent_operator_input",
            },
        )
        self.assertEqual(receipt["counts"]["completed_rows"], 2)
        self.assertEqual(receipt["counts"]["missing_rows"], 0)
        self.assertEqual(receipt["counts"]["duplicate_rows"], 0)
        self.assertEqual(
            receipt["inputs"]["submission_receipt"]["sha256"],
            sha256(self.fixture.submission_path),
        )
        self.assertEqual(
            set(receipt["inputs"]["artifacts"]), AUDIT.ARTIFACT_FILES
        )
        self.assertEqual(self.fixture.audit_path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(list(self.work.glob(".audit.json.*.tmp")), [])

    def test_operator_expectations_are_mandatory_in_api_and_cli(self) -> None:
        with self.assertRaises(TypeError):
            AUDIT.audit_fabric_shadow(
                self.fixture.artifacts,
                self.fixture.submission_path,
            )

        completed = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                str(self.fixture.artifacts),
                str(self.fixture.submission_path),
                "--out",
                str(self.fixture.audit_path),
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 2)
        for option in (
            "--expected-revision",
            "--expected-manifest-sha256",
            "--expected-corpus-mode",
            "--expected-row-count",
            "--expected-slurm-job-id",
        ):
            self.assertIn(option, completed.stderr)

        help_result = subprocess.run(
            [sys.executable, str(SCRIPT), "--help"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(help_result.returncode, 0, help_result.stderr)
        self.assertIn("Neither the API nor CLI derives", help_result.stdout)
        self.assertIn("--expected-slurm-job-id", help_result.stdout)

    def test_each_independent_operator_expectation_is_enforced(self) -> None:
        baseline = self.fixture.operator_expectations()
        cases = (
            (
                "revision",
                {"expected_revision": "9" * 40},
                "operator expectation submission revision",
            ),
            (
                "manifest",
                {"expected_manifest_sha256": "8" * 64},
                "operator expectation submission manifest SHA-256",
            ),
            (
                "mode",
                {
                    "expected_corpus_mode": "full",
                    "expected_manifest_sha256": AUDIT.FROZEN_FULL_MANIFEST_SHA256,
                    "expected_row_count": 7503,
                },
                "operator expectation submission corpus mode",
            ),
            (
                "rows",
                {"expected_row_count": 3},
                "operator expectation submission row count",
            ),
            (
                "job",
                {"expected_slurm_job_id": self.fixture.job_id + 1},
                "operator expectation submission Slurm job ID",
            ),
        )
        for name, overrides, fragment in cases:
            expectations = dict(baseline)
            expectations.update(overrides)
            with self.subTest(expectation=name):
                with self.assertRaises(AUDIT.AuditError) as captured:
                    AUDIT.audit_fabric_shadow(
                        self.fixture.artifacts,
                        self.fixture.submission_path,
                        **expectations,
                    )
                self.assertIn(fragment, str(captured.exception))

    def test_coherent_bundle_tampering_fails_original_operator_expectation(
        self,
    ) -> None:
        original_expectations = self.fixture.operator_expectations()
        altered_revision = "9" * 40
        altered_job_id = self.fixture.job_id + 700
        altered_worktree = (
            f"{self.fixture.work_root}/checkouts/{altered_revision[:12]}"
        )

        self.fixture.submission["revision"] = altered_revision
        self.fixture.submission["remote_worktree"] = altered_worktree
        self.fixture.submission["slurm"]["job_id"] = altered_job_id
        self.fixture.submission["slurm"]["raw_submission"] = (
            f"{altered_job_id};wmi"
        )
        self.fixture.slurm["revision"] = altered_revision
        self.fixture.slurm["slurm"]["job_id"] = str(altered_job_id)
        self.fixture.slurm["slurm"]["submit_dir"] = altered_worktree
        self.fixture.slurm["tools"]["runner"]["path"] = (
            f"{altered_worktree}/scripts/bench/run_fabric_shadow.py"
        )
        self.fixture.summary["resolution"]["repository_root"] = altered_worktree
        self.fixture.rewrite_summary()
        pretty_json(self.fixture.submission_path, self.fixture.submission)

        altered_expectations = dict(original_expectations)
        altered_expectations["expected_revision"] = altered_revision
        altered_expectations["expected_slurm_job_id"] = altered_job_id
        accepted = AUDIT.audit_fabric_shadow(
            self.fixture.artifacts,
            self.fixture.submission_path,
            **altered_expectations,
        )
        self.assertEqual(accepted["status"], "verified")

        with self.assertRaises(AUDIT.AuditError) as captured:
            AUDIT.audit_fabric_shadow(
                self.fixture.artifacts,
                self.fixture.submission_path,
                **original_expectations,
            )
        self.assertIn(
            "operator expectation submission revision", str(captured.exception)
        )

    def test_full_expectation_preserves_frozen_manifest_contract(self) -> None:
        expectations = self.fixture.operator_expectations()
        expectations.update(
            {
                "expected_corpus_mode": "full",
                "expected_row_count": 7503,
                "expected_manifest_sha256": "8" * 64,
            }
        )
        with self.assertRaises(AUDIT.AuditError) as captured:
            AUDIT.audit_fabric_shadow(
                self.fixture.artifacts,
                self.fixture.submission_path,
                **expectations,
            )
        self.assertIn(
            "operator expectation full manifest SHA-256", str(captured.exception)
        )

    def test_duplicate_key_and_nonfinite_json_are_rejected(self) -> None:
        raw = self.fixture.submission_path.read_text(encoding="ascii")
        self.fixture.submission_path.write_text(
            raw.replace(
                '  "status": "submitted",',
                '  "status": "submitted",\n  "status": "submitted",',
                1,
            ),
            encoding="ascii",
        )
        self.assert_audit_fails("duplicate JSON key")

        pretty_json(self.fixture.submission_path, self.fixture.submission)
        summary_path = self.fixture.artifacts / "summary.json"
        raw_summary = summary_path.read_text(encoding="ascii").replace(
            '"timeout_s": 60.0', '"timeout_s": NaN', 1
        )
        summary_path.write_text(raw_summary, encoding="ascii")
        self.fixture.refresh_slurm_artifact("summary")
        self.assert_audit_fails("non-finite JSON constant")

    def test_unexpected_files_and_artifact_symlinks_are_rejected(self) -> None:
        (self.fixture.artifacts / "unexpected.txt").write_text("x", encoding="ascii")
        self.assert_audit_fails("unexpected=['unexpected.txt']")
        (self.fixture.artifacts / "unexpected.txt").unlink()

        stdout = self.fixture.artifacts / "stdout.log"
        external = self.work / "external.log"
        external.write_bytes(stdout.read_bytes())
        stdout.unlink()
        stdout.symlink_to(external)
        self.assert_audit_fails("regular non-symlink file")

        self.fixture = FabricArtifactFixture(self.work / "directory-link-source")
        alias = self.work / "artifact-directory-link"
        alias.symlink_to(self.fixture.artifacts, target_is_directory=True)
        with self.assertRaises(AUDIT.AuditError) as captured:
            AUDIT.audit_fabric_shadow(
                alias,
                self.fixture.submission_path,
                **self.fixture.operator_expectations(),
            )
        self.assertIn("non-symlink directory", str(captured.exception))

    def test_remote_artifact_path_escape_is_rejected(self) -> None:
        self.fixture.slurm["artifacts"]["records"]["path"] = (
            f"{self.fixture.final_root}/../fabric-shadow.jsonl"
        )
        pretty_json(self.fixture.artifacts / "slurm.json", self.fixture.slurm)
        self.assert_audit_fails("records artifact path")

    def test_artifact_hash_and_byte_tampering_is_rejected(self) -> None:
        with (self.fixture.artifacts / "stderr.log").open("ab") as handle:
            handle.write(b"tampered\n")
        self.assert_audit_fails("stderr local hash binding")

        self.fixture = FabricArtifactFixture(self.work / "second")
        self.fixture.slurm["artifacts"]["solver"]["bytes"] += 1
        pretty_json(self.fixture.artifacts / "slurm.json", self.fixture.slurm)
        self.assert_audit_fails("solver local byte binding")

    def test_revision_timeout_runner_and_tool_bindings_are_exact(self) -> None:
        self.fixture.slurm["instance_timeout_s"] = 61.0
        pretty_json(self.fixture.artifacts / "slurm.json", self.fixture.slurm)
        self.assert_audit_fails("timeout binding")

        self.fixture = FabricArtifactFixture(self.work / "runner")
        self.fixture.slurm["tools"]["runner"]["sha256"] = "9" * 64
        pretty_json(self.fixture.artifacts / "slurm.json", self.fixture.slurm)
        self.assert_audit_fails("runner hash binding")

        self.fixture = FabricArtifactFixture(self.work / "tool")
        self.fixture.slurm["tools"]["cargo"]["sha256"] = "8" * 64
        pretty_json(self.fixture.artifacts / "slurm.json", self.fixture.slurm)
        self.assert_audit_fails("cargo tool binding")

    def test_record_schema_and_solver_result_claim_are_rejected(self) -> None:
        self.fixture.records[0]["result"] = "sat"
        self.fixture.rewrite_records()
        self.assert_audit_fails("extra=['result']")

        self.fixture = FabricArtifactFixture(self.work / "claim")
        self.fixture.records[0]["solver_result_emitted"] = True
        self.fixture.rewrite_records()
        self.assert_audit_fails("solver_result_emitted")

    def test_manifest_indices_must_be_ordered_unique_and_complete(self) -> None:
        self.fixture.records[1]["manifest_index"] = 0
        self.fixture.rewrite_records()
        self.assert_audit_fails("manifest_index order")

        self.fixture = FabricArtifactFixture(self.work / "missing")
        self.fixture.records.pop()
        self.fixture.rewrite_records()
        self.assert_audit_fails("complete row count")

    def test_input_manifest_and_solver_record_bindings_are_recomputed(self) -> None:
        self.fixture.records[0]["input_sha256"] = "7" * 64
        self.fixture.rewrite_records()
        self.assert_audit_fails("input binding digest")

        self.fixture = FabricArtifactFixture(self.work / "manifest")
        self.fixture.records[0]["manifest_sha256"] = "6" * 64
        self.fixture.rewrite_records()
        self.assert_audit_fails("manifest binding")

        self.fixture = FabricArtifactFixture(self.work / "solver")
        self.fixture.records[0]["solver_sha256"] = "5" * 64
        self.fixture.rewrite_records()
        self.assert_audit_fails("solver hash binding")

    def test_summary_errors_missing_counts_and_aggregates_are_rejected(self) -> None:
        self.fixture.summary["counts"]["error_rows"] = 1
        self.fixture.rewrite_summary()
        self.assert_audit_fails("summary error count")

        self.fixture = FabricArtifactFixture(self.work / "remaining")
        self.fixture.summary["counts"]["remaining_rows"] = 1
        self.fixture.rewrite_summary()
        self.assert_audit_fails("summary remaining count")

        self.fixture = FabricArtifactFixture(self.work / "aggregate")
        self.fixture.summary["aggregate_component_metrics"]["terms"] += 1
        self.fixture.rewrite_summary()
        self.assert_audit_fails("summary aggregate metrics")

    def test_output_cannot_enter_artifacts_or_replace_an_input(self) -> None:
        for output in (
            self.fixture.artifacts / "audit.json",
            self.fixture.submission_path,
        ):
            completed = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    str(self.fixture.artifacts),
                    str(self.fixture.submission_path),
                    *self.fixture.operator_cli_arguments(),
                    "--out",
                    str(output),
                ],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            with self.subTest(output=output):
                self.assertEqual(completed.returncode, 1)

        output_parent = self.work / "linked-output-parent"
        output_parent.symlink_to(self.fixture.artifacts, target_is_directory=True)
        completed = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                str(self.fixture.artifacts),
                str(self.fixture.submission_path),
                *self.fixture.operator_cli_arguments(),
                "--out",
                str(output_parent / "audit.json"),
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 1)
        self.assertFalse((self.fixture.artifacts / "audit.json").exists())


if __name__ == "__main__":
    unittest.main()
