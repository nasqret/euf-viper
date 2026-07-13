from __future__ import annotations

import hashlib
import json
import platform
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from scripts.bench import census_component_quotient_ram as census


ROOT = Path(__file__).resolve().parents[1]
SBATCH = ROOT / "scripts" / "wmi" / "euf_viper_component_quotient_census.sbatch"
SUBMIT = ROOT / "scripts" / "wmi" / "submit_component_quotient_census.sh"
VERIFIER = ROOT / "scripts" / "bench" / "verify_component_quotient_ram_bundle.py"
FINALIZER = (
    ROOT / "scripts" / "bench" / "finalize_component_quotient_ram_metadata.py"
)


class ComponentQuotientWmiTests(unittest.TestCase):
    def test_shell_scripts_are_syntactically_valid(self) -> None:
        for path in (SBATCH, SUBMIT):
            completed = subprocess.run(
                ["bash", "-n", str(path)],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_job_is_revision_bound_source_only_and_exactly_7503(self) -> None:
        text = SBATCH.read_text(encoding="utf-8")
        self.assertIn("EUF_VIPER_EXPECTED_REVISION", text)
        self.assertIn("git status --porcelain=v1 --untracked-files=no", text)
        self.assertIn('if [ "$EXPECTED_SOURCES" != 7503 ]', text)
        self.assertIn("census_component_quotient_ram.py", text)
        self.assertIn("component-quotient-ram-census-v1.json", text)
        self.assertEqual(text.count("--require-validity"), 1)
        self.assertIn("verify_component_quotient_ram_bundle.py", text)
        self.assertIn('--receipt-out "$OUT/verification.json"', text)
        self.assertIn("finalize_component_quotient_ram_metadata.py", text)
        self.assertIn('--records "$OUT/records.jsonl"', text)
        self.assertIn('--targets "$OUT/targets.jsonl"', text)
        self.assertIn('--aggregate "$OUT/aggregate.json"', text)
        self.assertIn('--verification "$OUT/verification.json"', text)
        for forbidden in (
            "cargo run",
            "target/release/euf-viper",
            " z3 ",
            "cvc5",
            "yices",
        ):
            self.assertNotIn(forbidden, text)

    def test_job_rechecks_and_invokes_one_pinned_python_for_every_phase(self) -> None:
        text = SBATCH.read_text(encoding="utf-8")
        self.assertIn("EUF_VIPER_COMPONENT_QUOTIENT_PYTHON_REALPATH", text)
        self.assertIn("EUF_VIPER_COMPONENT_QUOTIENT_PYTHON_VERSION", text)
        self.assertIn("EUF_VIPER_COMPONENT_QUOTIENT_PYTHON_SHA256", text)
        self.assertIn('actual_realpath="$(readlink -f -- "$PYTHON_REALPATH")"', text)
        self.assertIn('actual_sha256="$(sha256sum -- "$PYTHON_REALPATH")"', text)
        self.assertEqual(text.count("verify_python_identity "), 3)
        self.assertIn("verify_python_identity analyzer", text)
        self.assertIn("verify_python_identity verifier", text)
        self.assertIn("verify_python_identity metadata", text)
        self.assertEqual(text.count('"$PYTHON_REALPATH" scripts/bench/'), 3)
        self.assertNotRegex(text, r"(?m)^\s*python3(?:\s|$)")

    def test_independent_verifier_has_a_strict_receipt_contract(self) -> None:
        text = VERIFIER.read_text(encoding="utf-8")
        self.assertIn("verify_census_bundle", text)
        self.assertIn("--records", text)
        self.assertIn("--aggregate", text)
        self.assertIn("--targets", text)
        self.assertIn("--receipt-out", text)
        self.assertIn("--require-validity", text)
        self.assertIn("verified=true", text)

    def test_finalizer_binds_every_receipt_hash_and_rechecks_snapshots(self) -> None:
        text = FINALIZER.read_text(encoding="utf-8")
        for key in (
            "lock_sha256",
            "input_manifest_sha256",
            "portable_source_set_sha256",
            "analyzer_sha256",
            "parser_sha256",
            "taxonomy_builder_sha256",
            "records_jsonl_sha256",
            "terminal_record_sha256",
            "derived_target_manifest_sha256",
            "aggregate_json_sha256",
            "recomputed_gates_sha256",
        ):
            self.assertIn(f'"{key}"', text)
        self.assertIn("receipt_hashes[key] != current_hashes[key]", text)
        self.assertIn("aggregate_hashes[key] != current_hashes[key]", text)
        self.assertIn("_assert_snapshot_unchanged", text)
        self.assertIn("source changed during metadata finalization", text)
        self.assertIn('"status": "completed"', text)
        self.assertIn('"python": python_identity', text)

    def test_submitter_requires_published_revision_and_pins_remote_python(self) -> None:
        text = SUBMIT.read_text(encoding="utf-8")
        self.assertIn("git status --porcelain=v1 --untracked-files=no", text)
        self.assertIn("EUF_VIPER_COMPONENT_QUOTIENT_PUBLISHED_REF", text)
        self.assertIn(
            'PUBLISHED_REF="${EUF_VIPER_COMPONENT_QUOTIENT_PUBLISHED_REF:-origin/main}"',
            text,
        )
        self.assertIn('PUBLISHED_REVISION="$(git rev-parse "$PUBLISHED_REF")"', text)
        self.assertIn("HEAD $REVISION is not published", text)
        self.assertIn("fetch --quiet origin '$REVISION'", text)
        self.assertIn("euf_viper_component_quotient_census.sbatch", text)
        self.assertIn("component-quotient-census-submission-$JOB_ID.json", text)
        self.assertIn('if [ "$EXPECTED_SOURCES" != 7503 ]', text)
        self.assertIn("EUF_VIPER_COMPONENT_QUOTIENT_REMOTE_PYTHON", text)
        self.assertIn('realpath="$(readlink -f -- "$candidate")"', text)
        self.assertIn('sha256="$(sha256sum -- "$realpath")"', text)
        self.assertIn("EUF_VIPER_COMPONENT_QUOTIENT_PYTHON_REALPATH", text)
        self.assertIn("EUF_VIPER_COMPONENT_QUOTIENT_PYTHON_VERSION", text)
        self.assertIn("EUF_VIPER_COMPONENT_QUOTIENT_PYTHON_SHA256", text)
        self.assertIn('"python": {', text)


class FinalizerFixture:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.manifest = root / "manifest.jsonl"
        self.lock = root / "lock.json"
        self.records = root / "records.jsonl"
        self.aggregate = root / "aggregate.json"
        self.targets = root / "targets.jsonl"
        self.verification = root / "verification.json"
        self.run_log = root / "run.txt"
        self.verification_log = root / "verification.txt"
        self.metadata = root / "metadata.json"
        self.rows: list[dict[str, object]] = []
        self._add_source(
            "QF_UF/2018-Goel-hwbench/QF_UF_demo_ab_br_max.smt2", 2
        )
        self._add_source("QF_UF/QG-classification/qg1/demo1.smt2", 1)
        self._write_inputs()
        census.run_census(
            self.manifest,
            self.records,
            self.aggregate,
            self.targets,
            repository_root=self.root,
            lock_path=self.lock,
        )
        receipt = census.verify_census_bundle(
            self.manifest,
            self.records,
            self.aggregate,
            self.targets,
            repository_root=self.root,
            lock_path=self.lock,
        )
        self.verification.write_bytes(census.canonical_json_bytes(receipt))
        self.run_log.write_text("analysis complete\n", encoding="ascii")
        self.verification_log.write_text("verified=true\n", encoding="ascii")

    def _add_source(self, relative_path: str, record_id: int) -> None:
        source = b"(set-logic QF_UF)\n(assert true)\n(check-sat)\n"
        path = self.root / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(source)
        self.rows.append(
            {
                "id": record_id,
                "path": relative_path,
                "relative_path": relative_path,
                "bytes": len(source),
                "sha256": hashlib.sha256(source).hexdigest(),
            }
        )

    def _write_inputs(self) -> None:
        self.manifest.write_bytes(
            b"".join(census.canonical_json_bytes(row) for row in self.rows)
        )
        lock = json.loads(census.DEFAULT_LOCK_PATH.read_text(encoding="ascii"))
        portable_rows = sorted(self.rows, key=lambda row: row["relative_path"])
        portable_bytes = b"".join(
            census.canonical_json_bytes(
                {
                    "relative_path": row["relative_path"],
                    "bytes": row["bytes"],
                    "sha256": row["sha256"],
                }
            )
            for row in portable_rows
        )
        lock["corpus"]["expected_sources"] = 2
        lock["corpus"]["portable_source_set_sha256"] = hashlib.sha256(
            portable_bytes
        ).hexdigest()
        lock["corpus"]["families"]["qg"]["expected_population"] = 1
        lock["corpus"]["families"]["goel"]["expected_population"] = 1
        lock["gates"]["validity"]["required_sources"] = 2
        self.lock.write_text(
            json.dumps(lock, indent=2, sort_keys=True) + "\n", encoding="ascii"
        )

    def command(
        self,
        *,
        python_realpath: Path | None = None,
        python_version: str | None = None,
        python_sha256: str | None = None,
    ) -> list[str]:
        executable = Path(sys.executable).resolve()
        executable_sha256 = hashlib.sha256(executable.read_bytes()).hexdigest()
        return [
            sys.executable,
            str(FINALIZER),
            "--metadata-out",
            str(self.metadata),
            "--repository-root",
            str(self.root),
            "--manifest",
            str(self.manifest),
            "--lock",
            str(self.lock),
            "--records",
            str(self.records),
            "--aggregate",
            str(self.aggregate),
            "--targets",
            str(self.targets),
            "--verification",
            str(self.verification),
            "--run-log",
            str(self.run_log),
            "--verification-log",
            str(self.verification_log),
            "--expected-sources",
            "2",
            "--revision",
            "1" * 40,
            "--job-id",
            "123",
            "--python-realpath",
            str(python_realpath or executable),
            "--python-version",
            python_version or platform.python_version(),
            "--python-sha256",
            python_sha256 or executable_sha256,
        ]

    def finalize(
        self,
        *,
        python_realpath: Path | None = None,
        python_version: str | None = None,
        python_sha256: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            self.command(
                python_realpath=python_realpath,
                python_version=python_version,
                python_sha256=python_sha256,
            ),
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )


class ComponentQuotientMetadataBehaviorTests(unittest.TestCase):
    def test_valid_receipt_emits_completed_metadata_with_python_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = FinalizerFixture(Path(temporary))
            completed = fixture.finalize()
            self.assertEqual(completed.returncode, 0, completed.stderr)
            metadata = json.loads(fixture.metadata.read_text(encoding="ascii"))
        self.assertEqual(metadata["status"], "completed")
        self.assertEqual(
            metadata["python"]["realpath"], str(Path(sys.executable).resolve())
        )
        self.assertEqual(metadata["python"]["version"], platform.python_version())
        self.assertEqual(
            set(metadata["validation"]["receipt_bound_hashes"]),
            FINALIZER_RECEIPT_HASH_KEYS,
        )

    def test_fabricated_zero_receipt_hashes_cannot_emit_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = FinalizerFixture(Path(temporary))
            receipt = json.loads(fixture.verification.read_text(encoding="ascii"))
            receipt["hashes"] = {key: "0" * 64 for key in receipt["hashes"]}
            fixture.verification.write_bytes(census.canonical_json_bytes(receipt))
            completed = fixture.finalize()
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("verification receipt hash mismatch", completed.stderr)
            self.assertFalse(fixture.metadata.exists())

    def test_aggregate_mutation_after_verification_cannot_emit_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = FinalizerFixture(Path(temporary))
            aggregate = json.loads(fixture.aggregate.read_text(encoding="ascii"))
            aggregate["gates"]["implementation_allowed"] = not aggregate["gates"][
                "implementation_allowed"
            ]
            fixture.aggregate.write_bytes(census.canonical_json_bytes(aggregate))
            completed = fixture.finalize()
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("verification receipt hash mismatch", completed.stderr)
            self.assertFalse(fixture.metadata.exists())

    def test_python_version_drift_cannot_emit_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = FinalizerFixture(Path(temporary))
            completed = fixture.finalize(python_version="0.0.0")
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("Python version drift", completed.stderr)
            self.assertFalse(fixture.metadata.exists())

    def test_python_realpath_drift_cannot_emit_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = FinalizerFixture(Path(temporary))
            python_link = fixture.root / "python-link"
            python_link.symlink_to(Path(sys.executable).resolve())
            completed = fixture.finalize(python_realpath=python_link)
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("Python realpath drift", completed.stderr)
            self.assertFalse(fixture.metadata.exists())

    def test_python_sha256_drift_cannot_emit_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = FinalizerFixture(Path(temporary))
            completed = fixture.finalize(python_sha256="0" * 64)
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("Python SHA-256 drift", completed.stderr)
            self.assertFalse(fixture.metadata.exists())


FINALIZER_RECEIPT_HASH_KEYS = {
    "lock_sha256",
    "input_manifest_sha256",
    "portable_source_set_sha256",
    "analyzer_sha256",
    "parser_sha256",
    "taxonomy_builder_sha256",
    "records_jsonl_sha256",
    "terminal_record_sha256",
    "derived_target_manifest_sha256",
    "aggregate_json_sha256",
    "recomputed_gates_sha256",
}


if __name__ == "__main__":
    unittest.main()
